#!/usr/bin/env python3
"""Source-selection admission regressions; no product or archival reader runs."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('worktree_producer', Path(__file__).with_name('run-unprivileged-go-ci.py'))
producer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(producer)


class WorktreeSourceTests(unittest.TestCase):
    def setUp(self):
        base = Path(os.environ.get('PLUTO_WORKTREE_TEST_TEMP', tempfile.gettempdir())).resolve()
        self.temporary = tempfile.TemporaryDirectory(prefix='pluto-worktree-test-', dir=base)
        self.root = Path(self.temporary.name).resolve()
        assert self.root.is_relative_to(base) and self.root != base
        self.addCleanup(self.temporary.cleanup)

    def source(self, name='main.go', raw=b'current source\n'):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_bytes(raw)
        return dict(path=name, bytes=len(raw), sha256=hashlib.sha256(raw).hexdigest())

    def manifest(self, rows, name='.release/current/source-inputs.json', schema='exocortex.package3.frozen-source.v1'):
        file = self.root / name
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(json.dumps(dict(schema=schema, files=rows)), encoding='utf-8')
        return file

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.root), *args], check=True,
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def test_selected_current_manifest_ignores_stale_package3_inventory(self):
        row = self.source()
        current = self.manifest([row])
        self.manifest([dict(row, sha256='0' * 64)], '.release/package3-qualification/source-inputs.json')
        result = producer.worktree_source(self.root, current)
        self.assertEqual(result['mode'], 'EXPLICIT_QUALIFIED_MANIFEST')
        self.assertEqual(result['files'], [row])
        self.assertEqual(result['manifest']['path'], current.relative_to(self.root).as_posix())
        self.assertEqual(result['manifest']['sha256'], hashlib.sha256(current.read_bytes()).hexdigest())

    def test_explicit_wrong_manifest_refuses_without_current_fallback(self):
        row = self.source()
        self.manifest([row])
        old = self.manifest([dict(row, sha256='0' * 64)], '.release/package3-qualification/source-inputs.json')
        with self.assertRaisesRegex(ValueError, 'actual raw qualified source bytes differ'):
            producer.worktree_source(self.root, old)

    def test_qualified_source_requires_actual_raw_bytes(self):
        row = self.source(raw=b'line\r\n')
        canonical = hashlib.sha256(b'line\n').hexdigest()
        selected = self.manifest([dict(row, sha256=canonical, canonical_sha256=canonical)])
        with self.assertRaisesRegex(ValueError, 'actual raw qualified source bytes differ'):
            producer.worktree_source(self.root, selected)

    def test_qualified_source_refuses_mutation_after_manifest(self):
        row = self.source(raw=b'original')
        selected = self.manifest([row])
        (self.root / 'main.go').write_bytes(b'changed!')
        with self.assertRaises(ValueError):
            producer.worktree_source(self.root, selected)

    def test_manifest_must_be_explicit_regular_file_inside_checkout(self):
        row = self.source()
        selected = self.manifest([row])
        link = self.root / 'linked.json'
        link.symlink_to(selected)
        for candidate in (self.root.parent / 'outside.json', link, '', self.root):
            with self.subTest(candidate=str(candidate)), self.assertRaises(ValueError):
                producer.worktree_source(self.root, candidate)

    def test_unknown_schema_or_empty_or_duplicate_inventory_refuses(self):
        row = self.source()
        for rows, schema in (([], 'exocortex.package3.frozen-source.v1'),
                             ([row, row], 'exocortex.package3.frozen-source.v1'),
                             ([row], 'unknown-source-schema')):
            selected = self.manifest(rows, schema=schema)
            with self.subTest(rows=rows, schema=schema), self.assertRaises(ValueError):
                producer.worktree_source(self.root, selected)

    def test_noncanonical_escape_private_git_or_ads_paths_refuse(self):
        row = self.source()
        for name in ('../outside', '/absolute', 'sub/../main.go', './main.go',
                     'sub//main.go', 'sub\\main.go', '.git/config', 'main.go:stream', 'line\nname', None):
            selected = self.manifest([dict(row, path=name)])
            with self.subTest(name=name), self.assertRaises(ValueError):
                producer.worktree_source(self.root, selected)

    def test_source_parent_and_file_symlinks_refuse_even_inside_checkout(self):
        row = self.source('real/main.go')
        (self.root / 'linked-dir').symlink_to(self.root / 'real', target_is_directory=True)
        (self.root / 'linked.go').symlink_to(self.root / 'real/main.go')
        for name in ('linked-dir/main.go', 'linked.go'):
            selected = self.manifest([dict(row, path=name)])
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'reparse/symlink'):
                producer.worktree_source(self.root, selected)

    def test_declared_size_types_bounds_and_sha_are_checked(self):
        row = self.source()
        for bad in (dict(bytes=True), dict(bytes=-1), dict(bytes=8 * 2**20 + 1),
                    dict(sha256=None), dict(sha256='invalid')):
            selected = self.manifest([dict(row, **bad)])
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                producer.worktree_source(self.root, selected)

    def test_unqualified_git_snapshot_pins_current_tracked_bytes_only(self):
        self.git('init', '-q')
        self.source('main.go', b'staged\n')
        self.git('add', '--', 'main.go')
        row = self.source('main.go', b'current edited bytes\n')
        self.source('.secrets/untracked', b'not a source input')
        self.manifest([dict(row, sha256='0' * 64)], '.release/package3-qualification/source-inputs.json')
        result = producer.worktree_source(self.root)
        self.assertEqual(result['mode'], 'CURRENT_GIT_TRACKED_FILES')
        self.assertIsNone(result['manifest'])
        self.assertEqual(result['files'], [row])
        self.assertEqual(result, producer.worktree_source(self.root))

    def test_unqualified_git_tracked_symlink_is_not_followed(self):
        self.git('init', '-q')
        self.source('real.go')
        (self.root / 'link.go').symlink_to(self.root / 'real.go')
        self.git('add', '--', 'link.go')
        with self.assertRaisesRegex(ValueError, 'reparse/symlink'):
            producer.worktree_source(self.root)


if __name__ == '__main__':
    unittest.main()
