# Embedded into the generated bootstrap; never extract unvalidated tar paths.
import hashlib, io, json, pathlib, tarfile

PINNED_NOTICES = {
    'LICENSE': 'c6fe05491a60ae13bcd223088d2705e36dede24e5587226231d2459ada5c4822',
    'LICENSE-3RD-PARTY.md': 'b4366b9c27a9364633e015011a231913ed19bf1228f335bf617e50a6f7b168a6',
    'LICENSE-SQLITE': '8438c9c89b849131ead81d5435cb97fcf052df5b0b286dda8a2d4c29e6cb3fd0',
    'LICENSE-SQLITE_VEC': '6ce72bbe12d975bd5286e5ab0a064c069693300c47bccbc57bec18485f1621ea',
}

def verified_notices(raw, item):
    assert len(raw) == item['size'] and 0 < len(raw) <= 2 * 1024 * 1024
    assert hashlib.sha256(raw).hexdigest() == item['sha256']
    assert len(raw) % 512 == 0 and raw[-1024:] == bytes(1024)
    files = {}
    with tarfile.open(fileobj=io.BytesIO(raw), mode='r:') as archive:
        for member in archive:
            assert member.name in PINNED_NOTICES or member.name == 'INVENTORY.json'
            assert member.name not in files and member.isreg() and not member.linkname
            assert not member.pax_headers and 0 < member.size <= 2 * 1024 * 1024
            files[member.name] = archive.extractfile(member).read()
        assert not any(raw[archive.offset:]), 'Archive trailing data rejected'
    assert len(files) == 5
    for name, sha256 in PINNED_NOTICES.items():
        assert hashlib.sha256(files[name]).hexdigest() == sha256
    inventory = json.loads(files['INVENTORY.json'])
    assert inventory['schema'] == 1 and inventory['driver'] == 'modernc.org/sqlite@v1.60.1'
    assert len(inventory['files']) == 4
    expected = {name: (digest, len(files[name])) for name, digest in PINNED_NOTICES.items()}
    assert {entry['name']: (entry['sha256'], entry['size']) for entry in inventory['files']} == expected
    for arch in ['linux-amd64', 'linux-arm64']:
        entries = inventory['linkedModules'][arch]
        assert len({entry['path'] for entry in entries}) == len(entries)
        assert all(entry['path'] and entry['version'] and entry['sum'].startswith('h1:') for entry in entries)
        versions = {entry['path']: entry['version'] for entry in entries}
        assert versions['modernc.org/sqlite'] == 'v1.60.1' and versions['modernc.org/libc'] == 'v1.77.1'
    return files
