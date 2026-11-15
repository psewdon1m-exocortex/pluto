"""Stage fresh ordinary Go inputs, then irreversibly enter the reviewed UID10001 profile."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat


spec = json.loads(Path('/input.json').read_bytes())
assert os.getpid() == 1 and os.getuid() == os.getgid() == 0
assert spec['schema'] == 'pluto.ordinary-ci-worker-input.v1'
assert socket.gethostname() == spec['containerId'][:12]
source = Path('/test-input')
assert source.is_file() and not source.is_symlink()
with source.open('rb') as stream:
    assert hashlib.file_digest(stream, 'sha256').hexdigest() == spec['testBinarySHA256']
target = Path('/runtime/go-test')
assert not target.exists() and not target.is_symlink()
with source.open('rb') as src, target.open('xb') as dest:
    shutil.copyfileobj(src, dest, 65536)
    os.fchmod(dest.fileno(), 0o555)
    dest.flush()
    os.fsync(dest.fileno())
assert target.stat().st_uid == target.stat().st_gid == 0
for top, names in [('/retained', ['inputs', 'evidence']), ('/backups', ['store'])]:
    root = Path(top)
    assert root.is_dir() and not root.is_symlink() and not list(root.iterdir())
    assert root.stat().st_uid == root.stat().st_gid == 0
    assert shutil.disk_usage(root).free >= 65 * 2**30
    for name in names:
        directory = root / name
        directory.mkdir(mode=0o700)
        os.chown(directory, 10001, 10001)
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    os.chmod(root, 0o755)
os.execv('/usr/bin/setpriv', ['/usr/bin/setpriv', '--reuid=10001', '--regid=10001',
                            '--clear-groups', '--inh-caps=-all', '--ambient-caps=-all',
                            '--bounding-set=-all', '--no-new-privs',
                            '/usr/local/bin/python3', '-I', '-B', '/worker.py'])
