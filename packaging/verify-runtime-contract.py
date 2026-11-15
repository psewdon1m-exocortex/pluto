# Embedded in generated bootstrap. The policy boundary is compiled installer code,
# never a value chosen by signed metadata to waive notice requirements.
import json, re

CONTRACT_REQUIRED_SINCE = '0.1.5'

def unique_release_json(raw):
    assert len(raw) <= 65536
    def pairs(items):
        result = {}
        for key, value in items:
            assert key not in result, 'Duplicate release JSON key'
            result[key] = value
        return result
    value = json.loads(raw, object_pairs_hook=pairs)
    def bounded(node, depth=0):
        assert depth <= 16, 'Release JSON nesting exceeds limit'
        if isinstance(node, dict):
            for child in node.values(): bounded(child, depth + 1)
        elif isinstance(node, list):
            for child in node: bounded(child, depth + 1)
    bounded(value)
    return value

def requires_runtime_contract(version):
    assert isinstance(version, str) and re.fullmatch(r'(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)', version)
    for actual, expected in zip(version.split('.'), CONTRACT_REQUIRED_SINCE.split('.')):
        if actual != expected:
            return len(actual) > len(expected) if len(actual) != len(expected) else actual > expected
    return True

def validate_runtime_contract(manifest):
    required = requires_runtime_contract(manifest['version'])
    if 'runtimeContract' not in manifest:
        assert not required, 'Release requires embedded runtime contract'
        if manifest['schema'] == 1: assert 'runtimeNotices' not in manifest
        return False
    assert required and isinstance(manifest.get('runtimeNotices'), dict)
    item = manifest['runtimeNotices']['artifact']
    expected = {'schema': 'pluto-runtime-contract.v1', 'policy': 'sqlite-runtime-notices.v1',
                'requiredSince': CONTRACT_REQUIRED_SINCE,
                'embedded': {'format': 'pluto-runtime-notices.tar.v1', 'command': 'licenses --archive',
                             'size': item['size'], 'sha256': item['sha256']}}
    assert manifest['runtimeContract'] == expected, 'Runtime contract policy or identity rejected'
    return True

def bounded_candidate_command(executable, arguments, maximum):
    import os, selectors, signal, subprocess, time
    child = subprocess.Popen([str(executable), *arguments], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, start_new_session=True)
    streams = selectors.DefaultSelector()
    streams.register(child.stdout, selectors.EVENT_READ, ('stdout', maximum))
    streams.register(child.stderr, selectors.EVENT_READ, ('stderr', 4096))
    output = {'stdout': bytearray(), 'stderr': bytearray()}
    deadline = time.monotonic() + 5
    try:
        while streams.get_map():
            remaining = deadline - time.monotonic()
            assert remaining > 0, 'Candidate command deadline exceeded'
            for event, _ in streams.select(remaining):
                name, limit = event.data
                data = os.read(event.fileobj.fileno(), 65536)
                if not data: streams.unregister(event.fileobj); continue
                assert len(output[name]) + len(data) <= limit, 'Candidate command exceeds output limit'
                output[name].extend(data)
        assert child.wait(timeout=max(0.01, deadline - time.monotonic())) == 0
        return bytes(output['stdout'])
    finally:
        streams.close()
        # A child that exits early may leave descendants holding these pipes.
        # This private group was created by this probe, never discovered by name.
        try: os.killpg(child.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        child.wait()
