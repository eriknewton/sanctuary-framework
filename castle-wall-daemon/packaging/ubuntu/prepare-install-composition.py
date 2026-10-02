#!/usr/bin/env python3
"""Create public CI inputs with the shipped signer and ephemeral test authority."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


def prepare(signer, output):
    output.mkdir(mode=0o755)
    # Test response authority only; must match Sentinels in ci-install-composition.py.
    response = Ed25519PrivateKey.from_private_bytes(bytes([22]) * 32)
    key = response.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    endpoints = []
    for family, ip in [('ipv4', '127.0.0.1'), ('ipv6', '::1')]:
        for role, protocol, port in [('deny', 'tcp', 41001), ('deny', 'udp', 41002), ('allow', 'tcp', 41003)]:
            endpoints.append(dict(family=family, role=role, protocol=protocol, ip=ip, port=port,
                                  attempts=3, response_public_key_hex=key if role == 'allow' else None))
    (output / 'endpoints.json').write_text(json.dumps(dict(version=1, initial_delay_ms=60000,
        attempt_timeout_ms=3000, max_response_bytes=256, endpoints=endpoints)))
    (output / 'rules.json').write_text(json.dumps([dict(id='composition-allow', schema_version=1,
        created_at='2026-10-01T00:00:00Z', match=dict(ip=['127.0.0.1', '::1'], port=[41003], protocol='tcp'), disposition='allow')]))
    # Never retain or transfer the test signing seed; only the public bundle leaves.
    with tempfile.NamedTemporaryFile() as seed:
        seed.write(os.urandom(32))
        seed.flush()
        os.fchmod(seed.fileno(), 0o600)
        subprocess.run([str(signer.resolve()), '--fortress-id', '0123456789abcdef', '--agent-uid', '60123',
            '--system-uid-ceiling', '1000', '--generation', '1', '--rules', str(output / 'rules.json'),
            '--key-fd', str(seed.fileno()), '--output', str(output / 'policy.bundle.json')],
            pass_fds=(seed.fileno(),), check=True, timeout=30)
    bundle = json.loads((output / 'policy.bundle.json').read_text())
    (output / 'policy-key-sha256').write_text(hashlib.sha256(bytes.fromhex(bundle['public_key_hex'])).hexdigest() + '\n')
    for path in output.iterdir():
        path.chmod(0o644)
    (output / 'inputs.sha256').write_text(''.join(hashlib.sha256(p.read_bytes()).hexdigest() + '  ' + p.name + '\n' for p in sorted(output.iterdir())))


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--signer', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    prepare(args.signer, args.output)
