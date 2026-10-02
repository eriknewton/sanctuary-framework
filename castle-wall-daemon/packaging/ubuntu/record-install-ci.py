#!/usr/bin/env python3
"""Record CI provenance and required-job inventory; not a delivery verifier."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

REPO = Path(__file__).resolve().parents[3]
WORKFLOW = '.github/workflows/linux-install-package.yml'
# Must match the unconditional jobs and evidence needs in linux-install-package.yml.
PACKAGE_JOBS = ['install-rust', 'install-agent-manager', 'install-package-build', 'install-package-lifecycle', 'install-cold-composition']
# P4 must resolve matrix instances, check the unfiltered exact-head check view,
# and freeze every actual required job before any proof-host mutation. These
# categories cannot be silently removed by path filters or renamed workflows.
EXTERNAL_JOBS = {
    '.github/workflows/castle-wall-linux.yml': ['castle-wall-msrv', 'castle-wall-linux-integration', 'sanctuary-jail-static'],
    '.github/workflows/linux-package-structure.yml': ['internal-package-structure', 'internal-package-lifecycle'],
    '.github/workflows/ci.yml': ['test', 'lint'],
    '.github/workflows/test-baseline-guard.yml': ['test-baseline-guard'],
}
REQUIRED_CATEGORIES = ['Linux Rust fmt/clippy/locked tests', 'internal/install archives and lifecycle negatives',
                       'actual-manager launch and isolation', 'cold-install composition', 'frozen surfaces',
                       'typecheck and affected server tests', 'full required baseline suite']


def record(destination, require):
    source = subprocess.check_output(['git', '-C', str(REPO), 'rev-parse', 'HEAD'], text=True).strip()
    if source != os.environ.get('INSTALL_SOURCE_SHA') or not re.fullmatch(r'[0-9a-f]{40}', source):
        raise ValueError('CI checkout differs from exact source head')
    files = {WORKFLOW: [*PACKAGE_JOBS, 'install-package-evidence'], **EXTERNAL_JOBS}
    inventory = {}
    for path, jobs in files.items():
        raw = (REPO / path).read_bytes()
        # Closed indentation pins job IDs without depending on a YAML package.
        # YAML syntax itself is checked by the repository's workflow parse gate.
        actual = re.findall(r'^  ([a-z][a-z0-9-]*):\s*$', raw.decode(), re.M)
        if not set(jobs) <= set(actual):
            raise ValueError('required job disappeared from workflow: ' + path)
        inventory[path] = {'sha256': hashlib.sha256(raw).hexdigest(), 'required_job_ids': jobs}
    needs = json.loads(os.environ.get('INSTALL_NEEDS', '{}'))
    record = {'source_commit': source, 'workflow': WORKFLOW,
              'workflow_ref': os.environ.get('GITHUB_WORKFLOW_REF'),
              'workflow_sha': os.environ.get('GITHUB_WORKFLOW_SHA'),
              'run_id': os.environ.get('GITHUB_RUN_ID'), 'run_attempt': os.environ.get('GITHUB_RUN_ATTEMPT'),
              'artifact_id': os.environ.get('INSTALL_ARTIFACT_ID'),
              'artifact_service_digest': os.environ.get('INSTALL_ARTIFACT_DIGEST'),
              'required_inventory': inventory, 'required_categories': REQUIRED_CATEGORIES,
              'package_job_results': needs, 'external_exact_head_acceptance': 'P4 coordinator required',
              'reboot_claim': False}
    destination.write_text(json.dumps(record, sort_keys=True, indent=2) + '\n')
    if require:
        if set(needs) != set(PACKAGE_JOBS) or any(needs[job].get('result') != 'success' for job in PACKAGE_JOBS):
            raise ValueError('missing, skipped, cancelled or unsuccessful required package job')
        if not record['artifact_id'] or not re.fullmatch(r'(sha256:)?[0-9a-f]{64}', record['artifact_service_digest'] or ''):
            raise ValueError('artifact service identity/digest missing')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('output', type=Path)
    parser.add_argument('--require-package-jobs', action='store_true')
    try:
        args = parser.parse_args()
        record(args.output, args.require_package_jobs)
    except (ValueError, OSError, subprocess.SubprocessError) as exc:
        print('CI build record refused: ' + str(exc), file=sys.stderr)
        sys.exit(1)
