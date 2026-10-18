"""Passing controls, named assertions, and build accounting for mutation evidence."""
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from mutation_runner import execute_plant


class Controls(unittest.TestCase):
    def scenario(self, clean_fails=False, broken_build=False):
        with tempfile.TemporaryDirectory(prefix='smb-controls-') as directory:
            root = Path(directory)
            (root / 'server').mkdir()
            (root / 'castle-wall-daemon').mkdir()
            source = root / 'guard'
            source.write_text('refuse\n')
            patch = root / 'plant.patch'
            patch.write_text('--- a/guard\n+++ b/guard\n@@ -1 +1 @@\n-refuse\n+admit\n')
            report = root / 'report.json'
            # These are actual child programs: the assertion examines bytes changed by the patch.
            test = root / 'witness.py'
            test.write_text(f'''
import json
from pathlib import Path
import sys
root = Path(__file__).parent
passed = (root / 'guard').read_text() == 'refuse\\n' and {not clean_fails!r}
(root / 'report.json').write_text(json.dumps({{'testResults':[{{'assertionResults':[{{'fullName':'control', 'status':'passed' if passed else 'failed', 'failureMessages':[]}}]}}]}}))
sys.exit(0 if passed else 1)
''')
            build = root / 'build.py'
            build.write_text(f'''
from pathlib import Path
import sys
bad = {broken_build!r} and (Path(__file__).parent / 'guard').read_text() == 'admit\\n'
sys.exit(1 if bad else 0)
''')
            verdict = execute_plant(root, patch, 'control', [sys.executable, str(build)],
                                    [sys.executable, str(test)], dict(os.environ), report)
            self.assertEqual(source.read_text(), 'refuse\n')
            return verdict

    def test_clean_failure_refuses_to_plant(self):
        self.assertEqual(self.scenario(clean_fails=True), 'broken')

    def test_compile_failure_is_broken(self):
        self.assertEqual(self.scenario(broken_build=True), 'broken')

    def test_changed_guard_killed_by_assertion(self):
        self.assertEqual(self.scenario(), 'killed')


if __name__ == '__main__':
    unittest.main()
