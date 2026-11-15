"""Accounting-only negative regressions; no product runtime or archival fixture is simulated as evidence."""
import copy
import importlib.util
from pathlib import Path
import unittest


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(file))
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


accounting = load('partition_accounting', 'container-ci-accounting.py')
report = load('partition_test_report', 'check-go-ci.py')
PACKAGE = 'unit/accounting'


class PartitionTests(unittest.TestCase):
    def scope(self, name):
        inventory = [dict(Package=PACKAGE, Action='output', Output=name + '\n')]
        events = [dict(Package=PACKAGE, Test=name, Action=action) for action in ('run', 'pass')]
        events.append(dict(Package=PACKAGE, Action='pass'))
        return dict(name=name, directory='unit-only:' + name, assigned=[(PACKAGE, name)],
                    actualRunnerExit=0, actualCaptureExit=0, accounting=report.audit(inventory, events, 0, 0))

    def result(self, scopes, expected=None):
        return accounting.partition_report(expected or {(PACKAGE, 'TestA'), (PACKAGE, 'TestB')}, scopes, report.ARCHIVAL_TEST)

    def test_disjoint_actual_scope_accounting_covers_inventory_once(self):
        value = self.result([self.scope('TestA'), self.scope('TestB')])
        self.assertEqual(value['errors'], [])
        self.assertEqual(value['ordinaryPassed'], 2)
        self.assertTrue(value['completeInventoryAccounted'])

    def test_scoped_green_cannot_cover_missing_test(self):
        value = self.result([self.scope('TestA')])
        self.assertIn('DISCOVERED_TESTS_NOT_ASSIGNED', value['errors'])
        self.assertFalse(value['fullOrdinaryCIGreen'])

    def test_duplicate_and_undiscovered_assignments_fail(self):
        for scopes, error in [([self.scope('TestA'), self.scope('TestA'), self.scope('TestB')], 'OVERLAPPING_SCOPE_ASSIGNMENT'),
                              ([self.scope('TestA'), self.scope('TestB'), self.scope('TestUnknown')], 'UNDISCOVERED_SCOPE_ASSIGNMENT')]:
            with self.subTest(error=error):
                self.assertIn(error, self.result(scopes)['errors'])

    def test_real_runner_or_capture_failure_survives_green_accounting(self):
        for field, value in [('actualRunnerExit', 7), ('actualCaptureExit', 1), ('actualRunnerExit', False)]:
            with self.subTest(field=field, value=value):
                scopes = [self.scope('TestA'), self.scope('TestB')]
                scopes[0][field] = value
                result = self.result(scopes)
                self.assertTrue(result['errors'])
                self.assertFalse(result['fullOrdinaryCIGreen'])

    def test_unknown_skip_remains_fail(self):
        scope = self.scope('TestB')
        scope['accounting'] = report.audit([dict(Package=PACKAGE, Action='output', Output='TestB\n')],
            [dict(Package=PACKAGE, Test='TestB', Action=action) for action in ('run', 'skip')] +
            [dict(Package=PACKAGE, Action='pass')], 0, 0)
        self.assertIn('SCOPE_ACCOUNTING_FAILED', self.result([self.scope('TestA'), scope])['errors'])

    def test_explicit_conditional_not_run_never_becomes_full_pass_or_owner_waiver(self):
        scope = self.scope('TestB')
        scope['accounting']['ordinaryPassed'] = 0
        scope['accounting']['conditionalNotRun'] = [dict(package=PACKAGE, test='TestB', status='NOT_RUN', ownerWaiver=False)]
        value = self.result([self.scope('TestA'), scope])
        self.assertEqual(value['errors'], [])
        self.assertEqual(value['ordinaryPassed'], 1)
        self.assertEqual(value['status'], 'PASS_DEFAULT_ORDINARY_WITH_EXPLICIT_CONDITIONAL_NOT_RUN')
        self.assertFalse(value['fullOrdinaryCIGreen'])
        self.assertFalse(value['conditionalQualificationComplete'])
        invalid = copy.deepcopy(scope)
        invalid['accounting']['conditionalNotRun'][0]['ownerWaiver'] = True
        self.assertIn('CONDITIONAL_CASE_MUST_REMAIN_NOT_RUN', self.result([self.scope('TestA'), invalid])['errors'])

    def test_archival_waiver_cannot_silently_enter_ordinary_inventory(self):
        value = self.result([self.scope(report.ARCHIVAL_TEST)], {(PACKAGE, report.ARCHIVAL_TEST)})
        self.assertIn('ARCHIVAL_TEST_PRESENT_IN_ORDINARY_CI', value['errors'])
        self.assertFalse(value['fullOrdinaryCIGreen'])
        self.assertFalse(value['archival']['historicalV8CompatibilityConfirmed'])

    def test_discovery_duplicate_and_future_example_or_fuzz_require_assignment(self):
        for output in ('TestA\nTestA\n', 'ExampleFuture\n', 'FuzzFuture\n'):
            with self.subTest(output=output), self.assertRaises(ValueError):
                accounting.discovered_tests([dict(Package=PACKAGE, Action='output', Output=output)])


if __name__ == '__main__':
    unittest.main()
