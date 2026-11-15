"""Validate a disjoint partition of actual CI scopes; never synthesize Go events."""
import re


def discovered_tests(inventory):
    result = set()
    for event in inventory:
        if event.get('Action') == 'fail':
            raise ValueError('actual discovery failed')
        if event.get('Action') != 'output':
            continue
        for name in event.get('Output', '').splitlines():
            if name.startswith(('Example', 'Fuzz')):
                raise ValueError('Example/Fuzz execution needs an explicit CI assignment')
            if re.fullmatch('Test[A-Za-z0-9_]+', name):
                key = (event.get('Package', ''), name)
                if not key[0] or key in result:
                    raise ValueError('duplicate or unnamed discovery entry')
                result.add(key)
    if not result:
        raise ValueError('empty discovered inventory')
    return result


def partition_report(expected, scopes, archival_test):
    """Each input accounting has already been checked against its raw scope events."""
    errors, assigned, passed, conditional = [], set(), 0, []
    if any(name == archival_test for _, name in expected):
        errors.append('ARCHIVAL_TEST_PRESENT_IN_ORDINARY_CI')
    summaries = []
    for scope in scopes:
        keys = set(scope['assigned'])
        accounting = scope['accounting']
        if len(keys) != len(scope['assigned']) or not keys:
            errors.append('EMPTY_OR_DUPLICATE_SCOPE_ASSIGNMENT')
        if keys & assigned:
            errors.append('OVERLAPPING_SCOPE_ASSIGNMENT')
        assigned |= keys
        if type(scope['actualRunnerExit']) is not int or scope['actualRunnerExit'] != 0:
            errors.append('ACTUAL_SCOPE_RUNNER_FAILED')
        if type(scope['actualCaptureExit']) is not int or scope['actualCaptureExit'] != 0:
            errors.append('ACTUAL_SCOPE_CAPTURE_FAILED')
        if accounting['errors'] or accounting['ordinaryDiscovered'] != len(keys):
            errors.append('SCOPE_ACCOUNTING_FAILED')
        pending = accounting.get('conditionalNotRun', [])
        if accounting['ordinaryPassed'] + len(pending) != len(keys):
            errors.append('SCOPE_TESTS_NOT_ACCOUNTED')
        pending_keys = {(row['package'], row['test']) for row in pending}
        if len(pending_keys) != len(pending) or not pending_keys <= keys:
            errors.append('INVALID_CONDITIONAL_SCOPE_ASSIGNMENT')
        if any(row['status'] != 'NOT_RUN' or row['ownerWaiver'] is not False for row in pending):
            errors.append('CONDITIONAL_CASE_MUST_REMAIN_NOT_RUN')
        passed += accounting['ordinaryPassed']
        conditional += pending
        summaries.append(dict(name=scope['name'], directory=scope['directory'],
                              assigned=len(keys), actualRunnerExit=scope['actualRunnerExit'],
                              actualCaptureExit=scope['actualCaptureExit'], accounting=accounting))
    if assigned - expected:
        errors.append('UNDISCOVERED_SCOPE_ASSIGNMENT')
    if expected - assigned:
        errors.append('DISCOVERED_TESTS_NOT_ASSIGNED')
    errors = sorted(set(errors))
    return dict(schema='pluto.container-ordinary-ci.v1',
                status='FAIL_REQUIRED_ORDINARY_GO_TEST_SUITE' if errors else
                       'PASS_DEFAULT_ORDINARY_WITH_EXPLICIT_CONDITIONAL_NOT_RUN' if conditional else
                       'PASS_REQUIRED_ORDINARY_GO_TEST_SUITE',
                ordinaryDiscovered=len(expected), ordinaryAssigned=len(assigned), ordinaryPassed=passed,
                conditionalNotRun=conditional, conditionalQualificationComplete=not conditional,
                fullOrdinaryCIGreen=not errors and not conditional, completeInventoryAccounted=not errors,
                scopes=summaries, errors=errors,
                archival=dict(test=archival_test, status='WAIVED_BY_OWNER', reason='ARCHIVAL_INPUT_UNAVAILABLE',
                              runtime='NOT_RUN', historicalV8CompatibilityConfirmed=False,
                              downgradeSafetyConfirmed=False))
