"""Emit one JUnit testcase for each actual pytest 9 subtest report.

Pytest's default JUnit reporter counts subtests in suite totals but reuses the
parent node reporter, omitting successful subtest elements. Keep its normal
reporting behavior and give each observed subtest an explicit, finalized node.
This changes evidence only, never test outcomes or required skip policy.
"""

from collections import defaultdict
from copy import copy

import pytest
from _pytest.junitxml import xml_key
from _pytest.subtests import SubtestReport


@pytest.hookimpl(trylast=True)
def pytest_configure(config):
    xml = config.stash.get(xml_key, None)
    if xml is None:
        return
    original = xml.pytest_runtest_logreport
    ordinals = defaultdict(int)

    def logreport(report):
        if not isinstance(report, SubtestReport):
            original(report)
            return
        if report.when != "call":
            raise pytest.UsageError("PORTABLE_SUBTEST_REPORT_PHASE_UNSUPPORTED")
        parent = report.nodeid
        ordinals[parent] += 1
        ordinal = ordinals[parent]
        distinct = copy(report)
        distinct.nodeid = f"{parent}::portable_subtest[{ordinal:06d}]"
        distinct.user_properties = [
            *report.user_properties,
            ("portable.subtest.parent", parent),
            ("portable.subtest.ordinal", str(ordinal)),
        ]
        original(distinct)
        # A subtest has no separate teardown report. Finalize the precise node
        # after its actual outcome has been recorded, keeping its own identity.
        xml.finalize(distinct)
        xml.open_reports = [item for item in xml.open_reports if item is not distinct]

    # Pluggy stores bound methods at registration, so re-register the same
    # reporter after replacing only its logreport callback. Other plugins see
    # the original report; assertion execution and terminal summaries are intact.
    config.pluginmanager.unregister(xml)
    xml.pytest_runtest_logreport = logreport
    config.pluginmanager.register(xml)
