"""Test whether a Claude agent can be hijacked by instructions hidden in what it reads, and find what to fix.

Most people start at the command line, in `cli.py`. From Python, these are the names to use on a skill or agent you own:
read it with `load_target`, then check it for free with `audit`, or run planted attacks on it with `scan`.
"""

from injectiontests.lib.existing_agents.attacks import load_attacks
from injectiontests.lib.existing_agents.audit import audit
from injectiontests.lib.existing_agents.report import audit_report, scan_report
from injectiontests.lib.existing_agents.scan import scan
from injectiontests.lib.existing_agents.targets import find_target_files, load_target

__all__ = ["audit", "audit_report", "find_target_files", "load_attacks", "load_target", "scan", "scan_report"]
