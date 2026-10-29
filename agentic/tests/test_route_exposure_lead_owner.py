"""Only access_control confirms a route exposure lead (plan §23.13, AG3).

A live session with access_control off switched to rce and confirmed every lead
on "200 with the predicted content", a public-by-design route included. The
writer now refuses a lead's CONFIRMS edge from any other skill, so every caller
must hand it the skill; the live half is in test_route_exposure_confirm_live.py.

Run: ./agentic/run_tests.sh tests/test_route_exposure_lead_owner.py
"""

import ast
from pathlib import Path

from orchestrator_helpers import chain_graph_writer as writer

ROOT = Path(__file__).resolve().parents[1]


class _Session:
    def __init__(self):
        self.calls = []

    def run(self, query, params=None, **kw):
        self.calls.append((query, params or kw))


def _confirms_call(skill):
    session = _Session()
    writer._resolve_finding_bridges(session, "cf-1", [], [], "vulnerability_confirmed", "u", "p",
                                    related_finding_ids=["route_exposure_a"], skill=skill)
    return next((q, p) for q, p in session.calls if "CONFIRMS" in q)


def test_the_confirms_write_carries_the_skill_and_the_owner():
    query, params = _confirms_call("rce")
    assert "$skill = $lead_owner" in query
    assert "coalesce(target.needs_agent_confirmation, false) = false" in query
    assert "coalesce(target.source, '') <> 'route_exposure'" in query
    assert params["skill"] == "rce" and params["lead_owner"] == "access_control"


def test_a_missing_skill_is_the_empty_string_never_none():
    # None = 'access_control' is null in Cypher, which the OR would turn into a
    # pass for a signature finding but an unknown for a lead: keep it a string.
    _, params = _confirms_call(None)
    assert params["skill"] == ""


def _calls(path):
    tree = ast.parse((ROOT / path).read_text())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", "") == "fire_record_finding":
            yield node


def test_every_node_hands_the_writer_its_skill():
    seen = 0
    for path in ("orchestrator_helpers/nodes/think_node.py",
                 "orchestrator_helpers/nodes/fireteam_member_think_node.py"):
        for call in _calls(path):
            seen += 1
            kw = {k.arg: ast.unparse(k.value) for k in call.keywords}
            assert kw.get("skill") == "state.get('attack_path_type', '')", (path, call.lineno)
    assert seen == 4
