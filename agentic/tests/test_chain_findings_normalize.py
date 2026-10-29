"""chain_findings normalisation: a confirmation is its ids.

The route exposure agent campaign (AG1, deepseek-v4-pro) re-recorded proven
leads as entries carrying finding_type, related_finding_ids and confidence but no
title or evidence, which the normaliser dropped as meaningless; the model kept
believing they were written. An entry that names the recon finding it proves is
kept; one that names nothing is still dropped.

Run: ./agentic/run_tests.sh tests/test_chain_findings_normalize.py
"""

import json

from orchestrator_helpers.parsing import try_parse_llm_decision


def _decision(chain_findings):
    return json.dumps({
        "thought": "t", "reasoning": "r", "action": "use_tool", "tool_name": "query_graph",
        "tool_args": {"question": "MATCH (n) RETURN n LIMIT 1"},
        "output_analysis": {"interpretation": "i", "chain_findings": chain_findings},
    })


def _findings(chain_findings):
    decision, error = try_parse_llm_decision(_decision(chain_findings))
    assert error is None, error
    return decision.output_analysis.chain_findings


def test_an_entry_with_ids_and_no_title_is_kept():
    [f] = _findings([{"finding_type": "vulnerability_confirmed",
                      "related_finding_ids": ["route_exposure_b37ac20e1becd5e443e974cf"], "confidence": 90}])
    assert f.related_finding_ids == ["route_exposure_b37ac20e1becd5e443e974cf"]
    assert f.title == "vulnerability_confirmed: route_exposure_b37ac20e1becd5e443e974cf"
    assert f.confidence == 90


def test_an_entry_naming_nothing_is_still_dropped():
    assert _findings([{"finding_type": "custom", "confidence": 60},
                      {"finding_type": "custom", "title": " ", "related_finding_ids": [" "]}]) == []


def test_one_id_as_a_bare_string_does_not_fail_the_decision():
    [f] = _findings([{"finding_type": "vulnerability_confirmed", "title": "t",
                      "related_finding_ids": "route_exposure_x", "confidence": 85}])
    assert f.related_finding_ids == ["route_exposure_x"]


def test_a_null_title_does_not_fail_the_decision():
    [f] = _findings([{"finding_type": "vulnerability_confirmed", "title": None, "evidence": "200/200 sha 1a2b",
                      "related_finding_ids": ["route_exposure_y"]}])
    assert f.related_finding_ids == ["route_exposure_y"]
