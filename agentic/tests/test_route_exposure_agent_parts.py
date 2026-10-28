"""The route-exposure parts of access_control, path_traversal and rce (plan §23.12).

With recon's route exposure module off, the three skills render byte-identical
text (the golden's ALL_OFF hashes). With it on, the new parts follow the
existing ones; each gated part is absent unless its switch AND the RoE allow it,
and its parent prints ENABLED / DISABLED to match. Every part names real tools
only and carries the record contract, the verify step, the rejection rule, the
forbidden actions and the values-in-files rule.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent / "tools"))

from record_skill_golden import ALL_OFF, ALL_TOOLS, render_workflow  # noqa: E402

GOLDEN = json.loads((Path(__file__).resolve().parent / "fixtures" / "skill_workflow_golden.json").read_text())
SKILLS = ("access_control", "path_traversal", "rce")
ON = {"ROUTE_EXPOSURE_ENABLED": True}
GATES = {"PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True, "PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED": True,
         "RCE_HEAPDUMP_ANALYSIS_ENABLED": True}
ROE_OK = {"ROE_ALLOW_DATA_EXFILTRATION": True, "ROE_SENSITIVE_DATA_HANDLING": "limited_collection"}
REAL_TOOLS = {"execute_curl", "execute_code", "execute_playwright", "fs_write", "fs_list", "fs_delete",
              "job_spawn", "kali_shell", "query_graph", "graph_summary", "proxy_brain", "switch_skill"}


def _render(skill, settings, tools=ALL_TOOLS):
    return render_workflow(skill, settings, tools, False, [])


def _sha(parts):
    return hashlib.sha256("\n".join(parts).encode()).hexdigest()


def _text(skill, settings):
    return "\n".join(_render(skill, settings))


@pytest.mark.parametrize("skill", SKILLS)
def test_module_off_is_byte_identical(skill):
    for name, settings in (("defaults", {}), ("all_off", ALL_OFF)):
        assert _sha(_render(skill, settings)) == GOLDEN["workflow"][f"{name}/{skill}"]["sha256"]
    # The switches alone change nothing while the module is off.
    assert _sha(_render(skill, {**GATES, **ROE_OK})) == GOLDEN["workflow"][f"defaults/{skill}"]["sha256"]


@pytest.mark.parametrize("skill,new", [
    ("access_control", ["ROUTE EXPOSURE LEADS"]),
    ("path_traversal", ["EXPOSED FILES RECON FOUND"]),
    ("rce", ["DEBUG CONSOLES AND ENDPOINTS RECON FOUND"]),
])
def test_module_on_appends_the_new_part_after_the_existing_ones(skill, new):
    off = _render(skill, {})
    on = _render(skill, ON)
    assert on[:len(off)] == off
    assert len(on) == len(off) + len(new)
    for part, marker in zip(on[len(off):], new):
        assert marker in part


@pytest.mark.parametrize("settings,git,val", [
    ({}, False, False),
    ({"PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True}, False, False),          # switch, RoE forbids
    ({"PATH_TRAVERSAL_GIT_RECONSTRUCT_ENABLED": True, **ROE_OK}, True, False),
    ({"PATH_TRAVERSAL_VALIDATE_SECRETS_ENABLED": True}, False, True),         # switch only
    ({**GATES, **ROE_OK}, True, True),
])
def test_path_traversal_gates(settings, git, val):
    text = _text("path_traversal", {**ON, **settings})
    assert ("RECONSTRUCT AN EXPOSED .git" in text) is git
    assert ("VALIDATE A SECRET FROM AN EXPOSED FILE" in text) is val
    assert f"git reconstruction: {'ENABLED' if git else 'DISABLED'}" in text
    assert f"secret validation: {'ENABLED' if val else 'DISABLED'}" in text


def test_gated_parts_need_execute_code():
    tools = tuple(t for t in ALL_TOOLS if t != "execute_code")
    text = _text("path_traversal", {**ON, **GATES, **ROE_OK})
    assert "RECONSTRUCT AN EXPOSED .git" in text
    text = "\n".join(_render("path_traversal", {**ON, **GATES, **ROE_OK}, tools))
    assert "RECONSTRUCT AN EXPOSED .git" not in text and "git reconstruction: DISABLED" in text


@pytest.mark.parametrize("settings,on", [
    ({"RCE_HEAPDUMP_ANALYSIS_ENABLED": True}, False),
    ({"RCE_HEAPDUMP_ANALYSIS_ENABLED": True, "ROE_ALLOW_DATA_EXFILTRATION": True}, False),  # handling no_access
    ({"RCE_HEAPDUMP_ANALYSIS_ENABLED": True, **ROE_OK}, True),
    (ROE_OK, False),
])
def test_rce_heapdump_gate(settings, on):
    text = _text("rce", {**ON, **settings})
    assert ("ANALYSE AN EXPOSED HEAP DUMP" in text) is on
    assert f"heapdump analysis: {'ENABLED' if on else 'DISABLED'}" in text


# The existing parts' factory hashes are pinned in test_skill_override_compat.py.


def _new_parts():
    from prompts import (ACCESS_CONTROL_ROUTE_EXPOSURE_LEADS, PATH_TRAVERSAL_EXPOSED_FILES,
                         PATH_TRAVERSAL_GIT_RECONSTRUCT, PATH_TRAVERSAL_VALIDATE_SECRETS,
                         RCE_HEAPDUMP_ANALYSIS, RCE_ROUTE_EXPOSURE_CONSOLES)
    return {
        "leads": ACCESS_CONTROL_ROUTE_EXPOSURE_LEADS,
        "exposed_files": PATH_TRAVERSAL_EXPOSED_FILES.format(git_reconstruct="DISABLED",
                                                             validate_secrets="DISABLED"),
        "git": PATH_TRAVERSAL_GIT_RECONSTRUCT,
        "validate": PATH_TRAVERSAL_VALIDATE_SECRETS,
        "consoles": RCE_ROUTE_EXPOSURE_CONSOLES.format(heapdump_analysis="DISABLED"),
        "heapdump": RCE_HEAPDUMP_ANALYSIS,
    }


@pytest.mark.parametrize("name", ["leads", "exposed_files", "git", "validate", "consoles", "heapdump"])
def test_every_part_names_real_tools_only_and_no_em_dash(name):
    text = _new_parts()[name]
    assert "—" not in text
    named = set(re.findall(r"\b(execute_[a-z_]+|fs_[a-z]+|job_spawn|kali_shell|query_graph|graph_summary|"
                           r"proxy_brain|switch_skill)\b", text))
    assert named <= REAL_TOOLS, named - REAL_TOOLS
    assert "{" not in re.sub(r"\{[^{}]*\}", "", text) or "MATCH" in text


@pytest.mark.parametrize("name", ["leads", "exposed_files", "consoles"])
def test_main_parts_carry_the_contract(name):
    text = _new_parts()[name]
    # A bounded, ordered pull of route_exposure nodes.
    assert "source:'route_exposure'" in text and "ORDER BY" in text and "LIMIT 50" in text
    # The record contract: the proof type with the exact id, in the same response, then verified.
    assert "vulnerability_confirmed" in text and "related_finding_ids" in text
    assert "IN THE SAME RESPONSE" in text
    assert "MATCH (cf:ChainFinding)-[:CONFIRMS]->(v:Vulnerability {id:'<ID>'})" in text
    assert "NEVER put ids on `exploit_success`" in text
    # The rejection rule and the forbidden actions.
    assert "gets NO entry at all" in text
    for forbidden in ("never POST to any `/actuator/*` path", "springboot-env-rce-chains",
                      "never guess or compute a PIN", "No form submit, no"):
        assert forbidden in text
    # Values stay in files, with the banned curl flags.
    assert "/tmp/rex-<id>-anon.body" in text
    assert "`-v`, `-i`, `--trace`, `-D -` and `-o -` are" in text


def test_the_handoff_names_only_path_traversal_and_rce():
    text = _new_parts()["leads"]
    targets = set(re.findall(r"to_skill: '([a-z_]+)'", text)) | set(re.findall(r"switch to `([a-z_]+)`", text))
    assert targets == {"path_traversal", "rce"}
    from state import KNOWN_ATTACK_PATHS
    assert targets <= set(KNOWN_ATTACK_PATHS)


def test_exploitation_only_steps_say_so():
    parts = _new_parts()
    assert "EXPLOITATION phase only" in parts["leads"]
    assert "EXPLOITATION phase" in parts["git"] and "EXPLOITATION phase" in parts["heapdump"]
    assert "Unlocked (EXPLOITATION phase)" in parts["consoles"]
