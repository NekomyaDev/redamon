#!/usr/bin/env python3
"""End-to-end validator for the route exposure scan against this lab (plan §22.2).

    python3 validate_route_exposure.py setup S1 [--start]   # create the temp project over MCP
    python3 validate_route_exposure.py start <projectId>      # after the AuthProfile is set in the UI
    python3 validate_route_exposure.py verify S1 <projectId>  # wait, then compare with expected_results.yaml
    python3 validate_route_exposure.py reset-hits             # empty every service's hit log
    python3 validate_route_exposure.py agent-leaks <transcript.json>

Reads MCP_SERVER_TOKEN from the repo .env (through mcp_client) and never prints
it. The AuthProfile cannot be set over MCP: set it in the UI between `setup`
and `start` for the scenarios that need one. Traffic is attributed by the
module's own window (route_exposure.summary.started_at .. finished_at):
katana, arjun and the other crawlers hit the lab earlier in the same scan.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
EXPECTED = yaml.safe_load((HERE / "expected_results.yaml").read_text())
ROLES = EXPECTED["roles"]
CONTAINER = "redamon-route-exposure-{}"


def _prefix() -> str:
    out = subprocess.run(["docker", "network", "inspect", "redamon-network", "--format",
                          "{{(index .IPAM.Config 0).Subnet}}"], capture_output=True, text=True, check=True)
    return ".".join(out.stdout.strip().split(".")[:3])


PREFIX = _prefix()


def ip(role: str) -> str:
    return f"{PREFIX}.{ROLES[role]}"


def _mcp():
    sys.path.insert(0, str(HERE))
    import mcp_client  # noqa: PLC0415 - reads the token on import
    mcp_client.init()
    return mcp_client


def _call(mcp, tool: str, args: dict):
    result, is_error = mcp.call(tool, args)
    if is_error:
        raise SystemExit(f"{tool} refused: {json.dumps(result)[:800] if not isinstance(result, str) else result[:800]}")
    return result


def _payload(result) -> dict:
    return result if isinstance(result, dict) else {"text": result}


def hits(role: str) -> list:
    out = subprocess.run(["docker", "exec", CONTAINER.format(role), "cat", "/tmp/hits.jsonl"],
                         capture_output=True, text=True)
    return [json.loads(line) for line in out.stdout.splitlines() if line.strip()]


def reset_hits() -> None:
    for role in ROLES:
        subprocess.run(["docker", "exec", CONTAINER.format(role), "sh", "-c", ": > /tmp/hits.jsonl"],
                       check=False, capture_output=True)


def scenario_settings(name: str) -> dict:
    sc = EXPECTED["scenarios"][name]
    settings = {
        # Keep the run short: the module needs live URLs and the routes recon found.
        "scanModules": ["port_scan", "http_probe", "resource_enum", "js_recon"],
        "cveLookupEnabled": False, "mitreEnabled": False, "nmapEnabled": False,
        "jsReconEnabled": True, "routeExposureEnabled": True,
        # Every other Phase A sender off, so the module is alone in its window.
        "webCachePoisonEnabled": False, "graphqlSecurityEnabled": False,
        "subdomainTakeoverEnabled": False, "vhostSniEnabled": False, "originDiscoveryEnabled": False,
    }
    for key, value in (sc.get("settings") or {}).items():
        if isinstance(value, list):
            value = [ip(v[1:-1]) if isinstance(v, str) and v.startswith("<") else v for v in value]
        settings[key] = value
    return settings


def cmd_setup(name: str, start: bool) -> None:
    sc = EXPECTED["scenarios"][name]
    mcp = _mcp()
    args = {
        "name": f"route-exposure-e2e {name} (temp)",
        "engagementKind": "internal",
        "targetIps": [ip(r) for r in sc["roles"]],
        "settings": scenario_settings(name),
        "idempotencyKey": f"route-exposure-e2e-{name}-{int(time.time())}",
    }
    body = _payload(_call(mcp, "create_project", args))
    project_id = body.get("projectId") or body.get("id") or (body.get("project") or {}).get("id")
    print(f"project {project_id}  auth={sc['auth']}  targets={args['targetIps']}")
    if sc["auth"] != "none":
        print(f"set the {sc['auth']} AuthProfile in the UI, then: {sys.argv[0]} start {project_id}")
    elif start:
        cmd_start(project_id, mcp)


def cmd_start(project_id: str, mcp=None) -> None:
    mcp = mcp or _mcp()
    reset_hits()
    print(json.dumps(_payload(_call(mcp, "start_recon", {"projectId": project_id}))))


def _wait(mcp, project_id: str, timeout_s: int = 3600) -> dict:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        status = _payload(_call(mcp, "get_recon_status", {"projectId": project_id}))
        state = str(status.get("status") or status.get("state") or "").lower()
        if state in ("completed", "complete", "done", "finished", "error", "failed", "stopped"):
            return status
        time.sleep(15)
    raise SystemExit("the scan did not finish in time")


def _ts(value: str) -> float:
    return datetime.fromisoformat(value).timestamp()


def _role_of(baseurl: str) -> str:
    host = baseurl.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    for role, last in ROLES.items():
        if host == f"{PREFIX}.{last}":
            return role
    return "?"


def _match(finding: dict, row: dict) -> list:
    problems = []
    for key, want in (row.get("fields") or {}).items():
        if finding.get(key) != want:
            problems.append(f"{key}={finding.get(key)!r}, expected {want!r}")
    for hint in row.get("expected_by") or []:
        if hint not in (finding.get("auth_expected_by") or []):
            problems.append(f"auth_expected_by lacks {hint}")
    return problems


def verify(name: str, project_id: str) -> int:
    sc = EXPECTED["scenarios"][name]
    mcp = _mcp()
    status = _wait(mcp, project_id)
    report: list = [f"## {name}", "", f"- project: `{project_id}`", f"- scan status: `{status.get('status')}`"]
    failures: list = []
    data = json.loads((REPO / "recon" / "output" / f"recon_{project_id}.json").read_text())
    if "route_exposure" not in (data.get("metadata") or {}).get("modules_executed", []):
        if sc.get("settings", {}).get("stealthMode"):
            report.append("- module not run (stealth): OK")
        else:
            failures.append("route_exposure is not in modules_executed")
    rex = data.get("route_exposure") or {}
    summary = rex.get("summary") or {}
    findings = rex.get("findings") or []
    report.append(f"- summary: {json.dumps({k: summary.get(k) for k in ('routes_harvested', 'routes_generated', 'routes_requested', 'budget_cut', 'candidates', 'findings', 'requests_sent', 'dropped')})}")

    got = {(_role_of(f["baseurl"]), f["path"], f["exposure_kind"]): f for f in findings}
    disabled = {k for k, v in (sc.get("settings") or {}).items() if v is False}
    auth = sc["auth"] != "none" and "routeExposureCompareLoggedIn" not in disabled
    expected = []
    for row in EXPECTED["v1_findings"]:
        if row["role"] not in sc["roles"]:
            continue
        if row.get("needs_auth") and not auth:
            continue
        expected.append(row)
    if not disabled and "roeExcludedHosts" not in (sc.get("settings") or {}) and summary.get("budget_cut", 0) == 0:
        for row in expected:
            key = (row["role"], row["path"], row["kind"])
            f = got.get(key)
            if f is None:
                failures.append(f"missing {key}")
                continue
            problems = _match(f, row)
            if problems:
                failures.append(f"{key}: " + "; ".join(problems))
        expected_keys = {(r["role"], r["path"], r["kind"]) for r in expected}
        for key in sorted(set(got) - expected_keys):
            failures.append(f"unexpected {key}")
        for row in EXPECTED["v1_absent"]:
            if row["role"] in sc["roles"] and any(k[0] == row["role"] and k[1] == row["path"] for k in got):
                failures.append(f"a finding exists on {row['role']} {row['path']}")
    if not auth:
        if any("authed_status" in f or "bodies_match" in f for f in findings):
            failures.append("a logged-in comparison happened without a profile")

    # Hit logs, inside the module's window.
    if summary.get("started_at"):
        lo, hi = _ts(summary["started_at"]) - 0.5, _ts(summary["finished_at"]) + 0.5
        rules = EXPECTED["hit_rules"]
        for role in sc["roles"]:
            window = [h for h in hits(role) if lo <= h["t"] <= hi]
            bad_methods = {h["method"] for h in window} - set(rules["only_methods"])
            if bad_methods:
                failures.append(f"{role}: methods {sorted(bad_methods)} in the module window")
            for path in rules["zero_paths"]:
                if any(h["path"] == path for h in window):
                    failures.append(f"{role}: {path} was requested")
            for path in rules["never_full_get"]:
                if any(h["path"] == path and h["method"] == "GET" and not h["range"] for h in window):
                    failures.append(f"{role}: a full GET of {path}")
            if not auth and any(h["auth"] or h["api_key"] or h["cookie"] for h in window):
                failures.append(f"{role}: a credential rode on a request with no profile")
            if any(h["cookie"] and not h["auth"] and sc["auth"] != "cookie" for h in window):
                failures.append(f"{role}: an anonymous request carried a cookie")
            if len(window) > 1:
                rate = (len(window) - 1) / max(0.001, window[-1]["t"] - window[0]["t"])
                report.append(f"- {role}: {len(window)} request(s) in the window, {rate:.1f} rps")
        excluded = [v for v in (sc.get("settings") or {}).get("roeExcludedHosts", [])]
        for role in sc["roles"]:
            if f"<{role}>" in excluded and [h for h in hits(role) if lo <= h["t"] <= hi]:
                failures.append(f"{role} is RoE-excluded and was requested")
        all_window = sorted(h["t"] for r in sc["roles"] for h in hits(r) if lo <= h["t"] <= hi)
        if len(all_window) > 1:
            total = (len(all_window) - 1) / max(0.001, all_window[-1] - all_window[0])
            ceiling = (sc.get("settings") or {}).get("roeGlobalMaxRps") or 5
            report.append(f"- measured rate across hosts: {total:.2f} rps (limit {ceiling})")
            if total > ceiling * rules["rate_slack"]:
                failures.append(f"rate {total:.2f} rps above {ceiling}")
    outsider = hits("outsider")
    if outsider:
        failures.append(f"the outsider received {len(outsider)} request(s) during the scan")

    report.append(f"- result: {'PASS' if not failures else 'FAIL'}")
    report.extend(f"  - {f}" for f in failures)
    print("\n".join(report))
    return 1 if failures else 0


def agent_leaks(path: str) -> int:
    text = Path(path).read_text(errors="replace")
    secrets_json = subprocess.run(["docker", "exec", CONTAINER.format("main"), "cat", "/tmp/lab-secrets.json"],
                                  capture_output=True, text=True).stdout
    values = json.loads(secrets_json or "{}")
    hits_found = [r for r in EXPECTED["agent_leak_rules"]["static"] if r in text]
    hits_found += [k for k in EXPECTED["agent_leak_rules"]["from_secrets"] if values.get(k) and values[k] in text]
    print("leak scan:", "clean" if not hits_found else "LEAK " + ", ".join(hits_found))
    return 1 if hits_found else 0


def main(argv: list) -> int:
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    if cmd == "setup":
        cmd_setup(argv[2], "--start" in argv)
    elif cmd == "start":
        cmd_start(argv[2])
    elif cmd == "verify":
        return verify(argv[2], argv[3])
    elif cmd == "reset-hits":
        reset_hits()
    elif cmd == "agent-leaks":
        return agent_leaks(argv[2])
    else:
        print(__doc__)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
