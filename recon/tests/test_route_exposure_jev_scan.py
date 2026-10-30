"""The three Jev hooks inside a real route exposure run (shadow).

The hook modules are unit-tested on their own; this drives the scanner end to end
against a loopback app, with Jev answering through a mocked agent, and locks in:
- with AI in Pipeline and the three flags on, each hook leaves its record under
  jev_shadow.<hook> in the run's output, with no fallback;
- SHADOW changes nothing: the findings equal those of a run with the hooks off;
- a hook that raises is reported in one log line and the scan completes unchanged.
"""
from __future__ import annotations

import contextlib
import io
import json
from unittest import mock

import pytest

from recon.helpers import circuit_breaker as cb
from recon.helpers.ai_planner import jev_shadow
from recon.route_exposure import prober, run_route_exposure_isolated
from recon.tests.route_exposure_fakeapp import FakeApp, corpus, html_answer, json_answer, settings

USERS = json.dumps([{"id": i, "email": f"user{i}@lab.invalid"} for i in range(20)]).encode()
ROUTES = {
    "/": html_answer(200, b"<html><title>Lab</title><body>" + b"welcome " * 30 + b"</body></html>"),
    "/internal/users/export": json_answer(200, USERS),
    "/admin/overview": html_answer(200, b"<html><title>Overview</title><body>" + b"stats " * 40
                                        + b"</body></html>"),
    "/.env": (200, {"Content-Type": "text/plain"}, b"DB_PASSWORD=LAB-NOT-A-SECRET-1\nAPP_ENV=lab\n"),
}
ENDPOINTS = {
    "/internal/users/export": {"methods": ["GET"], "category": "file_access", "sources": ["katana"]},
    "/admin/overview": {"methods": ["GET"], "category": "admin", "sources": ["katana"]},
}
HOOKS_ON = {"AI_IN_PIPELINE": True, "ROUTE_EXPOSURE_JEV_RANK": True,
            "ROUTE_EXPOSURE_JEV_WALL_CHECK": True, "ROUTE_EXPOSURE_JEV_ASSESS": True}


@pytest.fixture(autouse=True)
def _fresh():
    cb.reset_registry()
    prober._reset_pacer()
    yield
    prober._reset_pacer()
    cb.reset_registry()


def _jev_answers(url, json=None, headers=None, timeout=None):
    r = mock.MagicMock(status_code=200, text="")
    if url.endswith("/jev/route-privacy-rank"):
        body = {"scores": [0.8] * len(json["routes"]), "model": "jev-1.13.0"}
    elif url.endswith("/jev/page-type"):
        body = {"labels": [{"page_class": "app", "confidence": 80} for _ in json["pages"]],
                "model": "jev-1.13.0"}
    elif url.endswith("/jev/route-exposure-assess"):
        body = {"labels": [{"kind": "data_export", "kind_confidence": 90, "sensitivity": 85}
                           for _ in json["candidates"]], "model": "jev-1.13.0"}
    else:
        raise AssertionError(f"unexpected agent call {url}")
    r.json.return_value = body
    return r


def _run(**extra):
    with FakeApp(ROUTES) as app:
        combined = corpus(app.base, endpoints=ENDPOINTS, js=[])
        out = run_route_exposure_isolated(combined, settings(ROUTE_EXPOSURE_VCS_FILES=True, **extra))
    prober._reset_pacer()
    return out


def _shape(findings):
    keys = ("path", "exposure_kind", "route_class", "needs_agent_confirmation", "severity",
            "auth_expected_by", "generated_by", "leak_signals")
    return sorted(json.dumps({k: f.get(k) for k in keys}, sort_keys=True) for f in findings)


def test_the_hooks_record_their_shadow_and_change_no_finding():
    off = _run()
    with mock.patch.object(jev_shadow.requests, "post", side_effect=_jev_answers) as post:
        on = _run(**HOOKS_ON)
    called = {c.args[0].rsplit("/", 1)[-1] for c in post.call_args_list}
    assert called == {"route-privacy-rank", "page-type", "route-exposure-assess"}
    assert "jev_shadow" not in off
    shadow = on["jev_shadow"]
    for hook in ("route_privacy_rank", "route_exposure_wall", "route_exposure_assess"):
        assert shadow[hook]["rollout"] == "shadow", hook
        assert shadow[hook]["summary"]["fallbacks"] == 0, hook
        assert shadow[hook]["summary"]["decisions"] > 0, hook
    assert _shape(on["route_exposure"]["findings"]) == _shape(off["route_exposure"]["findings"])
    assert on["route_exposure"]["findings"]


@pytest.mark.parametrize("target,line", [
    ("recon.helpers.ai_planner.route_privacy_rank.run_for_routes", "Jev ranking skipped"),
    ("recon.helpers.ai_planner.route_wall_check.run_for_pages", "Jev wall check skipped"),
    ("recon.helpers.ai_planner.route_exposure_assess.run_for_candidates", "Jev assessment skipped"),
])
def test_a_hook_that_raises_is_logged_and_the_scan_completes(target, line):
    off = _run()
    out = io.StringIO()
    with mock.patch(target, side_effect=RuntimeError("boom")), \
            mock.patch.object(jev_shadow.requests, "post", side_effect=_jev_answers), \
            contextlib.redirect_stdout(out):
        on = _run(**HOOKS_ON)
    assert f"[!][RouteExposure] {line} (RuntimeError)" in out.getvalue()
    assert _shape(on["route_exposure"]["findings"]) == _shape(off["route_exposure"]["findings"])
