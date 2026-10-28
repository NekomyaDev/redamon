"""Route exposure scan: request what recon found, plus what it generates, anonymously.

GROUP 6 Phase A (concurrent with nuclei, cache poisoning, GraphQL). For every
route it sends one anonymous GET (HEAD and a 1 KB Range read for backups), one
control request on a 2xx, and one logged-in GET where the project's AuthProfile
covers the host, then writes two kinds of :Vulnerability: candidates for the
agent to confirm (needs_agent_confirmation) and findings a signature proves.
GET and HEAD only; a state-changing path is never requested; PII is stored as
types and one count, never a value.

Logs are counts only: the orchestrator reads the drawer's phase out of stdout,
and a URL, host or exception text could move it.
"""

from __future__ import annotations

import copy
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.parse import urlsplit

from recon.helpers.isolated_result import TopLevelKeys
from recon.route_exposure import generators, harvest, normalizers, prober, ranking, verdict

SOURCE = "route_exposure"
ROUTE_EXPOSURE_JEV_HOOKS = ("route_privacy_rank", "route_exposure_wall", "route_exposure_assess")

#: Registry bounds (recon_settings/registry.yaml) and defaults. fetch_project_settings
#: does not clamp, so a stale or hand-edited row is clamped here.
BOUNDS = {
    "ROUTE_EXPOSURE_MAX_RPS": (1, 50, 5),
    "ROUTE_EXPOSURE_WORKERS": (1, 16, 4),
    "ROUTE_EXPOSURE_TIMEOUT": (2, 60, 10),
    "ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST": (10, 5000, 300),
    "ROUTE_EXPOSURE_MAX_ROUTES_TOTAL": (50, 50000, 3000),
}
#: Generator and analysis switches, all on by default.
SWITCHES = {
    "seed_paths": "ROUTE_EXPOSURE_SEED_PATHS",
    "vcs_files": "ROUTE_EXPOSURE_VCS_FILES",
    "backup_files": "ROUTE_EXPOSURE_BACKUP_FILES",
    "version_variants": "ROUTE_EXPOSURE_VERSION_VARIANTS",
    "compare_logged_in": "ROUTE_EXPOSURE_COMPARE_LOGGED_IN",
    "pii_detection": "ROUTE_EXPOSURE_PII_DETECTION",
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def _clamp(value, low, high, default):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if number != number:  # NaN
        return default
    return max(low, min(high, number))


def config(settings: dict) -> dict:
    """The run's knobs, every numeric clamped to its registry bounds."""
    cfg = {name: bool(settings.get(key, True)) for name, key in SWITCHES.items()}
    rps = _clamp(settings.get("ROUTE_EXPOSURE_MAX_RPS"), *BOUNDS["ROUTE_EXPOSURE_MAX_RPS"])
    ceiling = settings.get("ROE_GLOBAL_MAX_RPS") if settings.get("ROE_ENABLED") else 0
    if isinstance(ceiling, (int, float)) and not isinstance(ceiling, bool) and ceiling > 0:
        # The bounds' floor of 1 rps must never lift a slower engagement ceiling.
        rps = min(rps, float(ceiling))
    cfg["rps"] = rps
    cfg["workers"] = int(_clamp(settings.get("ROUTE_EXPOSURE_WORKERS"), *BOUNDS["ROUTE_EXPOSURE_WORKERS"]))
    cfg["timeout"] = _clamp(settings.get("ROUTE_EXPOSURE_TIMEOUT"), *BOUNDS["ROUTE_EXPOSURE_TIMEOUT"])
    cfg["per_host"] = int(_clamp(settings.get("ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST"),
                                 *BOUNDS["ROUTE_EXPOSURE_MAX_ROUTES_PER_HOST"]))
    cfg["total"] = int(_clamp(settings.get("ROUTE_EXPOSURE_MAX_ROUTES_TOTAL"),
                              *BOUNDS["ROUTE_EXPOSURE_MAX_ROUTES_TOTAL"]))
    return cfg


def _roe_excluded(settings: dict) -> list:
    if not settings.get("ROE_ENABLED"):
        return []
    return [h for h in settings.get("ROE_EXCLUDED_HOSTS") or [] if isinstance(h, str) and h.strip()]


def build_guard(combined_result: dict, settings: dict):
    """One guard per run, for every request and every control (plan T39).

    The run's own hosts (operator targets, the target list, the hosts
    http_probe reached) follow the pipeline's address rule: private addresses
    are scanned, metadata and never-scannable ones are not. A host seen only in
    a bundle must first be in the probe scope (a strict subdomain of a root in
    a full-discovery run), then pass the attacker-influenced URL rule, which
    refuses every private address. Answers are cached per host.
    """
    from recon.helpers.openapi.discovery import operator_targets
    from recon.helpers.roe_scope import _is_roe_excluded
    from recon.main_recon_modules.ip_filter import is_address_safe_to_scan, is_url_safe_to_probe
    from recon.main_recon_modules.js_recon import _endpoint_probe_scope, _host_of, _in_probe_scope

    by_url = (combined_result.get("http_probe") or {}).get("by_url") or {}
    reached = [{"url": str(e.get("url") or u)} for u, e in by_url.items() if isinstance(e, dict)]
    scope = _endpoint_probe_scope(combined_result, reached, settings)
    op_hosts, op_nets = operator_targets(settings)
    excluded = _roe_excluded(settings)
    cache: dict = {}
    lock = threading.Lock()

    def guard(url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        if parts.scheme not in ("http", "https") or not parts.hostname:
            return False
        if not _in_probe_scope(url, scope):
            return False
        host = _host_of(url)
        if excluded and _is_roe_excluded(host, excluded):
            return False
        with lock:
            if host in cache:
                return cache[host]
        if host in scope.hosts:
            allowed = is_address_safe_to_scan(host, op_hosts, op_nets)
        else:
            allowed = is_url_safe_to_probe(url)
        with lock:
            cache[host] = allowed
        return allowed

    return guard


def _window_open(settings: dict) -> bool:
    try:
        from recon.helpers import roe_scope
        allowed, _ = roe_scope._check_roe_time_window(settings)
        return bool(allowed)
    except Exception:  # noqa: BLE001 - a window that cannot be checked is closed
        return False


def _note_degraded(reason: str) -> None:
    try:
        from recon.helpers import circuit_breaker
        circuit_breaker.note_degraded(SOURCE, sources=(SOURCE,), reason=reason)
    except Exception:  # noqa: BLE001
        pass


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _observe_all(routes: list, probe: prober.Prober, cfg: dict) -> list:
    def one(route):
        try:
            return verdict.observe(route, probe, cfg)
        except Exception:  # noqa: BLE001 - one route's fault costs that route
            return verdict.Observation(route=route)

    if cfg["workers"] <= 1 or len(routes) <= 1:
        return [one(r) for r in routes]
    with ThreadPoolExecutor(max_workers=cfg["workers"], thread_name_prefix="route-exposure") as pool:
        return list(pool.map(one, routes))


def _run(combined_result: dict, settings: dict, started: str) -> dict:
    from recon.helpers import circuit_breaker as cb

    cfg = config(settings)
    scope = cb.scope((), label="RouteExposure", unit="host(s)")
    corpus = harvest.harvest(combined_result)
    harvested = len(corpus.routes)
    generated = generators.generate(corpus, cfg)
    guard = build_guard(combined_result, settings)
    routes = [r for r in corpus.routes.values() if guard(r.url)]
    out_of_scope = len(corpus.routes) - len(routes)
    selected, cut = ranking.select(routes, per_host=cfg["per_host"], total=cfg["total"])
    hosts = len({_host(r.baseurl) for r in routes})
    print(f"[*][RouteExposure] {len(routes)} route(s) on {hosts} host(s): {len(selected)} requested, "
          f"{cut} cut by the budget")
    probe = prober.Prober(settings, guard=guard, timeout=cfg["timeout"], rps=cfg["rps"],
                          breaker_scope=scope, roe_excluded=_roe_excluded(settings))
    observations = _observe_all(selected, probe, cfg)
    assessed = verdict.assess(observations, cfg)
    findings = assessed["findings"]

    dropped = dict(assessed["dropped"], unsafe=corpus.unsafe)
    summary = {
        "routes_harvested": harvested, "routes_generated": len(generated),
        "routes_requested": len(selected), "budget_cut": cut, "hosts": hosts,
        "out_of_scope": out_of_scope, "dropped": dropped,
        "logged_in_compared": assessed["logged_in_compared"], "requests_sent": probe.sent,
        "started_at": started, "finished_at": _now(),
    }
    result = normalizers.build_result(findings, endpoint_status=assessed["endpoint_status"],
                                      new_endpoints=assessed["new_endpoints"], summary=summary)
    scope.finish("route_exposure", host_source=SOURCE, payload=result, log=False)
    skipped = len(scope.hosts())
    result["summary"]["hosts_skipped"] = skipped
    # The breaker's own host list stays in the recon JSON, never in stdout.
    print(f"[*][RouteExposure] {probe.sent} request(s) sent ({probe.control_requests} control, "
          f"{probe.sent_with_auth} logged in)")
    if skipped:
        print(f"[!][RouteExposure] {skipped} host(s) skipped as unreachable")
    s = result["summary"]
    if findings:
        print(f"[+][RouteExposure] {s['candidates']} lead(s) for the agent, "
              f"{s['findings']} signature finding(s)")
    else:
        print("[-][RouteExposure] no exposed route found")
    return result


def run_route_exposure(combined_result: dict, settings: dict) -> dict:
    """Mutate combined_result["route_exposure"] in place and return combined_result.

    Shared entry of the full pipeline AND partial recon. Never raises.
    """
    settings = settings or {}
    if not settings.get("ROUTE_EXPOSURE_ENABLED", False):
        print("[-][RouteExposure] disabled")
        return combined_result
    started = _now()
    if not _window_open(settings):
        # Fail closed, and keep last run's findings: nothing was re-checked.
        _note_degraded("RoE time window")
        print("[!][RouteExposure] outside the RoE time window: nothing requested")
        combined_result["route_exposure"] = normalizers.build_result(
            [], summary={"started_at": started, "finished_at": _now()})
        return combined_result
    try:
        combined_result["route_exposure"] = _run(combined_result, settings, started)
    except Exception as e:  # noqa: BLE001
        # Empty and marked degraded: the prune must keep last run's findings
        # instead of deleting them as "gone". Type only: a message can quote a URL.
        _note_degraded("the route exposure scan failed")
        print(f"[!][RouteExposure] Error ({type(e).__name__}) - no results this run")
        combined_result["route_exposure"] = normalizers.build_result(
            [], summary={"started_at": started, "finished_at": _now()}, error=type(e).__name__)
    return combined_result


def run_route_exposure_isolated(combined_result: dict, settings: dict) -> TopLevelKeys:
    """Thread-safe: deep-copies first, returns this tool's payload plus its own Jev
    shadow records (merged per hook by _merge_isolated_result)."""
    snapshot = copy.deepcopy(combined_result)
    run_route_exposure(snapshot, settings)
    out = TopLevelKeys(route_exposure=snapshot.get("route_exposure", {}))
    shadow = {h: rec for h, rec in (snapshot.get("jev_shadow") or {}).items()
              if h in ROUTE_EXPOSURE_JEV_HOOKS}
    if shadow:
        out["jev_shadow"] = shadow
    return out
