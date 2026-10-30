"""
Disguised login wall and error page check on TypeSafe Jev (route exposure, hook B)
================================================================================
The route exposure scan drops an anonymous 2xx that is really a login form, an
error page or a placeholder, using page_type's deterministic prefilter. A page the
prefilter cannot place stays a lead. This hook asks Jev, for those HTML leads only,
which page class each is, reusing page_type's request item and its existing
`page-type` route.

Its own HOOK (`route_exposure_wall`, not `page_type`): ShadowRecorder writes
`jev_shadow[HOOK]`, and the page-type hook of the same run must keep its records.

Shipped in SHADOW: nothing is annotated or re-ordered; each answer is recorded
next to the prefilter's label ("app" when it placed nothing) in
`jev_shadow.route_exposure_wall`. Under ACT (later) a login_only or error answer
at confidence >= 70 would put the lead last; it never drops one.

The body reaches Jev masked (signals.mask_text, applied when the entry is built)
and capped. Log lines carry counts and indexes only.
"""

import os
import time
from typing import List, Optional

from recon.helpers.ai_planner import page_type
from recon.helpers.ai_planner.jev_shadow import SHADOW, ShadowRecorder, jev_model, jev_post

ROLLOUT = SHADOW

HOOK = "route_exposure_wall"
_TAG = "RouteWall-Jev"

MAX_PAGES_PER_SCAN = 100
BATCH_SIZE = 4
TIME_BUDGET_S = 60
TIMEOUT = 30


def jev_wall_check_enabled(settings: dict) -> bool:
    """Kind B gating: nothing upstream folds this flag into AI_IN_PIPELINE."""
    return bool(settings.get("AI_IN_PIPELINE") and settings.get("ROUTE_EXPOSURE_JEV_WALL_CHECK"))


def run_for_pages(entries: List[dict], settings: dict, recon_data: Optional[dict],
                  clock=time.monotonic) -> dict:
    """Ask Jev the page class of each lead's page entry (httpx-shaped, body masked).
    Never raises; returns count stats. Under SHADOW nothing changes."""
    stats = {"pages": 0, "asked": 0, "failed_batches": 0}
    if not entries or not jev_wall_check_enabled(settings):
        return stats
    recorder = ShadowRecorder(HOOK, rollout=ROLLOUT)
    try:
        groups: dict = {}
        for i, entry in enumerate(entries):
            if isinstance(entry, dict) and page_type._classifiable(entry):
                groups.setdefault(page_type.cache_key(entry), []).append(i)
        stats["pages"] = sum(len(v) for v in groups.values())
        keys = list(groups)[:MAX_PAGES_PER_SCAN]
        print(f"[*][{_TAG}] {stats['pages']} lead pages, {len(keys)} distinct to ask")
        started = clock()
        for start in range(0, len(keys), BATCH_SIZE):
            if clock() - started > TIME_BUDGET_S:
                print(f"[!][{_TAG}] Time budget of {TIME_BUDGET_S}s reached - "
                      f"{len(keys) - start} pages left unasked")
                break
            batch = keys[start:start + BATCH_SIZE]
            pages = [page_type._page(entries[groups[k][0]]) for k in batch]
            data = jev_post("page-type", {"pages": pages, "user_id": os.environ.get("USER_ID", ""),
                                          "project_id": os.environ.get("PROJECT_ID", "")},
                            _TAG, TIMEOUT)
            labels = page_type._validate(data, len(batch)) if data is not None else None
            if labels is None:
                if data is not None:
                    print(f"[!][{_TAG}] Agent answer failed validation - using the fallback.")
                stats["failed_batches"] += 1
                recorder.fallback()
                continue
            recorder.model = jev_model(data)
            stats["asked"] += len(batch)
            for k, (cls, conf) in zip(batch, labels):
                for i in groups[k]:
                    baseline = page_type.prefilter(entries[i]) or "app"
                    recorder.decision(f"page_{i}", cls, conf, baseline, url=entries[i].get("url"))
        print(f"[+][{_TAG}] {stats['asked']} pages asked, {stats['failed_batches']} batches fell back")
    except Exception as e:  # noqa: BLE001 - a second opinion is never worth breaking the scan
        print(f"[!][{_TAG}] Pass failed ({type(e).__name__}) - the leads stand as found.")
        recorder.fallback()
    finally:
        recorder.finish(recon_data)
    return stats
