"""
core/monitor.py — Module 4: Continuous Monitoring with APScheduler.
Includes change detection between consecutive scans.
"""

import json
import threading
from datetime import datetime
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.interval import IntervalTrigger


_scheduler: BackgroundScheduler | None = None
_scheduler_lock = threading.Lock()

# Preset intervals (minutes)
SCHEDULE_PRESETS = {
    "daily":   1440,
    "weekly":  10080,
    "monthly": 43200,
    "hourly":  60,
}


def get_scheduler() -> BackgroundScheduler:
    global _scheduler
    with _scheduler_lock:
        if _scheduler is None:
            _scheduler = BackgroundScheduler(
                job_defaults={"coalesce": True, "max_instances": 1},
                timezone="UTC",
            )
            _scheduler.start()
    return _scheduler


def add_monitor_job(schedule_id: int, app, run_scan_fn, push_event_fn):
    """Add a scheduled scan job for the given schedule."""
    scheduler = get_scheduler()
    job_id = f"monitor_{schedule_id}"

    try:
        scheduler.remove_job(job_id)
    except Exception:
        pass

    def job():
        with app.app_context():
            from db.manager import get_active_schedules, update_schedule_run, create_scan
            schedules = get_active_schedules()
            target_schedule = next((s for s in schedules if s.id == schedule_id), None)
            if not target_schedule or not target_schedule.active:
                return
            scan = create_scan(target_schedule.target_url, target_schedule.scan_type)
            update_schedule_run(schedule_id)
            t = threading.Thread(
                target=run_scan_fn,
                args=(app, scan.id, target_schedule.target_url, target_schedule.scan_type),
                daemon=True,
            )
            t.start()

    with app.app_context():
        from db.manager import get_active_schedules
        schedules = get_active_schedules()
        target = next((s for s in schedules if s.id == schedule_id), None)
        if not target:
            return
        interval_minutes = target.interval_minutes

    scheduler.add_job(
        job,
        trigger=IntervalTrigger(minutes=interval_minutes),
        id=job_id,
        replace_existing=True,
    )


def remove_monitor_job(schedule_id: int):
    """Remove a scheduled scan job."""
    scheduler = get_scheduler()
    job_id = f"monitor_{schedule_id}"
    try:
        scheduler.remove_job(job_id)
    except Exception:
        pass


def restore_schedules(app, run_scan_fn, push_event_fn):
    """On app startup, restore all active schedules from the database."""
    with app.app_context():
        from db.manager import get_active_schedules
        schedules = get_active_schedules()
        for schedule in schedules:
            add_monitor_job(schedule.id, app, run_scan_fn, push_event_fn)


def detect_endpoint_changes(
    current_endpoints: list[dict],
    previous_endpoints: list[dict],
) -> dict:
    """
    Detect changes between two sets of discovered endpoints.

    Returns:
        {
          "new_endpoints": [str],          # Paths added since last scan
          "removed_endpoints": [str],      # Paths no longer present
          "auth_changes": [dict],          # Paths where auth type changed
          "version_changed": bool,         # Whether API version appears different
        }
    """
    curr_map = {ep.get("path", ""): ep for ep in current_endpoints}
    prev_map = {ep.get("path", ""): ep for ep in previous_endpoints}

    curr_paths = set(curr_map.keys())
    prev_paths = set(prev_map.keys())

    new_eps     = sorted(curr_paths - prev_paths)
    removed_eps = sorted(prev_paths - curr_paths)

    auth_changes = []
    for path in curr_paths & prev_paths:
        curr_auth = curr_map[path].get("auth_type")
        prev_auth = prev_map[path].get("auth_type")
        if curr_auth != prev_auth:
            auth_changes.append({
                "path": path,
                "was": prev_auth or "None",
                "now": curr_auth or "None",
                "change_type": "Auth Type Changed",
            })

    return {
        "new_endpoints":    new_eps,
        "removed_endpoints": removed_eps,
        "auth_changes":     auth_changes,
        "version_changed":  False,
    }


def run_change_detection(app, current_session_id: int, target_url: str):
    """
    After a scan completes, compare with the most recent previous scan for the same URL.
    Saves a ScanComparison record if a previous scan exists.
    """
    with app.app_context():
        from db.manager import (
            get_scans_for_url, get_endpoints, get_findings,
            get_risk_analysis, save_scan_comparison,
        )

        # Find the previous completed scan for this URL
        all_scans = get_scans_for_url(target_url)
        prev_scan = next(
            (s for s in all_scans if s.id != current_session_id and s.status == "COMPLETED"),
            None,
        )
        if not prev_scan:
            return  # No previous scan to compare against

        curr_eps    = [ep.to_dict() for ep in get_endpoints(current_session_id)]
        prev_eps    = [ep.to_dict() for ep in get_endpoints(prev_scan.id)]
        curr_vulns  = [f.to_dict() for f in get_findings(current_session_id)]
        prev_vulns  = [f.to_dict() for f in get_findings(prev_scan.id)]

        curr_risk   = get_risk_analysis(current_session_id)
        prev_risk   = get_risk_analysis(prev_scan.id)

        curr_risk_d = curr_risk.to_dict() if curr_risk else {"overall_score": 0}
        prev_risk_d = prev_risk.to_dict() if prev_risk else {"overall_score": 0}

        ep_changes = detect_endpoint_changes(curr_eps, prev_eps)

        curr_types = {f.get("vuln_type", "") for f in curr_vulns}
        prev_types = {f.get("vuln_type", "") for f in prev_vulns}

        new_vuln_count  = len(curr_types - prev_types)
        res_vuln_count  = len(prev_types - curr_types)
        risk_delta      = round(
            curr_risk_d.get("overall_score", 0) - prev_risk_d.get("overall_score", 0), 1
        )

        save_scan_comparison(current_session_id, {
            "previous_session_id": prev_scan.id,
            "new_endpoints":       ep_changes["new_endpoints"],
            "removed_endpoints":   ep_changes["removed_endpoints"],
            "auth_changes":        ep_changes["auth_changes"],
            "new_vulns":           new_vuln_count,
            "resolved_vulns":      res_vuln_count,
            "risk_delta":          risk_delta,
            "version_changed":     ep_changes["version_changed"],
        })


def shutdown_scheduler():
    global _scheduler
    with _scheduler_lock:
        if _scheduler and _scheduler.running:
            _scheduler.shutdown(wait=False)
            _scheduler = None
