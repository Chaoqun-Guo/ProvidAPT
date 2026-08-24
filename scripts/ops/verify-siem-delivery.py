#!/usr/bin/env python3
"""Queue a ProvidAPT SIEM test event and verify control-plane delivery state."""

from __future__ import annotations

import argparse
import json
import sys
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


def request_json(
    method: str,
    server: str,
    path: str,
    payload: dict[str, Any] | None = None,
) -> dict[str, Any]:
    url = urljoin(server.rstrip("/") + "/", path.lstrip("/"))
    body = None
    headers = {"Accept": "application/json"}
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = Request(url, data=body, headers=headers, method=method)
    with urlopen(req, timeout=15) as response:
        data = response.read()
    if not data:
        return {}
    return json.loads(data.decode("utf-8"))


def siem_status(document: dict[str, Any]) -> dict[str, Any]:
    if isinstance(document.get("siem"), dict):
        return document["siem"]
    status = document.get("status")
    if isinstance(status, dict) and isinstance(status.get("siem"), dict):
        return status["siem"]
    return {}


def status_satisfies(status: dict[str, Any], require_forwarded: bool) -> bool:
    last_status = str(status.get("last_status") or "").lower()
    forwarded_events = int(status.get("forwarded_events") or 0)
    if require_forwarded:
        return last_status == "forwarded" or forwarded_events > 0
    return last_status in {"queued", "queued_disabled", "forwarded"} or forwarded_events > 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--server", required=True, help="Control-plane URL, for example http://localhost:18080")
    parser.add_argument("--note", default="ops-siem-verify", help="Operator note attached to the test event")
    parser.add_argument("--wait-seconds", type=float, default=45.0, help="Maximum time to poll compliance status")
    parser.add_argument("--poll-interval", type=float, default=3.0, help="Seconds between status polls")
    parser.add_argument("--require-forwarded", action="store_true", help="Require successful forwarding instead of queued evidence")
    args = parser.parse_args()

    deadline = time.time() + args.wait_seconds
    try:
        result = request_json(
            "POST",
            args.server,
            "/api/v1/control/compliance",
            {"action": "test_siem", "note": args.note, "actor": "ops-siem-verify"},
        )
        latest = siem_status(result)
        while time.time() <= deadline:
            if status_satisfies(latest, args.require_forwarded):
                print(json.dumps({"ok": True, "action_result": result, "siem": latest}, indent=2, sort_keys=True))
                return 0
            status = request_json("GET", args.server, "/api/v1/control/compliance")
            latest = siem_status(status)
            time.sleep(args.poll_interval)
        print(
            json.dumps(
                {"ok": False, "reason": "SIEM delivery state did not reach expected status", "siem": latest},
                indent=2,
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
