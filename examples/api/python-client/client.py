#!/usr/bin/env python3
import json
import os
import urllib.request


BASE_URL = os.environ.get("PROVIDAPT_URL", "http://localhost:18080").rstrip("/")
TOKEN = os.environ.get("PROVIDAPT_TOKEN", "")


def get(path: str) -> dict:
    request = urllib.request.Request(f"{BASE_URL}{path}")
    if TOKEN:
        request.add_header("X-API-Key", TOKEN)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def main() -> None:
    for path in (
        "/api/v1/status",
        "/api/v1/control/fleet",
        "/api/v1/alerts",
    ):
        print(f"== {path} ==")
        print(json.dumps(get(path), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
