"""Benchmark completed Argus scans against explicit public repositories."""

from __future__ import annotations

import argparse
import json
import time

import httpx


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("repositories", nargs="+", help="Public GitHub repository URLs to scan")
    parser.add_argument("--base-url", default="http://localhost:8000")
    parser.add_argument("--poll-interval", type=float, default=0.25)
    args = parser.parse_args()

    records = []
    with httpx.Client(base_url=args.base_url, timeout=30) as client:
        for repository_url in args.repositories:
            started = time.perf_counter()
            response = client.post("/api/v1/scans", json={"repository_url": repository_url})
            response.raise_for_status()
            scan_id = response.json()["scan_id"]
            while True:
                result = client.get(f"/api/v1/scans/{scan_id}")
                result.raise_for_status()
                scan = result.json()
                if scan["status"] in {"complete", "failed"}:
                    records.append({
                        "repository_url": repository_url,
                        "status": scan["status"],
                        "elapsed_seconds": round(time.perf_counter() - started, 3),
                        "dependencies": len(scan["dependencies"]),
                        "vulnerabilities": sum(len(item["vulnerabilities"]) for item in scan["dependencies"]),
                        "risk_score": scan["risk_score"],
                        "error": scan["error"],
                    })
                    break
                time.sleep(args.poll_interval)
    print(json.dumps({"repositories": records}, indent=2))


if __name__ == "__main__":
    main()
