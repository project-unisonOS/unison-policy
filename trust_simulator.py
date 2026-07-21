#!/usr/bin/env python3
"""Explain a synthetic Trust API decision without reading personal data."""
from __future__ import annotations

import argparse
import json
import sys

from src.trust_service import TrustEvaluator, TrustRepository


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("request", help="path to a synthetic JSON trust request, or - for stdin")
    args = parser.parse_args()
    try:
        raw = json.load(sys.stdin if args.request == "-" else open(args.request, encoding="utf-8"))
        decision = TrustEvaluator(TrustRepository()).evaluate(raw)
        print(json.dumps(decision.to_dict(), indent=2, sort_keys=True))
        return 0 if decision.outcome.value != "deny" else 2
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"outcome": "deny", "reason_code": "invalid-simulator-input", "explanation": str(exc)}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
