#!/usr/bin/env python3
from __future__ import annotations

import json
import statistics
import time

from re_ctm.debug import DebugEvent
from re_ctm.terminal_ui import TerminalSession


ITERATIONS = 20_000
P95_LIMIT_NS = 20_000


def main() -> int:
    session = TerminalSession(queue_size=ITERATIONS + 1)
    # Producer-only benchmark: activate the observer without a renderer so the
    # measurement covers filtering + Queue.put_nowait and no terminal I/O.
    session._started.set()
    sample = DebugEvent(
        timestamp="2026-08-31T22:55:00.000Z",
        trace_id="tr_benchmark_123456",
        event_type="tool.call_started",
        component="benchmark",
        details={"tool": "rethlas_step"},
    )
    durations: list[int] = []
    for _ in range(ITERATIONS):
        started = time.perf_counter_ns()
        session.observe(sample)
        durations.append(time.perf_counter_ns() - started)
    ordered = sorted(durations)
    p95 = ordered[int(len(ordered) * 0.95) - 1]
    payload = {
        "ok": p95 < P95_LIMIT_NS,
        "iterations": ITERATIONS,
        "producer_ns": {
            "median": int(statistics.median(durations)),
            "p95": p95,
            "max": max(durations),
            "acceptance_p95_lt": P95_LIMIT_NS,
        },
        "queue_dropped": session._dropped,
    }
    print(json.dumps(payload, indent=2))
    return 0 if payload["ok"] and payload["queue_dropped"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
