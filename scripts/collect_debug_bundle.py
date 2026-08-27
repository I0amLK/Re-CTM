#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from re_ctm.diagnostics import write_debug_bundle  # noqa: E402
from re_ctm.errors import ReCTMError  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create a redacted Re-CTM diagnostic bundle for post-push manual validation."
    )
    parser.add_argument("run_id")
    parser.add_argument("--data-root", default="~/.re-ctm")
    parser.add_argument("--output")
    args = parser.parse_args()
    output = Path(args.output or f"debug-bundle-{args.run_id}.json")
    try:
        target = write_debug_bundle(
            Path(args.data_root),
            args.run_id,
            output,
        )
    except ReCTMError as exc:
        print(json.dumps({"ok": False, "error": exc.to_payload()}, indent=2), file=sys.stderr)
        return 2
    print(json.dumps({"ok": True, "output": str(target)}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
