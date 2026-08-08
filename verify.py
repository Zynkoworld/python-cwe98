#!/usr/bin/env python3
"""verify.py — exit 0 iff the vendored ratified decider reproduces the external GT on the probes:
recall 1.0 on FLAG + FP0 on the negatives (SAFE/SUPPRESS) + non-degenerate (both classes present).
Spurious lines (the corpus's own-error convention) are excluded from BOTH sides. Byte-locks the set."""
import json
import os
import sys
import hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "oracle"))
from decide import decide

HERE = os.path.dirname(__file__)
rows = [json.loads(l) for l in open(os.path.join(HERE, "probes", "probes.jsonl")) if l.strip()]
live = [r for r in rows if not r.get("spurious")]
flags = [r for r in live if r["label"] == "FLAG"]
negs = [r for r in live if r["label"] != "FLAG"]

recovered = sum(1 for r in flags if decide(r["code"], r["line"]) == "FLAG")
false_pos = [r["id"] for r in negs if decide(r["code"], r["line"]) == "FLAG"]
recall = recovered / len(flags) if flags else 0.0
non_degenerate = bool(flags) and bool(negs)

set_hash = hashlib.sha256(
    json.dumps([{"id": r["id"], "label": r["label"], "line": r["line"], "code": r["code"]}
                for r in rows], sort_keys=True).encode()).hexdigest()[:12]

print("probes=%d (FLAG=%d, negatives=%d) | recall=%.3f | false_positives=%d | non_degenerate=%s | set=%s"
      % (len(live), len(flags), len(negs), recall, len(false_pos), non_degenerate, set_hash))
ok = recall == 1.0 and not false_pos and non_degenerate
print("RESULT: %s" % ("PROVEN (recall=1.0, FP0, non-degenerate)" if ok
                      else "NOT PROVEN: " + ("degenerate (no negative)" if not non_degenerate
                           else "false_positives=%s" % false_pos if false_pos else "recall<1.0")))
sys.exit(0 if ok else 1)
