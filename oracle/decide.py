"""standalone decider — concorde's RATIFIED detection engine, vendored verbatim.
decide(code, line) -> "FLAG" | "SAFE". The engine (oracle/engine/) is stdlib/ast only; the spec is
concorde's authoritative sink/sanitizer catalogue for this CWE. No re-implementation: this IS the
detector that was ratified recall 1.0 / FP0 against the external semgrep-taint GT."""
import os
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "engine"))
import injection_sinks_i1
import pathtrav_sinks_i1
import open_redirect_i1
import ssrf_sinks_i1
import hardcoded_credential_i1
import taint_sink_interp_i1

CWE = "CWE-98"
_SPEC = injection_sinks_i1.spec("CWE-98")
_PERCALL = taint_sink_interp_i1.per_call


def decide(code, line):
    """FLAG iff the ratified detector reports a FLAG verdict at the sink on `line`."""
    verdicts = dict(_PERCALL(_SPEC, code))
    return "FLAG" if verdicts.get(line) == "FLAG" else "SAFE"
