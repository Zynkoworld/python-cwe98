"""py_taint_verdict_i1 — concorde I1 of the Python taint verdict-lock (CWE-78 / CWE-22 / CWE-79).

The missing third leg of the Python taint byte-lock: an INDEPENDENT AST taint analyzer (concorde's
own — zynko's ast_taint_multi_py and zafire's flow_taint are NOT imported) that derives a FLAG/
SUPPRESS verdict per case on the shared canonical-adversarial fixture, using the source/sink/
sanitizer sets from the common curated catalog. If I1 byte-matches the I2==I3 consensus, the Python
lock ratifies to I1==I2==I3 ([[three-impl-independence-discipline]], [[curated-knowledge-front]]).

Contract: docs/curated/security/taint_sink_catalog_multilang.json (python section).
Fixture (shared oracle): sdl/cwe{78,22,79}_canonical_adversarial.jsonl (python cells).

Verdict semantics (sound taint reachability):
  FLAG      a tainted source reaches a CWE sink argument WITHOUT passing through a CWE-neutralizing
            sanitizer — and, for the shell family (CWE-78), only in shell mode (os.system/os.popen,
            or subprocess.* with shell=True; a list argv is not a shell string -> SUPPRESS).
  SUPPRESS  otherwise (no taint, or every tainted occurrence is wrapped in a sanitizer, or the sink
            is used safely).
"""
from __future__ import annotations

import ast

# ── source/sink/sanitizer sets (derived from the shared catalog's python section) ───────────────
_SOURCES = (
    "request.args", "request.form", "request.values", "request.headers", "request.cookies",
    "request.json", "request.get_json", "request.GET", "request.POST", "request.META",
    "os.environ", "os.getenv", "sys.argv", "input(",
)

# sink call targets per CWE (the tainted-reaching argument is arg 0 unless noted)
_SINKS = {
    "CWE-78": ("os.system", "os.popen", "subprocess.run", "subprocess.Popen",
               "subprocess.check_output", "commands.getoutput", "commands.getstatusoutput"),
    "CWE-22": ("open", "os.open", "send_file", "pathlib.Path.read_text", "Path.read_text"),
    "CWE-79": ("markupsafe.Markup", "mark_safe", "django.utils.safestring.mark_safe",
               "render_template_string"),
}
# subprocess.* is a shell sink ONLY with shell=True; os.system/os.popen/commands.* are always shell.
_SHELL_ALWAYS = ("os.system", "os.popen", "commands.getoutput", "commands.getstatusoutput")
_SHELL_NEEDS_FLAG = ("subprocess.run", "subprocess.Popen", "subprocess.check_output")

# sanitizers that neutralize a given CWE (basename/realpath from the catalog's CWE-22 sink note).
# CWE-78: shlex.quote escapes shell metacharacters; a NUMERIC CAST (int/float) cannot carry a shell
# metacharacter at all, so a value passed through int()/float() is shell-safe by construction — this
# is domain first-principles, not a borrowed verdict ([[curated-knowledge-front]]).
# CWE aliases (same taint detection, different CWE label): CWE-36 (absolute path traversal) and
# CWE-73 (external control of filename) share the CWE-22 path sinks/sanitizers; CWE-77 (command
# injection, general) shares the CWE-78 command sinks/sanitizers. The proof for these still requires
# their own external anchor — this only reuses the verified logic so the detector covers them.
_ALIAS = {"CWE-36": "CWE-22", "CWE-73": "CWE-22", "CWE-77": "CWE-78"}

_SANITIZERS = {
    "CWE-78": ("shlex.quote", "int", "float"),
    # CWE-22: only CONFINE-sanitizers count. basename strips to a filename (confines); realpath/abspath
    # merely NORMALISE (resolve '..') without confining to a base dir — realpath('/s/../etc/passwd')
    # = '/etc/passwd' is still traversal — so they are NOT sanitizers (external-CodeQL false-negative,
    # verified independently: a path through realpath still reaches the sink dangerously).
    "CWE-22": ("os.path.basename", "secure_filename"),
    "CWE-79": ("markupsafe.escape", "html.escape", "bleach.clean", "escape"),
}


def _dotted(node: ast.AST) -> str:
    """Best-effort dotted name of a call target / attribute chain (e.g. os.path.basename)."""
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _expr_src(node: ast.AST) -> str:
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def _is_source_expr(node: ast.AST) -> bool:
    """A node is a taint source if its unparsed text STARTS WITH a catalog source prefix. Anchored
    (startswith), not substring: so a composite like `'ping ' + shlex.quote(request.args.get())` is
    NOT a source at the BinOp level — reachability descends into it and stops at the sanitizer call.
    (A substring test was the RES2/RES3 binding-site bug: `request.args` textually present inside a
    sanitizer wrapper wrongly marked the whole expression tainted.)"""
    s = _expr_src(node)
    return any(s.startswith(pat) for pat in _SOURCES)


def _reaches_unsanitized(node: ast.AST, tainted: set[str], sanitizers: tuple[str, ...]) -> bool:
    """True if a tainted Name OR an inline source expression is reachable in `node` without passing
    through a sanitizer call for this CWE. Inline sources (a source directly in the sink argument,
    no intermediate variable — e.g. send_file(request.args.get('p'))) count: this is the RES1 gap
    the empty inline-source branch used to drop ([[three-impl-independence-discipline]])."""
    if isinstance(node, ast.Call):
        d = _dotted(node.func)
        if d in sanitizers or d.split(".")[-1] in sanitizers:
            return False                              # subtree neutralized — do not descend
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if _is_source_expr(node):
        return True                                   # inline / bare source reaches here unsanitized
    return any(_reaches_unsanitized(ch, tainted, sanitizers) for ch in ast.iter_child_nodes(node))


def _tainted_names(tree: ast.AST, sanitizers: tuple[str, ...]) -> set[str]:
    """Flow-sensitive taint over ALL assignments (module top-level AND function/branch bodies), in
    line order: an assignment taints its targets when the RHS reaches an UNSANITIZED source, and
    CLEANS them (removes taint) when the RHS is a constant or is sanitized at the binding site (so
    `host = shlex.quote(request.args.get('h'))` leaves host clean). Descending into function bodies
    (not just tree.body) is required to catch the real-world shape where the source read and the sink
    both sit inside a handler function — the dominant external-CodeQL recall gap."""
    tainted: set[str] = set()
    stmts = sorted((n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign))),
                   key=lambda n: (n.lineno, getattr(n, "col_offset", 0)))
    for stmt in stmts:
        if isinstance(stmt, ast.Assign):
            hit = _reaches_unsanitized(stmt.value, tainted, sanitizers)
            for tgt in stmt.targets:
                for nm in ast.walk(tgt):
                    if isinstance(nm, ast.Name):
                        (tainted.add if hit else tainted.discard)(nm.id)
        elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None and isinstance(stmt.target, ast.Name):
            hit = _reaches_unsanitized(stmt.value, tainted, sanitizers)
            (tainted.add if hit else tainted.discard)(stmt.target.id)
    return tainted


def _shell_true(call: ast.Call) -> bool:
    for kw in call.keywords:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _list_argv(call: ast.Call) -> bool:
    return bool(call.args) and isinstance(call.args[0], (ast.List, ast.Tuple))


def verdict(code: str, cwe: str) -> str:
    """FLAG / SUPPRESS / OUT_OF_SCOPE for a python snippet against one CWE, by independent AST taint
    reachability. Three-state (matching the multicwe arm and the ground-truth verdict space):
      OUT_OF_SCOPE  no sink of this CWE class is syntactically present.
      SUPPRESS      a class sink is present but its dangerous argument is constant / sanitized / a
                    safe form (list-argv subprocess, no shell=True).
      FLAG          a tainted source reaches a class sink's dangerous argument unsanitized."""
    tree = ast.parse(code)
    cwe = _ALIAS.get(cwe, cwe)                        # CWE-36/73 -> CWE-22 path; CWE-77 -> CWE-78 command
    sinks, sans = _SINKS[cwe], _SANITIZERS[cwe]
    tainted = _tainted_names(tree, sans)
    sink_seen = False
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        target = _dotted(call.func)
        if not any(target == s or target.endswith("." + s) or target.split(".")[-1] == s.split(".")[-1]
                   for s in sinks):
            continue
        sink_seen = True                              # a class sink IS present -> at worst SUPPRESS
        # CWE-78 shell-mode gate
        if cwe == "CWE-78":
            is_shell = any(target == s or target.endswith(s) for s in _SHELL_ALWAYS)
            if not is_shell and any(target.endswith(s) for s in _SHELL_NEEDS_FLAG):
                if _list_argv(call):
                    # list-form argv is safe from SHELL injection, BUT the FIRST element is the
                    # EXECUTABLE — a tainted first element lets the attacker choose the program run
                    # = command injection (external-standard precedence, ratified polaris #6338). A
                    # CONSTANT first element with tainted LATER args stays safe (['ls', user] -> SUPPRESS).
                    elts = call.args[0].elts if call.args and hasattr(call.args[0], "elts") else []
                    if elts and _reaches_unsanitized(elts[0], tainted, sans):
                        return "FLAG"
                    continue
                if not _shell_true(call):
                    continue                          # no shell=True -> not a shell string
                is_shell = True
            if not is_shell:
                continue
        arg = call.args[0] if call.args else None
        if arg is None:
            continue
        if _reaches_unsanitized(arg, tainted, sans):
            return "FLAG"
    return "SUPPRESS" if sink_seen else "OUT_OF_SCOPE"


# per-CWE case-id lists that the fixture pins (the shared oracle cells this lock covers)
_FIXTURE = {
    "CWE-78": "/srv/agent-bridge/sdl/cwe78_canonical_adversarial.jsonl",
    "CWE-22": "/srv/agent-bridge/sdl/cwe22_canonical_adversarial.jsonl",
    "CWE-79": "/srv/agent-bridge/sdl/cwe79_canonical_adversarial.jsonl",
}
_CASES = {"CWE-78": (9, 10, 11, 12, 13), "CWE-22": (9, 10, 11), "CWE-79": (1, 2, 3)}


def derive() -> dict:
    import json
    out: dict = {}
    for cwe, path in _FIXTURE.items():
        by_id = {}
        for line in open(path, encoding="utf-8"):
            line = line.strip()
            if not line:
                continue
            d = json.loads(line)
            if str(d.get("lang", "")).lower() == "python":
                by_id[d.get("case_id")] = d.get("code", d.get("snippet", ""))
        rows = []
        for cid in _CASES[cwe]:
            rows.append({"case_id": cid, "verdict": verdict(by_id[cid], cwe)})
        out[cwe] = rows
    return out


if __name__ == "__main__":
    import json
    print(json.dumps(derive(), indent=1))
