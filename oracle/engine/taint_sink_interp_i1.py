"""taint_sink_interp_i1 — concorde's INDEPENDENT interpreter for the `taint_sink` deriver class.

The fourth motor in the family (after kwarg_guard, conjunction, literal_property), and the first
one whose question is REACHABILITY rather than a property of a single call. It turns any
zynko.derived_detector_spec.v1 {kind: taint_sink} into a per-call detector: given the spec's sink
names, decide for each sink call whether a user-controlled value reaches one of its arguments.

Read the SHARED spec (data), never a sibling's interpreter ([[three-impl-independence-discipline]]).
The taint primitives are concorde's own, reused from py_taint_verdict_i1.

FOUR STATES, and the third one is the honest part:
  FLAG          a source reaches a sink argument — OR the sink's RECEIVER, an object built from
                untrusted data, which controls where the operation goes regardless of its arguments
  SUPPRESS      the sink is called, and nothing user-controlled reaches it (or it is neutralized)
  UNDECIDABLE   the sink is called with a value this model cannot trace — a parameter of a function
                that is not an entry point, an import, an attribute of an unknown object. NOT a
                clean negative: a flow engine with cross-file reach might well find a path
  NO_SINK       no call to a registered sink here

WHAT THIS MOTOR DOES NOT CLAIM. Taint reachability is where the honest limit of an AST-local model
sits ([[flow-bytelock-needs-deep-dataflow-engine]]): recall and precision TOGETHER need a real
cross-file/OO dataflow engine, not a walk over one module's tree. So this motor claims RECALL — it
is built to find the path when the path is visible in the file — and it abstains rather than
guessing when the value comes from outside its horizon. A SUPPRESS from this motor is a statement
about THIS FILE, not about the program.

SOURCE MODEL, derived from framework semantics rather than from any oracle's labels:
 · the request object's user-facing members (Flask request.args/form/values/json/data/files/
   cookies/headers; Django request.GET/POST/FILES/COOKIES/META) — these ARE the HTTP request;
 · a ROUTED VIEW's parameters. A function under @app.route("/<name>") receives `name` from the URL
   path, so the router binds untrusted input straight into the parameter. Missing this is the
   dominant recall gap for framework code, because the source never appears as an expression at all;
 · process-level inputs (sys.argv, input()).
Deliberately NOT sources: os.environ and file reads. Those are attacker-controlled only under a
threat model this spec does not state, and treating them as sources inflates recall on paper while
making every measured precision number worse.
"""
from __future__ import annotations

import ast
import re

from py_taint_verdict_i1 import _dotted, _expr_src

FLAG, SUPPRESS, UNDECIDABLE, NO_SINK = "FLAG", "SUPPRESS", "UNDECIDABLE", "NO_SINK"

#: Expression prefixes that ARE untrusted input. Anchored at the start (see py_taint_verdict_i1's
#: note): a source textually inside a sanitizer wrapper must not taint the whole expression.
_SOURCE_PREFIXES = (
    "request.args", "request.form", "request.values", "request.json", "request.get_json",
    "request.data", "request.files", "request.cookies", "request.headers", "request.stream",
    "request.GET", "request.POST", "request.FILES", "request.COOKIES", "request.META",
    "request.body", "self.request", "flask.request", "sys.argv", "input(",
    # The request OBJECT itself is untrusted, not only its named members. `request.path` is the
    # attacker-chosen URL path, and a bare `request.get("x")` reads request data directly — both
    # appear in real framework code and were the whole source-model gap on the CWE-89 corpus.
    "request.path", "request.full_path", "request.url", "request.query_string",
    "request.get(", "request.get_data", "request.form.get", "request.values.get",
    # Pyramid / WebOb request params — HTTP request input like request.args/values (NOT env/config).
    "request.params", "request.matchdict", "request.GET.get", "request.POST.get",
)

#: Neutralizers a spec need not spell out, because they exist FOR this purpose and a detector that
#: does not know them cannot tell a guarded query from an unguarded one. Derived from what each
#: library is for, not from any oracle's labels — and the distinction is testable: adding these
#: changes NO measured cell (an oracle's alert set contains vulnerabilities, not sanitized calls),
#: it only lets the discrimination probe tell this motor apart from a constant-FLAG detector.
_DEFAULT_SANITIZERS = {
    "sanitize",          # mongosanitizer.sanitizer.sanitize — exists to neutralize NoSQL queries
    "escape", "quote", "quote_plus", "escape_string", "escape_filter_chars",
    "bleach", "clean", "striptags",
}

#: Decorators that mean "the router binds this function's parameters from the URL".
_ROUTE_DECORATORS = ("route", "get", "post", "put", "delete", "patch", "websocket",
                     "add_url_rule", "api_route")

#: SERVER CONTRACTS — the two ways below a web framework that a handler receives the request.
#: A decorator-based source model sees neither, because neither uses a decorator: the request
#: arrives through a signature the standard fixes, or through the handler instance itself.
#:
#: WSGI (PEP 3333) specifies the application signature literally as `application(environ,
#: start_response)`, and defines `environ` as carrying the request — including the client-supplied
#: HTTP_* entries. So a function with that parameter pair has an untrusted first parameter by the
#: standard's own definition, not by any labelling.
_WSGI_SIGNATURE = ("environ", "start_response")

#: `http.server`: BaseHTTPRequestHandler documents `self.path`, `self.headers`, `self.requestline`
#: and `self.rfile` as the parsed REQUEST — the handler instance is the request object. Scoped to
#: modules that actually define such a handler, so `self.path` stays neutral everywhere else.
_HANDLER_BASES = ("BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "CGIHTTPRequestHandler",
                  "StreamRequestHandler", "BaseRequestHandler")
_HANDLER_SOURCE_ATTRS = ("self.path", "self.headers", "self.rfile", "self.requestline",
                         "self.command", "self.client_address")


def _contract_sources(tree: ast.AST):
    """(extra source prefixes, parameter names) that a SERVER CONTRACT makes untrusted."""
    prefixes, params = [], set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            if any(_dotted(b).split(".")[-1] in _HANDLER_BASES for b in node.bases):
                prefixes.extend(_HANDLER_SOURCE_ATTRS)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            names = [a.arg for a in list(node.args.posonlyargs) + list(node.args.args)]
            if tuple(names[:2]) == _WSGI_SIGNATURE:
                params.add(names[0])
    return tuple(prefixes), params


def _key_positions(node: ast.AST) -> list:
    """The NAME-position expressions of a header COLLECTION literal.

    Header APIs take a mapping or a list of pairs as readily as two arguments:
    `make_response(body, {name: value})`, `start_response(status, [(name, value)])`,
    `response.headers.extend(h)`. The dangerous position is the same one — the NAME — but it is
    now a dict KEY or the first element of a pair, so an argument-position model sees nothing.
    Returning only the key positions is what keeps `{"X-Fixed": user_value}` correctly quiet.
    """
    if isinstance(node, ast.Dict):
        return [k for k in node.keys if k is not None]
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return [el.elts[0] for el in node.elts
                if isinstance(el, (ast.Tuple, ast.List)) and el.elts]
    return []


def _literal_bindings(tree: ast.AST) -> dict:
    """name -> the collection literal last assigned to it, for `h = {...}; sink(h)`."""
    out = {}
    for stmt in (n for n in ast.walk(tree) if isinstance(n, ast.Assign)):
        if not isinstance(stmt.value, (ast.Dict, ast.List, ast.Tuple, ast.Set)):
            continue
        for tgt in stmt.targets:
            if isinstance(tgt, ast.Name):
                out[tgt.id] = stmt.value
    return out


def _is_route_decorator(dec: ast.AST) -> bool:
    name = _dotted(dec.func if isinstance(dec, ast.Call) else dec)
    return bool(name) and name.split(".")[-1] in _ROUTE_DECORATORS


def _routed_params(tree: ast.AST) -> dict:
    """{function node -> set of parameter names the router fills with untrusted input}."""
    out = {}
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        if not any(_is_route_decorator(d) for d in fn.decorator_list):
            continue
        args = fn.args
        names = [a.arg for a in list(args.posonlyargs) + list(args.args) + list(args.kwonlyargs)]
        out[fn] = {n for n in names if n not in ("self", "cls", "request")}
    return out


def _local_function_summaries(tree: ast.AST, sanitizers: set, normalizers: set) -> tuple:
    """({names of local functions returning UNTRUSTED data}, {those returning a NORMALISED path}).

    INTERPROCEDURAL, one level and within the file — the smallest step that stops a helper from
    hiding a source. The CWE-22 corpus is built on exactly this:

        def source():  return request.args.get("path", "")
        def normalize(x):  return os.path.normpath(x)

    Four of that cell's five misses had this ONE cause: `x = source()` left `x` untainted, so the
    sink read as SUPPRESS and the guard semantics never even came into play. The queue called it a
    "scaffold-FN", but `source()` is a real local function returning `request.args` — not a harness
    stub — so following it is a capability, not a fit to the test harness.

    Normalisation is summarised the same way and for the same reason: a prefix check confines a path
    only if it was normalised FIRST, and `normalize()` being a helper must not lose that.

    Computed to a fixpoint, because a helper may call a helper.
    """
    functions = {fn.name: fn for fn in ast.walk(tree)
                 if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef))}
    tainted_fns, normalising_fns = set(), set()
    for _ in range(6):
        before = (set(tainted_fns), set(normalising_fns))
        for name, fn in functions.items():
            for ret in (n for n in ast.walk(fn) if isinstance(n, ast.Return) and n.value is not None):
                if _reaches(ret.value, set(), sanitizers, ()) or _calls_any(ret.value, tainted_fns):
                    tainted_fns.add(name)
                if _calls_any(ret.value, normalizers | normalising_fns):
                    normalising_fns.add(name)
        if (tainted_fns, normalising_fns) == before:
            break
    return tainted_fns, normalising_fns


def _calls_any(node: ast.AST, names: set) -> bool:
    """Does this expression call one of `names`?"""
    if not names:
        return False
    for n in ast.walk(node):
        if isinstance(n, ast.Call):
            called = n.func.attr if isinstance(n.func, ast.Attribute) else getattr(n.func, "id", None)
            if called in names:
                return True
    return False


def _is_source_expr(node: ast.AST, extra: tuple = ()) -> bool:
    s = _expr_src(node)
    return any(s.startswith(p) for p in _SOURCE_PREFIXES + tuple(extra))


def _sanitized_call(node: ast.AST, sanitizers: set) -> bool:
    if not isinstance(node, ast.Call):
        return False
    name = _dotted(node.func)
    return bool(name) and (name in sanitizers or name.split(".")[-1] in sanitizers)


def _reaches(node: ast.AST, tainted: set, sanitizers: set, extra: tuple = ()) -> bool:
    """A tainted name or an inline source is reachable here without crossing a sanitizer."""
    if _sanitized_call(node, sanitizers):
        return False
    if isinstance(node, ast.Name) and node.id in tainted:
        return True
    if _is_source_expr(node, extra):
        return True
    return any(_reaches(ch, tainted, sanitizers, extra) for ch in ast.iter_child_nodes(node))


def _unknown_origin(node: ast.AST, tainted: set, known: set, sanitizers: set) -> bool:
    """A bare name that is neither tainted nor locally bound — this model cannot see where it
    came from, so a verdict about it would be a guess."""
    if _sanitized_call(node, sanitizers):
        return False
    if isinstance(node, ast.Name):
        return node.id not in tainted and node.id not in known
    return any(_unknown_origin(ch, tainted, known, sanitizers)
               for ch in ast.iter_child_nodes(node))


def _bound_names(tree: ast.AST) -> set:
    """Names this model actually TRACED to an origin — assignments, imports, defs.

    Function PARAMETERS are deliberately excluded. A parameter of a function that is not a routed
    view is precisely the case this model cannot see: the value arrives from a caller that may be
    in another file, and calling it clean would be the false green the UNDECIDABLE state exists to
    prevent. (Routed parameters are already tainted by the source model, so excluding them here
    costs nothing.)
    """
    out = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store):
            out.add(n.id)
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(n.name)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for a in n.names:
                out.add((a.asname or a.name).split(".")[0])
    return out


def _interproc_param_taint(tree: ast.AST, sanitizers: set, prefix_markers, tainted_fns: set,
                           module_tainted: set) -> dict:
    """{function node -> parameter names tainted because an IN-FILE call-site passes untrusted data
    into that position} — forward, single-file interprocedural taint.

    The smallest sound step past a parameter this model would otherwise leave UNDECIDABLE:

        @app.get("/f/")
        def view(path):                 # routed -> path is tainted
            handler.get_data(path)      # tainted arg into get_data's 1st non-self parameter
        class H:
            def get_data(self, filepath):
                open(filepath)          # filepath is tainted BY THE CALL -> a real finding

    Only ever ADDS taint, and only where a real tainted argument reaches the parameter, so a
    parameter with NO such call-site stays UNDECIDABLE (never silently called clean — the false
    green `_bound_names` exists to prevent). Methods are matched by NAME (the receiver's class is
    not resolved) and a leading `self`/`cls` shifts the positional mapping. Computed to a fixpoint
    jointly with `_function_taint`, because taint chains caller -> callee -> callee.
    """
    defs = {}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.setdefault(n.name, []).append(n)
    seed: dict = {}
    for _ in range(6):
        fn_taint = _function_taint(tree, sanitizers, prefix_markers, tainted_fns, seed)

        def _ctx_at(line: int) -> set:
            best, names = None, set()
            for (lo, hi), got in fn_taint.items():
                if lo <= line <= hi and (best is None or lo > best):
                    best, names = lo, got
            return module_tainted | names

        changed = False
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            callee = call.func.attr if isinstance(call.func, ast.Attribute) \
                else getattr(call.func, "id", None)
            if callee not in defs:
                continue
            ctx = _ctx_at(getattr(call, "lineno", 0))
            for target in defs[callee]:
                params = [a.arg for a in list(target.args.posonlyargs) + list(target.args.args)]
                offset = 1 if params and params[0] in ("self", "cls") else 0
                have = seed.setdefault(target, set())
                for i, arg in enumerate(call.args):
                    pidx = i + offset
                    if pidx < len(params) and params[pidx] not in have \
                            and _reaches(arg, ctx, sanitizers):
                        have.add(params[pidx])
                        changed = True
                for kw in call.keywords:
                    if kw.arg and kw.arg in params and kw.arg not in have \
                            and _reaches(kw.value, ctx, sanitizers):
                        have.add(kw.arg)
                        changed = True
        if not changed:
            break
    return {fn: s for fn, s in seed.items() if s}


def _function_taint(tree: ast.AST, sanitizers: set, prefix_markers=(),
                    tainted_fns: set = frozenset(), seed_params: dict = None) -> dict:
    """{(first_line, last_line) -> names carrying untrusted data} PER FUNCTION.

    A ROUTED PARAMETER belongs to the function the router binds it in, and nowhere else. A single
    module-wide set says otherwise, and the corpora test exactly that: semgrep's CWE-73 file holds
    the same `send_file(filename)` call twice, once in an `@app.route` view (an alert) and once in a
    plain helper (clean), distinguished ONLY by whether the router supplies the parameter. With a
    module-scoped set the helper inherits the view's taint and the clean case reads as a finding —
    the same cross-function name collision that made an un-normalised URL check look guarded.

    Module-level statements are handled separately (see `_taint_fixpoint`) because a module-level
    binding really is visible everywhere.
    """
    out = {}
    seed_params = seed_params or {}
    routed = _routed_params(tree)
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        span = (getattr(fn, "lineno", 0), getattr(fn, "end_lineno", 0) or 0)
        tainted = set(routed.get(fn, set())) | set(seed_params.get(fn, set()))
        extra_prefixes, contract_params = _contract_sources(fn)
        tainted |= contract_params
        assigns = [n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign))]
        for _ in range(8):
            before = set(tainted)
            for stmt in assigns:
                value = stmt.value
                if value is None:
                    continue
                hit = _reaches(value, tainted, sanitizers, extra_prefixes) or \
                    _calls_any(value, tainted_fns)
                if hit and prefix_markers and _fixes_destination(value, prefix_markers):
                    hit = False
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                for tgt in targets:
                    for nm in ast.walk(tgt):
                        if isinstance(nm, ast.Name):
                            if hit:
                                tainted.add(nm.id)
                            elif isinstance(value, ast.Constant) or _sanitized_call(value, sanitizers) or (
                                    prefix_markers and _fixes_destination(value, prefix_markers)):
                                # `x = sanitize(x)` clears x's taint — a reassignment through a
                                # neutraliser rebinds the name to a safe value.
                                tainted.discard(nm.id)
            if tainted == before:
                break
        out[span] = tainted
    return out


def _taint_fixpoint(tree: ast.AST, sanitizers: set, prefix_markers=(),
                    tainted_fns: set = frozenset()) -> set:
    """Names carrying untrusted data, to a fixpoint over assignments plus routed parameters.

    Iterated rather than single-pass because taint flows through chains (a = source; b = a; c = b)
    and a statement-ordered single pass misses a binding that is only tainted after a later one.
    """
    # Routed parameters are NOT seeded here: they belong to their own function and are handled by
    # `_function_taint`. Seeding them globally is what let one view's parameter taint another
    # function's identically-named one.
    tainted = set()
    extra_prefixes, contract_params = _contract_sources(tree)
    tainted |= contract_params
    assigns = [n for n in ast.walk(tree) if isinstance(n, (ast.Assign, ast.AnnAssign))]
    for _ in range(8):                                  # small module; converges in a few rounds
        before = set(tainted)
        for stmt in assigns:
            value = stmt.value
            if value is None:
                continue
            hit = _reaches(value, tainted, sanitizers, extra_prefixes) or \
                _calls_any(value, tainted_fns)
            # A LEADING CONSTANT can fix where a value points even though untrusted data is still
            # inside it: `"https://safe.com/" + user` is not a redirect the user controls. The
            # marker list comes from the spec, because what counts as "fixed" is a property of the
            # class (a URL host, a path root) rather than of concatenation.
            if hit and prefix_markers and _fixes_destination(value, prefix_markers):
                hit = False
            targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
            for tgt in targets:
                for nm in ast.walk(tgt):
                    if isinstance(nm, ast.Name):
                        if hit:
                            tainted.add(nm.id)
                        elif isinstance(value, ast.Constant) or (
                                prefix_markers and _fixes_destination(value, prefix_markers)):
                            tainted.discard(nm.id)      # a constant genuinely cleans the binding
        if tainted == before:
            break
    return tainted


def _call_name(call: ast.Call):
    return call.func.attr if isinstance(call.func, ast.Attribute) else getattr(call.func, "id", None)


def _literal_parts(node: ast.AST) -> list:
    """Every string literal inside an expression — the part the caller wrote, not the value."""
    out = []
    for n in ast.walk(node):
        if isinstance(n, ast.Constant) and isinstance(n.value, str):
            out.append(n.value)
    return out


def _arg_matches_shape(call: ast.Call, pattern: str) -> bool:
    """Does argument 0's literal text carry the class's own syntax?"""
    if not call.args:
        return False
    return any(re.search(pattern, lit) for lit in _literal_parts(call.args[0]))


def _has_nonhtml_content_type(call: ast.Call) -> bool:
    """Does this response call set a NON-HTML Content-Type (json/plain/...)? Checks a headers dict
    literal ({'Content-Type': 'application/json'}) and content_type=/mimetype= keywords. Conservative:
    only returns True for an explicit non-HTML type (never suppresses an HTML/unspecified response)."""
    def _nonhtml(s):
        s = s.lower()
        return ("html" not in s) and (("json" in s) or ("text/plain" in s) or ("octet-stream" in s)
                                      or ("csv" in s) or ("javascript" in s) or ("xml" in s and "html" not in s))
    # headers dict literal among the positional args
    for a in call.args:
        if isinstance(a, ast.Dict):
            for k, v in zip(a.keys, a.values):
                if isinstance(k, ast.Constant) and isinstance(k.value, str) and k.value.lower() == "content-type":
                    if isinstance(v, ast.Constant) and isinstance(v.value, str) and _nonhtml(v.value):
                        return True
    # content_type= / mimetype= keyword
    for kw in call.keywords or []:
        if kw.arg in ("content_type", "mimetype") and isinstance(kw.value, ast.Constant) \
                and isinstance(kw.value.value, str) and _nonhtml(kw.value.value):
            return True
    return False


#: yaml loaders that cannot construct arbitrary objects — the safe counterparts to the full loader.
_SAFE_YAML_LOADERS = ("SafeLoader", "CSafeLoader", "BaseLoader", "CBaseLoader")


def _has_safe_loader_kwarg(call: ast.Call) -> bool:
    """Does this load() carry Loader=<a safe loader>? `yaml.load(x, Loader=SafeLoader)` cannot build
    arbitrary objects, so it is neutralised. Conservative: only the explicitly-safe loaders (never
    FullLoader/Loader/an unknown expression), so an unsafe or unspecified loader still flags."""
    for kw in call.keywords or []:
        if kw.arg == "Loader":
            name = _dotted(kw.value) if not isinstance(kw.value, ast.Name) else kw.value.id
            if name and name.split(".")[-1] in _SAFE_YAML_LOADERS:
                return True
    return False


#: lxml/ElementTree parser constructors whose entity resolution can be turned off.
_XML_PARSER_CTORS = ("XMLParser", "ETCompatXMLParser", "XMLPullParser", "get_default_parser")


def _xml_parser_call_is_safe(call: ast.Call) -> bool:
    """An XMLParser(...) constructor that DISABLES entity resolution (resolve_entities=False).
    lxml defaults resolve_entities=True, so only an explicit False is safe; True/absent stays unsafe."""
    if not isinstance(call, ast.Call):
        return False
    if (_call_name(call) or "").split(".")[-1] not in _XML_PARSER_CTORS:
        return False
    for kw in call.keywords or []:
        if kw.arg == "resolve_entities" and isinstance(kw.value, ast.Constant) and kw.value.value is False:
            return True
    return False


def _safe_xml_parser_vars(tree: ast.AST) -> dict:
    """{(fn first_line, last_line) -> names bound to a resolve_entities=False parser} PER FUNCTION.

    Function-scoped, not module-scoped: two handlers routinely reuse the local name `parser`, one a
    safe (resolve_entities=False) parser and one an unsafe (resolve_entities=True) one. A module-wide
    set would let the safe handler's `parser` suppress the unsafe handler's identically-named sink —
    the same cross-function name collision the taint model is split per function to avoid. A
    reassignment of the name to any other call within the function drops it from the safe set.
    """
    out = {}
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        span = (getattr(fn, "lineno", 0), getattr(fn, "end_lineno", 0) or 0)
        safe = set()
        for stmt in (n for n in ast.walk(fn) if isinstance(n, ast.Assign)):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    if _xml_parser_call_is_safe(stmt.value):
                        safe.add(tgt.id)
                    elif isinstance(stmt.value, ast.Call):
                        safe.discard(tgt.id)   # rebound to a non-safe parser -> no longer safe
        out[span] = safe
    return out


def _has_safe_xml_parser(call: ast.Call, safe_vars: set) -> bool:
    """Does this parse carry parser=<a parser with entity resolution off>? Handles both a bound name
    (parser=parser) and an inline constructor (parser=XMLParser(resolve_entities=False))."""
    for kw in call.keywords or []:
        if kw.arg == "parser":
            v = kw.value
            if isinstance(v, ast.Name) and v.id in safe_vars:
                return True
            if _xml_parser_call_is_safe(v):
                return True
    return False


def _has_shell_true(call: ast.Call) -> bool:
    """Does this call pass shell=True? The subprocess family (run/call/Popen/check_*) runs a SHELL —
    and is a command-injection sink — only with shell=True; the list-argv form (subprocess.run(['ls',
    x])) execs directly with no shell, so a tainted element cannot inject a command."""
    for kw in call.keywords or []:
        if kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True:
            return True
    return False


def _sink_args(call: ast.Call) -> list:
    return list(call.args) + [kw.value for kw in call.keywords]


#: Whole-string predicates: each is TRUE only if EVERY character satisfies it, so passing one
#: constrains the entire value's alphabet. `startswith`/`endswith`/`in`/`len` are deliberately NOT
#: here — they constrain a part, and the rest of the string stays free.
_WHOLE_STRING_PREDICATES = ("isalnum", "isalpha", "isdecimal", "isdigit", "isnumeric",
                            "isascii", "isspace", "islower", "isupper")


def _pattern_is_restrictive(pattern: str) -> bool:
    """A regex restricts the alphabet only if it cannot match arbitrary characters.

    The discriminator is the unescaped `.` (and its friends `\\S`, `\\W`): they admit anything, so a
    pattern containing one constrains nothing about content no matter how it is anchored. This is
    what separates the oracle's guarded cells from its two MISSING ones — `[a-zA-Z0-9]+` restricts,
    `.*[a-zA-Z0-9]+.*` does not, and the second must stay flagged.
    """
    out, i = [], 0
    while i < len(pattern):
        if pattern[i] == "\\" and i + 1 < len(pattern):
            out.append("\\" + pattern[i + 1])
            i += 2
            continue
        out.append(pattern[i])
        i += 1
    tokens = out
    if any(t == "." for t in tokens):
        return False
    return not any(t in ("\\S", "\\W", "\\D") for t in tokens)


def _anchored(pattern: str) -> bool:
    return pattern.startswith("^") and pattern.endswith("$")


def _normalised_names(tree: ast.AST, normalizers: set, normalising_fns: set = frozenset()) -> set:
    """Names assigned from a path-normalising call. Half of a containment guard, never the whole.

    `startswith(ROOT)` alone does NOT confine a path: STATIC_DIR + "/../../etc/passwd" passes the
    prefix test and still escapes. Only a NORMALISED path can be confined by a prefix check, which
    is exactly the pair the CWE-22 oracle draws — "normalized, but not checked" is still an alert,
    and so is a check whose body does not contain the sink.
    """
    out = set()
    for stmt in (n for n in ast.walk(tree) if isinstance(n, ast.Assign)):
        for call in (x for x in ast.walk(stmt.value) if isinstance(x, ast.Call)):
            name = call.func.attr if isinstance(call.func, ast.Attribute) \
                else getattr(call.func, "id", None)
            if name in normalizers or name in normalising_fns:
                for tgt in stmt.targets:
                    for nm in ast.walk(tgt):
                        if isinstance(nm, ast.Name):
                            out.add(nm.id)
    return out


def _containment_guarded(test: ast.AST, guards: set, normalised: set) -> set:
    """Names a containment check confines — only where the value was normalised first."""
    names = set()
    for node in ast.walk(test):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr in guards and isinstance(node.func.value, ast.Name)
                and node.func.value.id in normalised):
            names.add(node.func.value.id)
    return names


def _guarded_names(test: ast.AST, compiled: dict) -> set:
    """Names whose ENTIRE content this boolean test constrains.

    Derived from what each API promises, not from which cells the oracle marks OK:
      · a whole-string predicate on a name constrains that name;
      · re.fullmatch(p, x) constrains x when p is restrictive — fullmatch already spans the string;
      · re.match(p, x) only pins a PREFIX, so it constrains x only when p is anchored ^...$;
      · the compiled forms follow the same split, using the pattern given to re.compile.
    """
    names = set()
    for node in ast.walk(test):
        if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
            continue
        attr = node.func.attr
        if attr in _WHOLE_STRING_PREDICATES and isinstance(node.func.value, ast.Name):
            names.add(node.func.value.id)
            continue
        if attr not in ("match", "fullmatch"):
            continue
        base = node.func.value
        pattern = None
        if isinstance(base, ast.Name) and base.id == "re" and node.args:
            first = node.args[0]
            pattern = first.value if isinstance(first, ast.Constant) else None
            target = node.args[1] if len(node.args) > 1 else None
        elif isinstance(base, ast.Name):
            pattern = compiled.get(base.id)
            target = node.args[0] if node.args else None
        else:
            continue
        if not isinstance(pattern, str) or not isinstance(target, ast.Name):
            continue
        if not _pattern_is_restrictive(pattern):
            continue                              # `.`-bearing pattern restricts nothing
        if attr == "fullmatch" or _anchored(pattern):
            names.add(target.id)
    return names


def _compiled_patterns(tree: ast.AST) -> dict:
    """{name: pattern} for `name = re.compile("...")`, so reg.match(x) can be judged."""
    out = {}
    for stmt in (n for n in ast.walk(tree) if isinstance(n, ast.Assign)):
        v = stmt.value
        if (isinstance(v, ast.Call) and isinstance(v.func, ast.Attribute)
                and v.func.attr == "compile" and v.args
                and isinstance(v.args[0], ast.Constant) and isinstance(v.args[0].value, str)):
            for tgt in stmt.targets:
                if isinstance(tgt, ast.Name):
                    out[tgt.id] = v.args[0].value
    return out


def _guard_regions(tree: ast.AST, tainted: set, sanitizers: set,
                   containment: set = frozenset(), normalizers: set = frozenset(),
                   url_guards: dict | None = None, url_normalizers=(),
                   constant_equality: bool = False, early_return: bool = False,
                   normalising_fns: set = frozenset()) -> list:
    """[(first_line, last_line, {names clean inside this branch})] for every `if <strong guard>:`.

    Flow-sensitive on purpose and only in the true branch: a validated value is validated where the
    check succeeded, not in the else-branch and not afterwards.

    The validated name is rarely the one handed to the sink. The shape that matters is

        if user_input.isalnum():
            url = f"https://example.com/foo#{user_input}"
            requests.get(url)

    where `url` is what reaches the call. So cleanliness PROPAGATES inside the region: a name
    assigned there from a right-hand side that no longer reaches anything tainted is clean too.
    Without that step the guard recognises the check and still flags the call, which is the same as
    not having it.
    """
    compiled = _compiled_patterns(tree)
    normalised = _normalised_names(tree, normalizers, normalising_fns) if containment else set()
    url_normalised_by_fn = _normalised_for_url(tree, set(url_normalizers)) if url_guards else {}

    def _normalised_at(line: int) -> set:
        best, names = None, set()
        for (lo, hi), got in url_normalised_by_fn.items():
            if lo <= line <= hi and (best is None or lo > best):
                best, names = lo, got
        return names
    out = []
    for node in (n for n in ast.walk(tree) if isinstance(n, ast.If)):
        names = _guarded_names(node.test, compiled)
        if containment:
            names |= _containment_guarded(node.test, containment, normalised)
        if url_guards:
            names |= _url_guarded(node.test, url_guards, _normalised_at(getattr(node, "lineno", 0)))
        if constant_equality:
            names |= _constant_equality_names(node.test)
        # EARLY RETURN. `if <negated guard>: return safe` leaves the rest of the function reachable
        # only when the guard HELD, so the value is validated after the `if`, not inside it.
        if early_return and _always_exits(node.body) and url_guards:
            inverted = _url_guarded(ast.UnaryOp(op=ast.Not(), operand=node.test),
                                    url_guards, _normalised_at(getattr(node, "lineno", 0)))
            if inverted:
                enclosing = _enclosing_function_span(tree, getattr(node, "lineno", 0))
                if enclosing:
                    end_of_if = max((getattr(x, "lineno", 0) for x in ast.walk(node)), default=0)
                    out.append((end_of_if + 1, enclosing[1], set(inverted)))
        if not names or not node.body:
            continue
        lines = [x.lineno for b in node.body for x in ast.walk(b) if hasattr(x, "lineno")]
        if not lines:
            continue
        lo, hi = min(lines), max(lines)
        clean = set(names)
        for _ in range(4):                              # short chains inside a branch
            before = set(clean)
            for stmt in (n for n in ast.walk(node) if isinstance(n, ast.Assign)):
                if not (lo <= getattr(stmt, "lineno", -1) <= hi):
                    continue
                if _reaches(stmt.value, tainted - clean, sanitizers):
                    continue                            # still carries something unvalidated
                for tgt in stmt.targets:
                    for nm in ast.walk(tgt):
                        if isinstance(nm, ast.Name):
                            clean.add(nm.id)
            if clean == before:
                break
        out.append((lo, hi, clean))
    return out



def _leading_literal(node: ast.AST):
    """The constant string that a concatenation/format puts FIRST, or None.

    The order is the whole question for a redirect: `"https://safe.com/" + user` cannot leave
    safe.com, and `user + "?login=success"` fixes nothing. Handled for every spelling of the same
    operation, because the operator is irrelevant — `+`, `+=`, `.format()`, an f-string and `%` all
    put a literal in front or they do not.
    """
    if isinstance(node, ast.Constant):
        return node.value if isinstance(node.value, str) else None
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _leading_literal(node.left)
    if isinstance(node, ast.JoinedStr):                     # f"..."
        first = node.values[0] if node.values else None
        return _leading_literal(first) if isinstance(first, ast.Constant) else None
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
            and node.func.attr == "format":
        return _leading_literal(node.func.value)
    return None


def _fixes_destination(node: ast.AST, markers) -> bool:
    """Does this expression begin with a constant that pins where the value points?"""
    lit = _leading_literal(node)
    if not lit:
        return False
    return any(m in lit if m == "://" else lit.startswith(m) for m in markers)


def _normalised_for_url(tree: ast.AST, normalizers) -> dict:
    """Names that had a BACKSLASH normalised away — the precondition a host check needs.

    Browsers read `\\/evil.com` as `//evil.com`, so `urlparse` reports an EMPTY netloc for it and an
    unnormalised emptiness check passes on a URL that leaves the site. The oracle's corpus draws the
    pair deliberately: `/ok8` and `/not_ok6` are the same function apart from this call.
    """
    # PER FUNCTION, not per module. A module-wide set says `untrusted` is normalised because some
    # OTHER view normalised a variable of that name — and the oracle's corpus is built out of
    # functions that reuse the name deliberately (`/ok7` normalises, `/not_ok5` does not, and they
    # are otherwise identical). Module scope makes the vulnerable one look guarded.
    out: dict = {}
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        names = set()
        for stmt in (n for n in ast.walk(fn) if isinstance(n, ast.Assign)):
            call = stmt.value
            if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
                continue
            if call.func.attr not in normalizers or not call.args:
                continue
            first = call.args[0]
            if not (isinstance(first, ast.Constant) and isinstance(first.value, str)
                    and "\\" in first.value):
                continue                                    # a replace of something else is not this
            for tgt in stmt.targets:
                for nm in ast.walk(tgt):
                    if isinstance(nm, ast.Name):
                        names.add(nm.id)
        out[(getattr(fn, "lineno", 0), getattr(fn, "end_lineno", 0) or 0)] = names
    return out


def _url_guarded(test: ast.AST, guards: dict, normalised: set, negated: bool = False) -> set:
    """Names a HOST-ALLOWLIST check validates in this test, honouring polarity and normalisation."""
    out = set()
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        return _url_guarded(test.operand, guards, normalised, not negated)
    if isinstance(test, ast.BoolOp):
        for v in test.values:
            out |= _url_guarded(v, guards, normalised, negated)
        return out
    if isinstance(test, ast.Compare) and len(test.ops) == 1:
        op = test.ops[0]
        # `netloc == ""` and `netloc in ["", host]` assert the host is not the attacker's; `!=` and
        # `not in` assert the opposite. Under a NEGATION the two swap — `not (netloc not in L)` is
        # `netloc in L`, which is the shape an early-return guard takes: the `if` sends the bad case
        # away and everything after it has passed the check.
        positive = isinstance(op, (ast.Eq, ast.In))
        negative = isinstance(op, (ast.NotEq, ast.NotIn))
        asserts_empty = (positive and not negated) or (negative and negated)
        return _url_guarded_name(test.left, guards, normalised, want_empty=asserts_empty)
    return _url_guarded_name(test, guards, normalised, want_empty=negated) | out


def _url_guarded_name(node: ast.AST, guards: dict, normalised: set, want_empty: bool) -> set:
    """The name a single host-check expression is about, if the check is sound as written."""
    name = attr = None
    if isinstance(node, ast.Attribute):                     # urlparse(x).netloc
        attr = node.attr
        inner = node.value
    elif isinstance(node, ast.Call):
        func = node.func
        attr = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
        # An argument-less METHOD carries its subject in the receiver chain, not in args:
        # `yarl.URL(url).is_absolute()` asks about `url`, which sits under func.value.
        inner = node.args[0] if node.args else (
            func.value if isinstance(func, ast.Attribute) else None)
        if attr in guards and guards[attr].get("polarity") == "truthy":
            # a helper that answers the question directly, e.g. Django's own
            if want_empty:
                return set()                                # `not helper(x)` permits the bad case
            nm = _first_name(inner)
            return {nm} if nm else set()
    else:
        return set()
    rule = guards.get(attr)
    if rule is None:
        return set()
    polarity = rule.get("polarity")
    if polarity == "empty" and not want_empty:
        return set()                                        # `netloc != ""` is the wrong direction
    if polarity == "negated" and not want_empty:
        return set()                                        # `is_absolute()` must be NEGATED
    nm = _first_name(inner)
    if nm is None:
        return set()
    if rule.get("requires_normalisation") and nm not in normalised:
        return set()                                        # the backslash bypass is still open
    return {nm}


def _first_name(node: ast.AST):
    """The name a check is ABOUT — structurally, not the first Name a walk happens to meet.

    A flat walk answers `urlparse` for `urlparse(url).netloc` and `yarl` for
    `yarl.URL(url).is_absolute()`, because the callee is a Name too and comes first. Both readings
    then fail the normalisation test against a name that was never a value, and the guard silently
    stops working — which is how four correctly-guarded redirects read as findings.
    """
    if node is None:
        return None
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Call):
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            nm = _first_name(arg)
            if nm:
                return nm
        return _first_name(node.func) if isinstance(node.func, ast.Attribute) else None
    if isinstance(node, ast.Attribute):
        return _first_name(node.value)
    if isinstance(node, (ast.Subscript, ast.Starred)):
        return _first_name(node.value)
    if isinstance(node, ast.BinOp):
        return _first_name(node.left) or _first_name(node.right)
    return None


def _constant_equality_names(test: ast.AST) -> set:
    """`x == "literal"` pins x to that literal, so it is no longer attacker-controlled."""
    out = set()
    if isinstance(test, ast.BoolOp):
        for v in test.values:
            out |= _constant_equality_names(v)
        return out
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        if isinstance(test.left, ast.Name) and len(test.comparators) == 1 \
                and isinstance(test.comparators[0], ast.Constant):
            out.add(test.left.id)
    return out


def _always_exits(body: list) -> bool:
    """Does this branch always leave the function? Then a NEGATED guard in front of it validates the
    value for everything AFTER the `if` — the early-return shape, which the oracle's /ok11 uses and
    a true-branch-only model reads as an unguarded redirect."""
    return bool(body) and isinstance(body[-1], (ast.Return, ast.Raise, ast.Continue, ast.Break))


def _enclosing_function_span(tree: ast.AST, line: int):
    """(first, last) line of the function containing `line`, for the early-return region."""
    best = None
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        lo, hi = getattr(fn, "lineno", 0), getattr(fn, "end_lineno", 0) or 0
        if lo <= line <= hi and (best is None or lo > best[0]):
            best = (lo, hi)
    return best


def _receiver(call: ast.Call):
    """The object a method is called ON, or None for a bare function call.

    RECEIVER TAINT, and why it is not the same question as argument taint. An object built from
    untrusted data carries that data's control into every operation performed on it — the arguments
    of the later call are irrelevant to where it goes. The SSRF shape that made this visible:

        conn = HTTPConnection(unsafe_host)   # the DESTINATION is attacker-controlled
        conn.request("GET", "/foo")          # constant path, still a request to the attacker

    Two cells of the CWE-918 oracle set turned on exactly this, and no amount of sink-name listing
    reaches them, because the sink was already found; what was missing was the taint's route.

    Deliberately narrow: this only lifts a call that is ALREADY a registered sink. A tainted object
    is not made dangerous by having methods — it is dangerous when one of them performs the
    operation the CWE is about.
    """
    return call.func.value if isinstance(call.func, ast.Attribute) else None


def per_call(spec: dict, code: str) -> list:
    """Per-CALL verdicts [(lineno, FLAG|SUPPRESS|UNDECIDABLE)] for the spec's sinks."""
    sinks = set(spec.get("sink_names", []))
    # spec-declared neutralizers, plus the library-purpose defaults (see _DEFAULT_SANITIZERS)
    sanitizers = set(spec.get("sanitizers", [])) | _DEFAULT_SANITIZERS
    out = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return out
    prefix_markers = tuple(spec.get("destination_fixing_prefix", ()))
    tainted_fns, normalising_fns = _local_function_summaries(
        tree, sanitizers, set(spec.get("path_normalizers", ())))
    tainted = _taint_fixpoint(tree, sanitizers, prefix_markers, tainted_fns)
    seed_params = _interproc_param_taint(tree, sanitizers, prefix_markers, tainted_fns, tainted)
    fn_taint = _function_taint(tree, sanitizers, prefix_markers, tainted_fns, seed_params)

    # Names a function locally CLEANS — rebound to a sanitised call or a constant (`x = escape(x)`)
    # and not re-tainted by the function view. These shadow the coarse module taint, which cannot
    # clear a name per function. Only the cleaned names are shadowed (not every local binding), so a
    # name the function does not clean keeps whatever the module fixpoint derived for it.
    fn_cleared = {}
    for fn in (n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))):
        span = (getattr(fn, "lineno", 0), getattr(fn, "end_lineno", 0) or 0)
        cleaned = set()
        for a in (n for n in ast.walk(fn) if isinstance(n, (ast.Assign, ast.AnnAssign))):
            if a.value is not None and (isinstance(a.value, ast.Constant)
                                        or _sanitized_call(a.value, sanitizers)):
                for tgt in (a.targets if isinstance(a, ast.Assign) else [a.target]):
                    for nm in ast.walk(tgt):
                        if isinstance(nm, ast.Name):
                            cleaned.add(nm.id)
        fn_cleared[span] = cleaned - fn_taint.get(span, set())

    def _tainted_at(line: int) -> set:
        """The enclosing function's own taint, plus module taint EXCEPT names the function locally
        cleans (a per-function sanitise the module-wide fixpoint cannot see) — never another
        function's."""
        best, names, cleared = None, set(), set()
        for (lo, hi), got in fn_taint.items():
            if lo <= line <= hi and (best is None or lo > best):
                best, names, cleared = lo, got, fn_cleared.get((lo, hi), set())
        return (tainted - cleared) | names
    # MODULE-SCOPED NEUTRALISERS. Some protections are not applied to the value at all — they wrap
    # the whole application at start-up, in a different function from the one holding the sink.
    # `wsgiref.validate.validator(app)` is the clear case: PEP 3333's validator rejects headers
    # containing newlines, so a wrapped app cannot split a response no matter how its headers are
    # built. Nothing local to the sink says so, which is why this is judged per MODULE.
    # The coarseness is real and worth stating: a module defining two apps, only one of them
    # wrapped, is called clean throughout. That is a known over-suppression, not an oversight.
    module_neutral = set(spec.get("module_neutralizers") or ())
    neutralised_module = bool(module_neutral) and any(
        _call_name(n) in module_neutral for n in ast.walk(tree) if isinstance(n, ast.Call))
    if neutralised_module:
        tainted = set()
        # A module-scoped protection covers the FUNCTION-scoped taint too. Splitting the taint model
        # per function moved the routed parameters out of the set this reset was clearing, so a
        # wrapped WSGI app started reading as unprotected again — the fix has to apply to BOTH
        # halves or it only appears to apply.
        fn_taint = {span: set() for span in fn_taint}
    extra_prefixes, _ = _contract_sources(tree)
    literals = _literal_bindings(tree)
    collection_hits = []
    known = _bound_names(tree)
    safe_xml_parsers_by_fn = _safe_xml_parser_vars(tree) if spec.get("xml_parser_safe") else {}

    def _safe_parsers_at(line: int) -> set:
        best, names = None, set()
        for (lo, hi), got in safe_xml_parsers_by_fn.items():
            if lo <= line <= hi and (best is None or lo > best):
                best, names = lo, got
        return names
    regions = _guard_regions(tree, tainted, sanitizers,
                             set(spec.get("containment_guards", ())),
                             set(spec.get("path_normalizers", ())),
                             url_guards=spec.get("url_host_guards") or None,
                             url_normalizers=tuple(spec.get("url_normalizers", ())),
                             constant_equality=bool(spec.get("constant_equality_guard")),
                             early_return=bool(spec.get("early_return_guard")),
                             normalising_fns=normalising_fns)
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        if _call_name(call) not in sinks:
            continue
        line = getattr(call, "lineno", 0)
        guarded = set()
        for lo, hi, names in regions:
            if lo <= line <= hi:
                guarded |= names
        local_tainted = _tainted_at(line) - guarded   # validated in this branch, not everywhere
        args = _sink_args(call)
        # POSITION-RESTRICTED SINKS. For some classes only certain argument positions are dangerous.
        # HTTP header APIs are the clear case: modern frameworks strip newlines from a header VALUE
        # but not from a header NAME, so headers.add("X", user) is safe while headers.add(user, "X")
        # is response splitting. Flagging every argument would call the safe spelling a finding.
        # SHAPE-GATED SINKS. Some real sink names are also extremely common elsewhere:
        # ElementTree's `find`/`findall` accept a restricted XPath, and `find` is equally
        # `str.find` and `pymongo.find`. A name-only list flags `s.find(user_input)` as XPath
        # injection; omitting the name loses `tree.findall("./x[@id=%s]" % v)`, which is the real
        # weakness. So the ARGUMENT decides: the literal part must look like the class's syntax.
        shape = (spec.get("sink_arg_shape") or {}).get(_call_name(call))
        if shape is not None and not _arg_matches_shape(call, shape):
            continue
        positions = (spec.get("sink_taint_args") or {}).get(_call_name(call))
        if positions is not None:
            args = [call.args[i] for i in positions if i < len(call.args)]
        # COLLECTION-SHAPED SINKS. The finding is reported where the collection is BUILT, which is
        # the line the untrusted name actually reaches — a separate statement from the call whenever
        # the collection is bound to a variable first.
        coll_idx = (spec.get("collection_args") or {}).get(_call_name(call))
        if coll_idx is not None and coll_idx < len(call.args):
            node = call.args[coll_idx]
            lit = literals.get(node.id) if isinstance(node, ast.Name) else node
            for key in _key_positions(lit) if lit is not None else []:
                if _reaches(key, local_tainted, sanitizers, extra_prefixes):
                    collection_hits.append((getattr(lit, "lineno", line), FLAG))
        recv = _receiver(call)
        # CONFINING SINKS. Some APIs confine their later arguments to a ROOT given in the first
        # one — send_from_directory(root, filename) cannot escape `root`. That makes them a sink or
        # a neutraliser depending on the ROOT, not on the function: with a constant root the call is
        # safe, and with an attacker-controlled root it confines nothing. A binary sink/sanitizer
        # split cannot express that, and getting it wrong costs a real alert in either direction —
        # listing it as a sanitizer lost the oracle's `send_from_directory(dirname, filename)` cell.
        confine = (spec.get("confining_sinks") or {}).get(_call_name(call))
        if confine is not None:
            trusted = call.args[:confine]
            if not any(_reaches(a, local_tainted, sanitizers) for a in trusted):
                out.append((getattr(call, "lineno", 0), SUPPRESS))
                continue                              # root is trusted -> the rest is confined
        # CONTENT-TYPE SAFETY (XSS, spec-gated): a response served with a NON-HTML Content-Type is not
        # rendered as HTML, so a tainted body cannot execute — e.g.
        #   make_response(json.dumps(x), 200, {'Content-Type': 'application/json'})
        # Only active when the spec opts in (content_type_safe), so no other CWE is affected.
        if spec.get("content_type_safe") and _has_nonhtml_content_type(call):
            out.append((getattr(call, "lineno", 0), SUPPRESS))
            continue
        # DESERIALIZATION SAFE-LOADER (CWE-502, spec-gated): yaml.load(x, Loader=SafeLoader) cannot
        # construct arbitrary objects. pickle/marshal/dill take no Loader kwarg, so are unaffected.
        if spec.get("deser_safe_loader") and _has_safe_loader_kwarg(call):
            out.append((getattr(call, "lineno", 0), SUPPRESS))
            continue
        # SHELL-CONDITIONAL SINKS (CWE-78, spec-gated): subprocess run/call/Popen/check_* are a command-
        # injection sink ONLY with shell=True. Without it the args are an exec argv (no shell), so a
        # tainted element cannot inject a command -> not a sink.
        if _call_name(call) in (spec.get("shell_required_sinks") or ()) and not _has_shell_true(call):
            out.append((getattr(call, "lineno", 0), SUPPRESS))
            continue
        # XXE SAFE PARSER (CWE-611, spec-gated): parse(x, parser=XMLParser(resolve_entities=False))
        # cannot expand external entities. resolve_entities defaults True, so only explicit-False parses
        # are suppressed; the resolve_entities=True super-vuln parser still flags.
        if spec.get("xml_parser_safe") and _has_safe_xml_parser(call, _safe_parsers_at(getattr(call, "lineno", 0))):
            out.append((getattr(call, "lineno", 0), SUPPRESS))
            continue
        if any(_reaches(a, local_tainted, sanitizers, extra_prefixes) for a in args):
            verdict_ = FLAG
        elif recv is not None and not spec.get("ignore_receiver_taint") \
                and _reaches(recv, local_tainted, sanitizers, extra_prefixes):
            verdict_ = FLAG                       # receiver taint: the destination is controlled
            # (CWE-434 sets ignore_receiver_taint: an uploaded file OBJECT `f=request.files[..]` is a
            # tainted receiver, but the injection is the PATH arg of f.save(path) — not `f` itself.)
        elif any(_unknown_origin(a, local_tainted, known, sanitizers) for a in args):
            verdict_ = UNDECIDABLE
        else:
            verdict_ = SUPPRESS
        # LINE ATTRIBUTION over the call's whole span. A multi-line call carries the oracle's
        # marker on the line where the interesting ARGUMENT sits, not where the call starts:
        #     conn.search(dn, ldap.SCOPE_SUBTREE,
        #                 search_filter)   # $ Alert     <- the pointer is here
        # Reporting only call.lineno made four CWE-90 cells read as NO_SINK, which looks like a
        # missing sink name and is really a missing line.
        start = getattr(call, "lineno", 0)
        end = getattr(call, "end_lineno", start) or start
        for line_no in range(start, end + 1):
            out.append((line_no, verdict_))
    out.extend(collection_hits)      # last, so a construction-site FLAG outranks the call's verdict
    return out


def make_detector(spec: dict):
    """spec -> verdict(code) -> FLAG|SUPPRESS|UNDECIDABLE|NO_SINK (function-level)."""
    def verdict(code: str) -> str:
        results = [v for _line, v in per_call(spec, code)]
        if not results:
            return NO_SINK
        if FLAG in results:
            return FLAG
        return UNDECIDABLE if UNDECIDABLE in results else SUPPRESS

    return verdict


if __name__ == "__main__":
    spec = {"kind": "taint_sink", "sink_names": ["find", "find_one"], "lang": "python"}
    d = make_detector(spec)
    print("routed param ->", d("@app.route('/u/<name>')\ndef v(name):\n    db.users.find({'n': name})\n"))
    print("request.args ->", d("def v():\n    q = request.args.get('q')\n    db.c.find({'a': q})\n"))
    print("constant     ->", d("def v():\n    db.c.find({'a': 'literal'})\n"))
    print("unknown      ->", d("def helper(x):\n    db.c.find({'a': x})\n"))
    print("no sink      ->", d("print('hello')\n"))
