"""injection_sinks_i1 — concorde's sink catalogues for the injection family (CWE-78/90/94/502/611/79).

Same discipline as ssrf_sinks_i1 and pathtrav_sinks_i1: FAMILIES defined by what the API does, each
carrying members the oracle's test files never exercise, so the list is knowledge rather than a
transcript of an answer key.

One catalogue per class, because the dangerous operation differs and so does what neutralises it:

  CWE-78  command execution — the payload is a SHELL STRING. A list argv is not a shell string, so
          the same function is a sink or not depending on how it is called; that distinction lives
          in the taint motor, not in a name list.
  CWE-90  LDAP search — the payload is a FILTER or DN. Neutralised by the escaping functions the
          LDAP libraries provide for exactly this.
  CWE-94  code execution — the payload is SOURCE. ast.literal_eval is the safe counterpart and is
          therefore a neutraliser, not a sink.
  CWE-502 deserialization — the payload is a SERIALISED OBJECT that can carry executable state.
          yaml.safe_load and json.loads cannot, so they are not sinks; yaml.load without a safe
          Loader can.
  CWE-611 XML parsing — the danger is ENTITY RESOLUTION, not the parse. defusedxml exists to turn it
          off, and a parser configured with resolve_entities=False is neutralised.
  CWE-79  cross-site scripting — the payload reaches an HTTP RESPONSE. The honest note is that the
          dominant shape is a view's RETURN value rather than a call, which a name catalogue cannot
          express; what is here covers the call-shaped half only.
"""
from __future__ import annotations

# ── CWE-78: command execution ───────────────────────────────────────────────────────────────────
CMD_SHELL = ("system", "popen", "popen2", "popen3", "popen4")          # (+) popen2/3/4
CMD_SPAWN = ("call", "run", "check_output", "check_call", "Popen",
             "spawn", "spawnl", "spawnv", "spawnve", "execl", "execv")  # (+) spawn*/exec* family
CMD_HELPERS = ("getoutput", "getstatusoutput")
CMD_SINKS = tuple(sorted(set(CMD_SHELL + CMD_SPAWN + CMD_HELPERS)))
CMD_NEUTRALIZERS = ("quote", "list2cmdline", "shlex_quote")

# ── CWE-90: LDAP injection ──────────────────────────────────────────────────────────────────────
LDAP_SINKS = ("search", "search_s", "search_st", "search_ext", "search_ext_s",
              "modify_s", "delete_s", "compare_s")                      # (+) modify/delete/compare
LDAP_NEUTRALIZERS = ("escape_filter_chars", "escape_dn_chars", "escape_rdn", "escape_dn")

# ── CWE-94: code injection ──────────────────────────────────────────────────────────────────────
CODE_SINKS = ("eval", "exec", "execfile", "compile", "__import__", "runsource", "runcode")
CODE_NEUTRALIZERS = ("literal_eval",)

# ── CWE-502: unsafe deserialization ─────────────────────────────────────────────────────────────
#: `load`/`loads` are the dangerous spellings; the SAFE counterparts below are not sinks at all.
DESER_SINKS = ("loads", "load", "Unpickler", "unpickle", "load_all",     # (+) Unpickler, load_all
               "from_yaml", "recv_object", "read_pickle")               # (+) pandas.read_pickle
DESER_NEUTRALIZERS = ("safe_load", "safe_load_all", "SafeLoader", "literal_eval")

# ── CWE-611: XXE ────────────────────────────────────────────────────────────────────────────────
XML_SINKS = ("parse", "fromstring", "XML", "iterparse", "parseString",
             "XMLParser", "feed")                                        # (+) XMLParser, feed
XML_NEUTRALIZERS = ("defusedxml", "safe_parse", "DefusedXMLParser", "escape")  # (+) markupsafe.escape

# ── CWE-79: XSS (call-shaped half only) ─────────────────────────────────────────────────────────
XSS_SINKS = ("render_template_string", "HttpResponse", "Response", "Markup", "mark_safe",
             "make_response", "write", "send", "set_data")               # (+) make_response, set_data
XSS_NEUTRALIZERS = ("escape", "escape_html", "conditional_escape", "format_html", "striptags",
                    "bleach", "clean")

CATALOGUE = {
    "CWE-77": (CMD_SINKS, CMD_NEUTRALIZERS),   # generic command injection — same sinks as CWE-78
    "CWE-78": (CMD_SINKS, CMD_NEUTRALIZERS),
    "CWE-90": (LDAP_SINKS, LDAP_NEUTRALIZERS),
    "CWE-94": (CODE_SINKS, CODE_NEUTRALIZERS),
    "CWE-502": (DESER_SINKS, DESER_NEUTRALIZERS),
    "CWE-611": (XML_SINKS, XML_NEUTRALIZERS),
    "CWE-79": (XSS_SINKS, XSS_NEUTRALIZERS),
}


def spec(cwe: str, lang: str = "python") -> dict:
    """A taint_sink spec for `cwe` from this catalogue — concorde's own model, not a rule reading."""
    sinks, neutralizers = CATALOGUE[cwe]
    s = {"kind": "taint_sink", "cwe": cwe, "lang": lang,
         "sink_names": list(sinks), "sanitizers": list(neutralizers),
         "provenance": "concorde injection_sinks_i1 — API families, not oracle labels"}
    # XSS: a response served with a NON-HTML Content-Type (application/json, ...) is not rendered as
    # HTML, so a tainted body cannot execute. General XSS fact, gated to CWE-79 so no other cell shifts.
    if cwe == "CWE-79":
        s["content_type_safe"] = True
    # CWE-502: yaml.load(x, Loader=SafeLoader) cannot construct arbitrary objects, so the safe-Loader
    # kwarg neutralises the load. Gated to CWE-502; pickle/marshal/dill take no Loader so are unaffected.
    if cwe == "CWE-502":
        s["deser_safe_loader"] = True
    # CWE-611: a parse with parser=XMLParser(resolve_entities=False) cannot expand external entities.
    if cwe == "CWE-611":
        s["xml_parser_safe"] = True
    # CWE-434: the injection is the PATH argument of open/save, not the tainted file-object receiver.
    if cwe == "CWE-434":
        s["ignore_receiver_taint"] = True
    # CWE-78: the subprocess family is a shell-injection sink ONLY with shell=True; the list-argv form
    # (subprocess.run(['ls', x])) execs directly with no shell, so it is not a command-injection sink.
    if cwe in ("CWE-78", "CWE-77"):
        s["shell_required_sinks"] = ["run", "call", "check_call", "check_output", "Popen"]
    # CWE-89: only arg0 (the SQL string) is the injection surface; a tainted params arg is bound.
    if cwe == "CWE-89":
        s["sink_taint_args"] = {name: [0] for name in SQL_STRING_ARG0}
    return s


# ── CWE-89: SQL injection ───────────────────────────────────────────────────────────────────────
#: Executing a statement the caller supplied as a STRING. The safety question for SQL is structural
#: rather than lexical — a parameterised query is safe no matter what the parameters contain — so
#: this list names the execution points and leaves the string/parameter distinction to the taint
#: motor, which can see whether the argument was CONCATENATED from untrusted data or is a literal.
SQL_EXECUTE = ("execute", "executemany", "executescript", "executescript_many",   # (+) last one
               "execute_many", "exec_driver_sql")                                  # (+) both
#: Django's escape hatches out of the ORM: each takes SQL or a SQL fragment directly.
SQL_DJANGO_RAW = ("raw", "extra", "RawSQL", "annotate_raw")                        # (+) annotate_raw
#: SQLAlchemy's textual constructs.
SQL_SQLALCHEMY = ("text", "from_statement", "literal_column", "column")            # (+) last two
SQL_SINKS = tuple(sorted(set(SQL_EXECUTE + SQL_DJANGO_RAW + SQL_SQLALCHEMY)))
#: Name-based neutralisers are thin here, and saying so is more useful than padding the list:
#: real SQL safety is parameter BINDING, which is a shape rather than a call.
SQL_NEUTRALIZERS = ("quote_identifier", "quote", "escape_string", "bindparams", "params")

CATALOGUE["CWE-89"] = (SQL_SINKS, SQL_NEUTRALIZERS)

# ── CWE-98: RFI / dynamic module import from an untrusted name ─────────────────────────────────────
#: importlib.import_module(user) / __import__(user) runs the named module's top-level code, so an
#: attacker-controlled module name is code execution. A named validator is the neutraliser.
RFI_SINKS = ("import_module", "__import__")
RFI_NEUTRALIZERS = ("validate_module",)
CATALOGUE["CWE-98"] = (RFI_SINKS, RFI_NEUTRALIZERS)

# ── CWE-1236: CSV/formula injection ───────────────────────────────────────────────────────────────
#: user data written to a CSV cell can be interpreted as a FORMULA (a leading =/+/-/@) by a spreadsheet.
#: The runtime prefix is invisible to a static motor, so the model is conservative: untrusted -> a CSV
#: writer is a finding unless a formula-neutraliser wrapped it.
CSV_SINKS = ("writerow", "writerows")
CSV_NEUTRALIZERS = ("escape_formula", "sanitize_formula", "neutralize_formula")
CATALOGUE["CWE-1236"] = (CSV_SINKS, CSV_NEUTRALIZERS)

# ── CWE-434: unrestricted file upload ─────────────────────────────────────────────────────────────
#: an uploaded file's own FILENAME used as the save PATH lets the attacker choose where/what is written.
#: The dangerous position is the PATH argument (not the file-object receiver), and secure_filename is the
#: standard neutraliser.
UPLOAD_SINKS = ("open", "save")
UPLOAD_NEUTRALIZERS = ("secure_filename",)
CATALOGUE["CWE-434"] = (UPLOAD_SINKS, UPLOAD_NEUTRALIZERS)

#: For the execution sinks, only the FIRST argument is the SQL STRING — the injection surface. A
#: tainted value passed as the SEPARATE params argument (`execute(sql, [param])`, `execute(sql,
#: {'k': param})`) is BOUND by the driver and is the canonical SAFE spelling; flagging it calls
#: every parameterised query a finding. So taint is checked at position 0 only for these. The
#: string/parameter distinction the class docstring defers to the motor lives exactly here.
SQL_STRING_ARG0 = ("execute", "executemany", "executescript", "execute_many", "exec_driver_sql",
                   "raw", "RawSQL", "text", "from_statement")
