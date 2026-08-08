"""hardcoded_credential_i1 — concorde's detector for hardcoded credentials (CWE-798).

Two questions, and only the second one is hard:

1. IS THIS VALUE USED AS A CREDENTIAL? Answered by where it goes — a keyword argument named
   `password`, `token`, `api_key`, `username` and so on. A constant assigned to a module-level name
   and then passed to one of those is the shape the class is about, so the value is followed from the
   assignment to the call.

2. IS THIS STRING ACTUALLY A SECRET? A string literal in a credential position is not automatically
   a credential: source is full of placeholders, examples and format templates, and flagging those
   makes the detector useless in exactly the codebases that matter.

WHAT THIS FILE CLAIMS, and what it does not. The shape rules below are derived from what
distinguishes a SECRET from a WORD, not from any oracle's answer key:

  · a secret is long enough to be one — a four-character string is a placeholder;
  · a secret is not a dictionary word or a Capitalized word, because those are chosen by people to
    read as examples;
  · a secret has no surrounding whitespace — nobody types a password with a leading space;
  · a secret is not a repetition (`aaaaaaaaaa`) and does not end in filler underscores
    (`insecure__`), because both are how humans write "put the real thing here";
  · a secret is not a FORMAT TEMPLATE, and the test is about the placeholder's CONTENT: empty, an
    index, or a field name with an optional spec. Random punctuation between braces is not a
    placeholder. This distinction is load-bearing, and it took a measurement to find: the oracle's
    own corpus carries a 100-character random credential with the comment "TODO: we think this is a
    format string :\\" — a false negative its author flags as a bug — and that string contains
    `{E*2=`;3]G~k&+;khy3}`, a brace pair with no whitespace. A "no whitespace inside" rule therefore
    reproduces the oracle's bug exactly, which is what the first draft of this file did while its
    docstring claimed the opposite.

So on that one line this detector DISAGREES with the oracle, in the direction the oracle's author
calls a bug. The snapshot records it as an acknowledged false negative rather than scoring it as
either arm's error.
"""
from __future__ import annotations

import ast
import re

#: Keyword names that put a value in a credential position.
CREDENTIAL_KEYWORDS = (
    "password", "passwd", "pwd", "passphrase",
    "secret", "secret_key", "client_secret", "api_key", "apikey", "access_key",
    "token", "auth_token", "access_token", "refresh_token", "bearer",
    "username", "user", "userid", "login",
    "private_key", "credential", "credentials",
)

#: Minimum length for a string to be a plausible secret rather than a placeholder.
MIN_LENGTH = 6

#: A format template placeholder. The CONTENT is what makes it one: empty, an index, or a field
#: name with an optional conversion/format spec — never random punctuation.
#:
#: The first draft asked only for "a balanced brace pair with no whitespace", which the oracle's own
#: 100-character random credential satisfies by accident (it contains `{E*2=`;3]G~k&+;khy3}`). So the
#: detector reproduced the oracle's acknowledged false negative while this module's docstring claimed
#: it did not — the measurement contradicted the prose, and the prose was the part that was wrong.
_FORMAT_PLACEHOLDER = re.compile(
    r"\{\s*"                                  # opening brace
    r"(?:[A-Za-z_]\w*|\d+)?"                   # a field name or an index, or nothing
    r"(?:\.[A-Za-z_]\w*|\[[^\]]*\])*"          # attribute / item access
    r"(?:![rsa])?"                             # conversion
    r"(?::[^{}]*)?"                            # format spec
    r"\s*\}")

#: Filler tails people write instead of a value.
_FILLER_TAIL = re.compile(r"[_\-.]{2,}$")


def looks_like_secret(value: str) -> tuple:
    """(verdict, reason). True only when nothing says "this is a placeholder"."""
    if not isinstance(value, str):
        return False, "not a string"
    if len(value) < MIN_LENGTH:
        return False, "shorter than %d characters — a placeholder, not a secret" % MIN_LENGTH
    if value != value.strip():
        return False, "surrounded by whitespace; nobody types a credential that way"
    if _FORMAT_PLACEHOLDER.search(value):
        return False, "contains a format placeholder, so the value is filled in elsewhere"
    if _FILLER_TAIL.search(value):
        return False, "ends in filler punctuation — the human way of writing 'real value here'"
    if len(set(value)) <= 2:
        return False, "a repetition of %d distinct character(s)" % len(set(value))
    if value[:1].isupper() and value[1:].islower() and value.isalpha():
        return False, "a Capitalized dictionary word, which is how examples are written"
    return True, "long enough, mixed, unpadded and not a template"


def _keyword_positions(call: ast.Call) -> list:
    """[(keyword_name, value_node)] for every credential-named keyword in this call."""
    out = []
    for kw in call.keywords:
        if kw.arg and kw.arg.lower() in CREDENTIAL_KEYWORDS:
            out.append((kw.arg, kw.value))
    return out


def _constant_bindings(tree: ast.AST) -> dict:
    """name -> (literal, line) for every string constant assigned to a bare name."""
    out = {}
    for stmt in (n for n in ast.walk(tree) if isinstance(n, ast.Assign)):
        if not (isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str)):
            continue
        for tgt in stmt.targets:
            if isinstance(tgt, ast.Name):
                out[tgt.id] = (stmt.value.value, getattr(stmt, "lineno", 0))
    return out


def per_call(spec: dict, code: str) -> list:
    """[(lineno, FLAG)] at the line where the credential VALUE is written.

    The line matters: the oracle points at the assignment (`PASSWORD = "..."`), not at the call that
    consumes it, because that is where the secret enters the source and where it has to be removed.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []
    bindings = _constant_bindings(tree)
    out = []
    for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
        for _name, node in _keyword_positions(call):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                literal, line = node.value, getattr(node, "lineno", 0)
            elif isinstance(node, ast.Name) and node.id in bindings:
                literal, line = bindings[node.id]
            else:
                continue
            ok, _why = looks_like_secret(literal)
            if ok:
                out.append((line, "FLAG"))
    return sorted(set(out))


def make_detector(spec: dict):
    def verdict(code: str) -> str:
        return "FLAG" if per_call(spec, code) else "OUT_OF_SCOPE"
    return verdict


def spec(lang: str = "python") -> dict:
    return {"kind": "credential_literal", "cwe": "CWE-798", "lang": lang,
            "credential_keywords": list(CREDENTIAL_KEYWORDS),
            "min_length": MIN_LENGTH,
            "provenance": "concorde hardcoded_credential_i1 — a credential POSITION plus a "
                          "secret-SHAPE test derived from what separates a secret from a word"}
