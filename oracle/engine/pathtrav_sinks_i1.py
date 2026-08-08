"""pathtrav_sinks_i1 — concorde's path-traversal sink catalogue (CWE-22).

Same discipline as ssrf_sinks_i1, and for the same reason: a list that contains exactly the symbols
the oracle's test file uses is a transcript of the answer key, and the next unseen file misses. So
these are FAMILIES defined by what the API does with a path, and each carries members the oracle's
files never exercise.

A path-traversal sink is any API that RESOLVES a caller-supplied path against the filesystem. The
danger is not reading or writing per se — it is that `../` in the path escapes the intended root.

  FILE_OPEN        opening a file by name, in any of the stdlib's spellings.
  PATH_READ_WRITE  pathlib's read/write shorthands, which open and act in one call.
  FS_MUTATE        operations that create, move, delete or re-permission a path.
  FS_INSPECT       operations that reveal a path's existence or contents. Weaker impact than the
                   others, but the traversal is identical and disclosure is the classic use.
  SERVE_FILE       framework helpers that turn a path into an HTTP response body — the shape that
                   makes CWE-22 remotely exploitable.
  ARCHIVE_EXTRACT  extraction, where the traversal comes from the ARCHIVE's member names (zip-slip
                   and tar-slip). Present because the CWE is the same even though the untrusted
                   input arrives by a different route.

NEUTRALIZERS are the mirror question — what actually removes the traversal, rather than what merely
looks defensive. `basename` discards every directory component; `secure_filename` and `safe_join`
exist for this; a realpath/commonpath containment check confines the result to a root. Deliberately
NOT here: `replace("../", "")`, which is defeated by `....//`, and bare `abspath`, which normalises
without confining.
"""
from __future__ import annotations

FILE_OPEN = (
    "open", "fdopen",                                   # builtins / os
    "opener",                                           # (+) io helpers
)

PATH_READ_WRITE = (
    "read_text", "write_text", "read_bytes", "write_bytes",
    "touch",                                            # (+) pathlib
)

FS_MUTATE = (
    "remove", "unlink", "rename", "replace", "rmdir", "mkdir", "makedirs", "removedirs",
    "chmod", "chown", "symlink", "link", "truncate",    # (+) symlink, link, truncate
    "copy", "copy2", "copyfile", "copytree", "move", "rmtree",
)

FS_INSPECT = (
    "stat", "lstat", "listdir", "scandir", "walk", "glob", "iglob",   # (+) scandir, iglob
    "exists", "isfile", "isdir", "getsize",                           # (+) all four
)

SERVE_FILE = (
    "send_file", "send_from_directory", "FileResponse", "static_file",
    "send_static_file", "serve",                        # (+) send_static_file, serve
)

#: Sinks that CONFINE their later arguments to a root given in the first N. Neither a plain sink nor
#: a plain neutraliser: send_from_directory(STATIC_DIR, filename) is safe, and
#: send_from_directory(dirname, filename) with an attacker-controlled dirname is not. Listing it as
#: a sanitizer lost that second cell; listing it as a sink flagged the first. The root is what
#: decides, so the root is what gets checked.
CONFINING_SINKS = {"send_from_directory": 1, "safe_join": 1, "send_static_file": 1}

ARCHIVE_EXTRACT = (
    "extract", "extractall",
)

#: What genuinely removes a traversal, as opposed to what merely looks careful.
NEUTRALIZERS = (
    "basename", "secure_filename",
    "commonpath", "commonprefix", "relative_to",        # containment checks
)

PATHTRAV_SINKS = tuple(sorted(set(
    FILE_OPEN + PATH_READ_WRITE + FS_MUTATE + FS_INSPECT + SERVE_FILE + ARCHIVE_EXTRACT)))

FAMILIES = {
    "file_open": FILE_OPEN,
    "path_read_write": PATH_READ_WRITE,
    "fs_mutate": FS_MUTATE,
    "fs_inspect": FS_INSPECT,
    "serve_file": SERVE_FILE,
    "archive_extract": ARCHIVE_EXTRACT,
}


def spec(lang: str = "python") -> dict:
    """A taint_sink spec for CWE-22 built from this catalogue — concorde's own sink model."""
    return {"kind": "taint_sink", "cwe": "CWE-22", "lang": lang,
            "sink_names": list(PATHTRAV_SINKS),
            "sanitizers": list(NEUTRALIZERS),
            # A prefix check confines a path ONLY if the path was normalised first; neither half
            # alone is a guard, which is the pair the CWE-22 oracle draws.
            "confining_sinks": dict(CONFINING_SINKS),
            "containment_guards": ["startswith"],
            "path_normalizers": ["normpath", "realpath", "abspath"],
            "provenance": "concorde pathtrav_sinks_i1 — API families, not oracle labels"}


def serve_file_spec(cwe: str = "CWE-73", lang: str = "python") -> dict:
    """The SERVE-FILE half of this catalogue, as its own cell.

    CWE-73 (external control of a file name or path) and CWE-22 (path traversal) overlap but are not
    the same question: CWE-22 asks whether `../` can escape a root, CWE-73 asks whether the caller
    chose the path at all. In a web application the second lands almost entirely on the file-serving
    helpers, so this narrows the catalogue to those and keeps the confinement rule — which is what
    separates `send_file(user_path)` from `send_from_directory(STATIC_DIR, user_path)`.
    """
    return {"kind": "taint_sink", "cwe": cwe, "lang": lang,
            "sink_names": list(SERVE_FILE),
            "sanitizers": list(NEUTRALIZERS),
            "confining_sinks": dict(CONFINING_SINKS),
            "containment_guards": ["startswith"],
            "path_normalizers": ["normpath", "realpath", "abspath"],
            "provenance": "concorde pathtrav_sinks_i1.serve_file_spec — the file-serving family, "
                          "where external control of a path lands in a web application"}


def family_of(name: str) -> str:
    for fam, names in FAMILIES.items():
        if name in names:
            return fam
    return "unknown"
