"""open_redirect_i1 — concorde's catalogue for open redirect (CWE-601).

The sink is easy and the GUARDS are the whole class. A redirect is safe exactly when the
DESTINATION HOST is not attacker-controlled, and there are several genuinely different ways to
establish that — each with a precondition that is easy to get wrong and is what real bypasses
exploit.

WHAT FIXES THE DESTINATION:

1. A CONSTANT PREFIX that already contains the host. `"https://safe.com/" + user` cannot leave
   safe.com, whatever `user` is. The prefix has to come FIRST: `user + "?login=success"` fixes
   nothing, because the host is still whatever the user wrote. This holds identically for `+`,
   `+=`, `.format()`, f-strings and `%` — the operator is irrelevant, the ORDER is what matters.
   (CodeQL's own query gets the `+` forms right and flags the format/f-string/% ones; its corpus
   marks those three `$ SPURIOUS: Alert # FP`, i.e. the query author states they are the query's
   false positives.)

2. A HOST ALLOWLIST CHECK. `urlparse(url).netloc` empty means the URL is relative;
   `not yarl.URL(url).is_absolute()` says the same; Django's
   `url_has_allowed_host_and_scheme(url, allowed_hosts=...)` exists for this question.

   THE PRECONDITION, and it is the actual bug in most hand-rolled versions: a BACKSLASH must be
   normalised to a forward slash first. Browsers treat `\\/evil.com` as `//evil.com`, so
   `urlparse("\\\\/evil.com").netloc` is empty — the check passes and the redirect leaves the site.
   So a netloc or is_absolute check counts as a guard only when the value was backslash-normalised;
   without that it is the vulnerable spelling, and the oracle's corpus draws exactly that pair
   (`/ok8` vs `/not_ok6`, identical but for the `replace`).

   Django's helper is exempt because it handles this itself — which is why it exists.

3. THE CHECK'S POLARITY. `netloc != ""` guarding the redirect is the same check pointed the wrong
   way: it permits exactly the absolute URLs the empty-netloc test excludes. Not a guard.

4. EQUALITY WITH A CONSTANT pins the value completely: after `if target == "example.com/"`, the
   value IS that constant.
"""
from __future__ import annotations

#: Framework redirects. Each takes a destination and sends the user there.
REDIRECT_SINKS = (
    "redirect",                 # flask, django.shortcuts
    "HttpResponseRedirect", "HttpResponsePermanentRedirect",   # (+) django, both
    "RedirectResponse",         # (+) starlette / fastapi
    "redirect_to", "url_for_redirect",                          # (+)
    "send_redirect",            # (+) servlet-style APIs
)

#: Host-allowlist checks, and whether each needs the backslash normalisation to be sound.
#: `requires_normalisation` is the difference between the oracle's `/ok8` and `/not_ok6`.
URL_HOST_GUARDS = {
    "netloc": {"requires_normalisation": True, "polarity": "empty"},
    "is_absolute": {"requires_normalisation": True, "polarity": "negated"},
    "url_has_allowed_host_and_scheme": {"requires_normalisation": False, "polarity": "truthy"},
    "is_safe_url": {"requires_normalisation": False, "polarity": "truthy"},   # (+) older Django name
    "hostname": {"requires_normalisation": True, "polarity": "empty"},        # (+) urlsplit variant
}

#: What normalises the backslash so a host check means what it appears to mean.
URL_NORMALIZERS = ("replace",)

#: A redirect's destination is fixed by a leading constant that already carries scheme-and-host, or
#: that starts an absolute PATH — both leave the attacker no say in where the user lands.
PREFIX_FIXES_DESTINATION = ("://", "/")

NEUTRALIZERS = ("quote", "urlencode", "quote_plus")


def spec(lang: str = "python") -> dict:
    return {"kind": "taint_sink", "cwe": "CWE-601", "lang": lang,
            "sink_names": list(REDIRECT_SINKS),
            "sanitizers": list(NEUTRALIZERS),
            "destination_fixing_prefix": list(PREFIX_FIXES_DESTINATION),
            "url_host_guards": {k: dict(v) for k, v in URL_HOST_GUARDS.items()},
            "url_normalizers": list(URL_NORMALIZERS),
            "constant_equality_guard": True,
            "early_return_guard": True,
            "provenance": "concorde open_redirect_i1 — what fixes the destination HOST, and the "
                          "backslash precondition real bypasses exploit"}
