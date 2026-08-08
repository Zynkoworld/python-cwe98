"""ssrf_sinks_i1 — concorde's SSRF sink catalogue (CWE-918), derived from what the APIs DO.

Written after a measured gap, and the way it is written is the point. On 2026-07-25 concorde's
independent taint motor scored 28/80 on the corrected CWE-918 oracle set, and 50 of the 52 misses
were one cause: Azure SDK entry points that take a caller-supplied service URL are not HTTP verbs,
so a generic get/post/urlopen list never sees them.

The temptation is to add exactly the five symbols the oracle's test file flags. That would raise the
number and prove nothing — it is fitting, and the next unseen file would miss again. So this
catalogue encodes FAMILIES, defined by what the API does, and each family deliberately includes
members the oracle's test file never exercises. If the list only ever contains what was already
measured, it is a transcript of the answer key, not knowledge.

The families, and why each is an SSRF sink — every one of them takes a URL from the caller and
performs (or configures) an outbound request to it:

  HTTP_VERBS        requests / httpx / aiohttp style verbs and the generic `request`.
  URL_OPENERS       urllib's urlopen/urlretrieve and http.client's `request` on a connection.
  AZURE_SERVICE_URL Azure SDK clients constructed FROM a service URL. Key Vault's clients take
                    `vault_url`; storage's `from_*_url` factories take a resource URL. Present here
                    but absent from the oracle's file: CertificateClient, BlobClient.from_blob_url,
                    BlobServiceClient.from_..., QueueClient.from_queue_url, upload_blob_to_url.
  URL_HELPERS       module-level helpers that take a URL and move bytes.

Scope note kept honest: this is a NAME catalogue, so it says nothing about whether a given call is
actually reachable from untrusted input — that is the taint motor's job, and a name on this list is
a sink candidate, not a finding.
"""
from __future__ import annotations

#: requests / httpx / aiohttp verbs, plus the generic dispatcher. Matched on the called NAME, so
#: `requests.get`, `session.get` and `client.get` are all covered.
HTTP_VERBS = (
    "get", "post", "put", "delete", "head", "patch", "options", "request",
)

#: stdlib URL openers. `request` above already covers http.client's conn.request.
URL_OPENERS = (
    "urlopen", "urlretrieve", "urlcleanup",
)

#: Azure SDK entry points constructed from a caller-supplied service URL. Key Vault clients take a
#: vault_url; storage exposes `from_*_url` factories. Members marked (+) are NOT in the oracle's
#: test file and are here because the family says so, not because a measurement asked for them.
AZURE_SERVICE_URL = (
    "SecretClient", "KeyClient", "CertificateClient",            # (+) CertificateClient
    "from_file_url", "from_container_url", "from_blob_url",      # (+) from_blob_url
    "from_queue_url", "from_share_url", "from_directory_url",    # (+) all three
    "from_connection_string",                                    # (+) endpoint comes from the string
)

#: Module-level helpers that take a URL and transfer data.
URL_HELPERS = (
    "download_blob_from_url", "upload_blob_to_url",              # (+) upload_blob_to_url
)

#: The full sink-name set the taint motor is given for CWE-918.
SSRF_SINKS = tuple(sorted(set(HTTP_VERBS + URL_OPENERS + AZURE_SERVICE_URL + URL_HELPERS)))

#: Family membership, for a report that wants to say WHICH family caught a cell.
FAMILIES = {
    "http_verbs": HTTP_VERBS,
    "url_openers": URL_OPENERS,
    "azure_service_url": AZURE_SERVICE_URL,
    "url_helpers": URL_HELPERS,
}


def spec(lang: str = "python") -> dict:
    """A taint_sink spec for CWE-918 built from this catalogue.

    Not a replacement for zynko's derived spec (kind semgrep_pattern) — that one describes what
    semgrep's rules match. This is concorde's own sink model, which is what makes the arm
    independent rather than a re-implementation of the other oracle.
    """
    return {"kind": "taint_sink", "cwe": "CWE-918", "lang": lang,
            "sink_names": list(SSRF_SINKS),
            "provenance": "concorde ssrf_sinks_i1 — API families, not oracle labels"}


def family_of(name: str) -> str:
    for fam, names in FAMILIES.items():
        if name in names:
            return fam
    return "unknown"
