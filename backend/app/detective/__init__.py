"""
detective.py package - "detective mindset" checks: pure-Python, zero-new-binary
vulnerability detectors that don't need a CLI tool (unlike tools.py, which
shells out to subfinder/nuclei/etc.).

This used to be a single ~8,900 line detective.py file. It is now split by
vulnerability category into submodules for maintainability:
  - shared.py         shared helpers/constants (logger, timeout, hostname/URL
                       validation, entropy calc)
  - injection.py       SQLi, SSTI, XXE, LDAP/XPath injection, command injection,
                       prototype pollution, NoSQL injection, LFI/traversal, etc.
  - ssrf.py            reflected/blind SSRF, cloud metadata credential theft
  - auth_access.py     JWT, CORS, CSRF, IDOR, verb tampering, mass assignment,
                       session/cookie handling, admin panel access, API keys
  - cloud_storage.py   S3/Azure bucket and Firebase exposure
  - client_side.py     XSS variants, clickjacking, insecure upload
  - infra_exposure.py  leaked config/CI files, debug endpoints, exposed DB/dev
                       tool admin consoles, backup/dump files, missing headers
  - recon_misc.py      subdomain takeover, cache deception/poisoning, WAF
                       fingerprinting, GraphQL introspection, open redirect,
                       websocket downgrade/CSWSH, weak TLS, business-logic recon

Every function is read-only / non-destructive - no writes, no exploitation,
just detection. Each returns None when nothing is found, or a dict describing
the finding when something is. Callers (pipeline.py) decide what to do with
that.

All checks are re-exported at package level, so existing call sites
(`detective.check_foo(...)`) are unaffected by this split.
"""

from .shared import (
    logger,
    _TIMEOUT,
    _MAX_REASONABLE_URL_LENGTH,
    _extract_hostname,
    _looks_like_sane_url,
    _shannon_entropy,
    _replace_query_param,
)
from .injection import *  # noqa: F401,F403
from .ssrf import *  # noqa: F401,F403
from .auth_access import *  # noqa: F401,F403
from .cloud_storage import *  # noqa: F401,F403
from .client_side import *  # noqa: F401,F403
from .infra_exposure import *  # noqa: F401,F403
from .recon_misc import *  # noqa: F401,F403
