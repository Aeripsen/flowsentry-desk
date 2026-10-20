"""Who is the analyst: Clerk sign-in behind a flag, an anonymous browser workspace otherwise.

DESK_AUTH=clerk turns sign-in on. It needs CLERK_PUBLISHABLE_KEY (the browser loads Clerk
from the Frontend API encoded in it) and verifies each request's session token itself:
RS256 signature against Clerk's JWKS (or CLERK_JWT_KEY, a PEM public key, with no network
call), exp and nbf, and azp against DESK_ALLOWED_ORIGINS. The workspace is the Clerk user id.

Without it, each browser gets a random workspace id in an HttpOnly cookie, so judges can
each work their own copy of the queue.
"""
from __future__ import annotations

import base64
import hashlib
import os
import secrets
from dataclasses import dataclass
from functools import lru_cache

COOKIE = "desk_ws"


@dataclass(frozen=True)
class Analyst:
    workspace: str
    kind: str          # "clerk" or "anon"
    actor: str         # what the audit log records


def clerk_enabled() -> bool:
    return os.environ.get("DESK_AUTH", "anon").strip().lower() == "clerk"


def publishable_key() -> str | None:
    return os.environ.get("CLERK_PUBLISHABLE_KEY") or None


def frontend_api(pk: str | None = None) -> str | None:
    """pk_test_<base64(frontend-api + '$')> -> frontend-api host."""
    pk = pk or publishable_key()
    if not pk or not pk.startswith(("pk_test_", "pk_live_")):
        return None
    raw = pk.split("_", 2)[2]
    raw += "=" * (-len(raw) % 4)
    try:
        host = base64.b64decode(raw).decode().rstrip("$")
    except (ValueError, UnicodeDecodeError):
        return None
    return host or None


def allowed_origins() -> list[str]:
    return [o.strip() for o in os.environ.get("DESK_ALLOWED_ORIGINS", "").split(",") if o.strip()]


@lru_cache(maxsize=1)
def _jwks_client():
    import jwt

    host = frontend_api()
    if not host:
        raise RuntimeError("CLERK_PUBLISHABLE_KEY is missing or malformed")
    return jwt.PyJWKClient(f"https://{host}/.well-known/jwks.json", cache_keys=True)


class AuthError(Exception):
    pass


def verify_clerk_token(token: str, key=None) -> dict:
    """Return the token's claims or raise AuthError. `key` is for tests."""
    import jwt

    try:
        if key is None:
            pem = os.environ.get("CLERK_JWT_KEY")
            key = pem.replace("\\n", "\n") if pem else _jwks_client().get_signing_key_from_jwt(
                token).key
        claims = jwt.decode(token, key, algorithms=["RS256"],
                            options={"require": ["exp", "nbf", "sub"], "verify_aud": False},
                            leeway=5)
    except Exception as e:  # any failure is a 401, with no detail leaked to the client
        raise AuthError("invalid session token") from e
    azp = claims.get("azp")
    origins = allowed_origins()
    if azp and origins and azp not in origins:
        raise AuthError("token issued for another origin")
    if claims.get("sts") == "pending":
        raise AuthError("session pending")
    return claims


def from_request(headers: dict, cookies: dict) -> tuple[Analyst | None, str | None]:
    """(analyst, new_cookie_value). Raises AuthError when Clerk is on and the token is bad."""
    if clerk_enabled():
        h = headers.get("authorization", "")
        token = h[7:] if h.lower().startswith("bearer ") else cookies.get("__session")
        if not token:
            raise AuthError("sign in first")
        c = verify_clerk_token(token)
        return Analyst(workspace=f"clerk:{c['sub']}", kind="clerk", actor=c["sub"]), None
    tok = cookies.get(COOKIE)
    new = None
    if not tok or len(tok) < 20:
        tok = secrets.token_urlsafe(24)
        new = tok
    ws = "anon:" + hashlib.sha256(tok.encode()).hexdigest()[:20]
    return Analyst(workspace=ws, kind="anon", actor="analyst"), new
