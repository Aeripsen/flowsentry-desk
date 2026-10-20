"""Clerk session tokens are verified on the server: signature, expiry, origin."""
import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from desk import auth


@pytest.fixture(scope="module")
def keys():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return k, k.public_key()


def tok(priv, **over):
    now = int(time.time())
    claims = {"sub": "user_123", "exp": now + 60, "nbf": now - 5, "iat": now - 5,
              "azp": "https://desk.example", **over}
    return jwt.encode(claims, priv, algorithm="RS256")


def test_valid_token(keys, monkeypatch):
    monkeypatch.setenv("DESK_ALLOWED_ORIGINS", "https://desk.example")
    c = auth.verify_clerk_token(tok(keys[0]), key=keys[1])
    assert c["sub"] == "user_123"


def test_expired_token(keys):
    with pytest.raises(auth.AuthError):
        auth.verify_clerk_token(tok(keys[0], exp=int(time.time()) - 120), key=keys[1])


def test_wrong_origin(keys, monkeypatch):
    monkeypatch.setenv("DESK_ALLOWED_ORIGINS", "https://desk.example")
    with pytest.raises(auth.AuthError):
        auth.verify_clerk_token(tok(keys[0], azp="https://evil.example"), key=keys[1])


def test_wrong_key_and_garbage(keys):
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(auth.AuthError):
        auth.verify_clerk_token(tok(other), key=keys[1])
    with pytest.raises(auth.AuthError):
        auth.verify_clerk_token("not.a.token", key=keys[1])


def test_hs256_downgrade_is_refused(keys):
    t = jwt.encode({"sub": "x", "exp": int(time.time()) + 60, "nbf": 0}, "s" * 40,
                   algorithm="HS256")
    with pytest.raises(auth.AuthError):
        auth.verify_clerk_token(t, key=keys[1])


def test_frontend_api_from_publishable_key():
    pk = "pk_test_" + base64.b64encode(b"happy-otter-12.clerk.accounts.dev$").decode().rstrip("=")
    assert auth.frontend_api(pk) == "happy-otter-12.clerk.accounts.dev"
    assert auth.frontend_api("sk_test_nope") is None


def test_clerk_mode_requires_a_token(monkeypatch):
    monkeypatch.setenv("DESK_AUTH", "clerk")
    with pytest.raises(auth.AuthError):
        auth.from_request({}, {})


def test_anon_mode_issues_a_workspace():
    a, cookie = auth.from_request({}, {})
    assert a.kind == "anon" and cookie and a.workspace.startswith("anon:")
    a2, c2 = auth.from_request({}, {auth.COOKIE: cookie})
    assert a2.workspace == a.workspace and c2 is None
