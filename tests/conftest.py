import os

import pytest

# never let a developer's real keys or flags change what the tests exercise
for k in ("ANTHROPIC_API_KEY", "DESK_PROVIDER", "DESK_LIVE_AGENT", "DESK_AUTH", "DESK_ENV_FILE",
          "CLERK_PUBLISHABLE_KEY", "CLERK_JWT_KEY", "DESK_ALLOWED_ORIGINS"):
    os.environ.pop(k, None)
os.environ["DESK_DB_PATH"] = ":memory:"


@pytest.fixture(scope="session")
def b():
    from desk.store import load

    return load()


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient

    from desk import app as appmod
    from desk.db import DB

    appmod.set_db(DB(":memory:"))
    return TestClient(appmod.app)
