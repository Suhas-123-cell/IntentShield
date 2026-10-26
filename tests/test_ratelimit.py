from fastapi.testclient import TestClient

from intentshield.api import create_app
from intentshield.ratelimit import RateLimiter


def test_bucket_allows_burst_then_refuses_per_client():
    limiter = RateLimiter(per_minute=2)
    assert limiter.allow("a") and limiter.allow("a")
    assert not limiter.allow("a")
    assert limiter.allow("b")


def test_api_returns_429_when_limit_exceeded(tmp_path, monkeypatch):
    monkeypatch.setenv("INTENTSHIELD_RATE_LIMIT_PER_MIN", "2")
    with TestClient(create_app(tmp_path / "rl.db")) as client:
        codes = [client.get("/api/security/status").status_code for _ in range(3)]
        assert codes[-1] == 429
        assert client.get("/health").status_code == 200


def test_rate_limit_can_be_disabled(tmp_path, monkeypatch):
    monkeypatch.setenv("INTENTSHIELD_RATE_LIMIT_PER_MIN", "0")
    with TestClient(create_app(tmp_path / "rl.db")) as client:
        assert all(client.get("/api/security/status").status_code == 200 for _ in range(5))


def test_flooding_new_keys_does_not_reset_a_throttled_client():
    limiter = RateLimiter(per_minute=1, burst=2, max_clients=100)
    assert limiter.allow("throttled") and limiter.allow("throttled")
    assert not limiter.allow("throttled")
    for i in range(1_000):
        limiter.allow(f"spoofed-{i}")
    assert len(limiter._buckets) <= 100
    assert not limiter.allow("throttled")
