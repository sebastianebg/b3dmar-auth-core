"""Tests for b3dmar_auth.state — signed state tokens."""

import pytest

from b3dmar_auth.state import (
    StateExpiredError,
    StateInvalidError,
    StateSigner,
    StateSignerConfig,
)


@pytest.fixture
def signer() -> StateSigner:
    return StateSigner(StateSignerConfig(secret_key="test-secret-key", salt="test-salt"))


def test_sign_unsign_roundtrip(signer: StateSigner) -> None:
    data = {"provider": "google", "nonce": "abc123"}
    token = signer.sign(data)
    assert signer.unsign(token) == data


def test_unsign_expired(signer: StateSigner) -> None:
    import time

    token = signer.sign({"x": 1})
    time.sleep(2)
    with pytest.raises(StateExpiredError, match="expired"):
        signer.unsign(token, max_age=1)


def test_unsign_tampered(signer: StateSigner) -> None:
    token = signer.sign({"x": 1})
    with pytest.raises(StateInvalidError, match="invalid"):
        signer.unsign(token + "tampered")


def test_unsign_wrong_secret() -> None:
    signer_a = StateSigner(StateSignerConfig(secret_key="secret-a"))
    signer_b = StateSigner(StateSignerConfig(secret_key="secret-b"))
    token = signer_a.sign({"x": 1})
    with pytest.raises(StateInvalidError):
        signer_b.unsign(token)


def test_empty_secret_raises() -> None:
    with pytest.raises(ValueError, match="secret_key"):
        StateSignerConfig(secret_key="")


def test_different_salts_incompatible() -> None:
    signer_a = StateSigner(StateSignerConfig(secret_key="same", salt="salt-a"))
    signer_b = StateSigner(StateSignerConfig(secret_key="same", salt="salt-b"))
    token = signer_a.sign({"x": 1})
    with pytest.raises(StateInvalidError):
        signer_b.unsign(token)
