"""Tests for argon2id password hashing."""

from b3dmar_auth.password import hash_password, needs_rehash, verify_password


class TestPasswordHashing:
    def test_hash_and_verify(self) -> None:
        hashed = hash_password("correct-horse-battery-staple")
        assert verify_password("correct-horse-battery-staple", hashed)

    def test_wrong_password_rejected(self) -> None:
        hashed = hash_password("correct-password")
        assert not verify_password("wrong-password", hashed)

    def test_hash_is_argon2id(self) -> None:
        hashed = hash_password("test")
        assert hashed.startswith("$argon2id$")

    def test_hashes_are_unique(self) -> None:
        h1 = hash_password("same-password")
        h2 = hash_password("same-password")
        assert h1 != h2  # different salts

    def test_invalid_hash_returns_false(self) -> None:
        assert not verify_password("anything", "not-a-valid-hash")

    def test_empty_password(self) -> None:
        hashed = hash_password("")
        assert verify_password("", hashed)
        assert not verify_password("not-empty", hashed)

    def test_needs_rehash_with_current_params(self) -> None:
        hashed = hash_password("test")
        assert not needs_rehash(hashed)
