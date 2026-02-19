"""Password hashing with argon2id (OWASP recommended).

Standardizes on a single hashing algorithm with production-grade parameters.
"""

import argon2

# OWASP recommended parameters for argon2id:
# https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
_hasher = argon2.PasswordHasher(
    time_cost=2,
    memory_cost=19456,  # 19 MiB
    parallelism=1,
    hash_len=32,
    salt_len=16,
    type=argon2.Type.ID,
)


def hash_password(password: str) -> str:
    """Hash a password using argon2id with OWASP-recommended parameters.

    Returns an encoded hash string that includes the algorithm, parameters,
    salt, and hash — safe to store directly in a DB column.
    """
    return _hasher.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against an argon2id hash.

    Returns True if the password matches, False otherwise.
    Handles invalid hash formats gracefully (returns False).
    """
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (argon2.exceptions.VerifyMismatchError, argon2.exceptions.InvalidHashError):
        return False


def needs_rehash(hashed_password: str) -> bool:
    """Check if a hash was created with outdated parameters and should be rehashed.

    Call this after a successful verify_password to transparently upgrade
    hashes when parameters change (e.g. increasing time_cost).
    """
    return _hasher.check_needs_rehash(hashed_password)
