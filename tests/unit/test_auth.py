import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from dashboard.services.auth_service import hash_password
from passlib.hash import bcrypt


class TestPasswordHashing:
    def test_hash_is_not_plaintext(self):
        hashed = hash_password("MyPassword123!")
        assert hashed != "MyPassword123!"

    def test_hash_verifies_correctly(self):
        hashed = hash_password("MyPassword123!")
        assert bcrypt.verify("MyPassword123!", hashed) is True

    def test_wrong_password_fails(self):
        hashed = hash_password("MyPassword123!")
        assert bcrypt.verify("WrongPassword", hashed) is False

    def test_different_hashes_for_same_password(self):
        h1 = hash_password("SamePassword")
        h2 = hash_password("SamePassword")
        assert h1 != h2  # bcrypt uses random salt

    def test_empty_password_hashes(self):
        hashed = hash_password("")
        assert len(hashed) > 0
