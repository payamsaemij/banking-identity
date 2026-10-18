import pytest

from identity_service.application.security import hash_token
from identity_service.application.validators.email import (
    normalize_and_validate_email,
)
from identity_service.application.validators.password import validate_password
from identity_service.domain.exceptions import InvalidEmailError, InvalidPasswordError


class TestEmailValidation:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("  USER@Example.COM ", "user@example.com"),
            ("Mixed.Case+Tag@Sub.Domain.example", "mixed.case+tag@sub.domain.example"),
            ("simple@example.ir", "simple@example.ir"),
            ("  trim@example.com\t", "trim@example.com"),
        ],
    )
    def test_normalization_policy(self, raw: str, expected: str) -> None:
        assert normalize_and_validate_email(raw) == expected

    @pytest.mark.parametrize(
        "raw",
        [
            "",
            "   ",
            "no-at-sign.example.com",
            "@example.com",
            "user@",
            "user@@example.com",
            "user name@example.com",
            "user@-example-.com",
            "user@example..com",
            "user@example.com.",
            "a" * 65 + "@example.com",
            "user@" + "d" * 250 + ".com",
        ],
    )
    def test_malformed_emails_are_rejected(self, raw: str) -> None:
        with pytest.raises(InvalidEmailError):
            normalize_and_validate_email(raw)

    def test_email_must_be_a_string(self) -> None:
        with pytest.raises(InvalidEmailError):
            normalize_and_validate_email(123)  # type: ignore[arg-type]

    def test_plus_tags_and_dots_are_preserved(self) -> None:
        normalized = normalize_and_validate_email("First.Last+news@Example.com")
        assert normalized == "first.last+news@example.com"


class TestPasswordValidation:
    def test_minimum_boundary_is_accepted(self) -> None:
        assert validate_password("a" * 12) == "a" * 12

    def test_password_below_minimum_is_rejected(self) -> None:
        with pytest.raises(InvalidPasswordError):
            validate_password("a" * 11)

    def test_password_above_maximum_is_rejected(self) -> None:
        with pytest.raises(InvalidPasswordError):
            validate_password("a" * 129)

    def test_password_is_not_modified(self) -> None:
        password = "  padded password with spaces  "
        assert validate_password(password) == password

    def test_password_must_be_a_string(self) -> None:
        with pytest.raises(InvalidPasswordError):
            validate_password(None)  # type: ignore[arg-type]

    def test_no_composition_rules(self) -> None:
        # Letters only, no digits or symbols, still valid.
        assert validate_password("onlylowercaseletters") == "onlylowercaseletters"


class TestTokenHashing:
    def test_hash_differs_from_raw_token(self) -> None:
        raw = "some-raw-token-value"
        assert hash_token(raw) != raw

    def test_hash_is_deterministic(self) -> None:
        assert hash_token("stable") == hash_token("stable")

    def test_different_tokens_hash_differently(self) -> None:
        assert hash_token("one") != hash_token("two")
