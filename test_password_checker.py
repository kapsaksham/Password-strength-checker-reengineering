"""Automated tests for main.py.  Run them with:  pytest

No test makes a real network request: the Have I Been Pwned API is always mocked.
"""

import hashlib
import math
import secrets
import string

import pytest
import requests

import main

STRONG_PASSWORD = "k9#Vq2$mL7!pZ4wX"
TEST_PASSWORD = "Zq7!unique-test-pw"  # unusual on purpose, so we can check it is never sent


# ------------------------------------------------------------ test helpers --


@pytest.fixture(autouse=True)
def block_real_network(monkeypatch):
    """Safety net: fail loudly if any test forgets to mock requests.get."""

    def fail(*args, **kwargs):
        raise AssertionError("A test tried to make a real network request!")

    monkeypatch.setattr(main.requests, "get", fail)


class FakeResponse:
    """A tiny stand-in for requests.Response."""

    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


def mock_api(monkeypatch, response):
    """Replace requests.get. Returns a list that records every call made."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append((url, kwargs))
        if isinstance(response, Exception):
            raise response
        return response

    monkeypatch.setattr(main.requests, "get", fake_get)
    return calls


def sha1_parts(password):
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    return digest[:5], digest[5:]


# ---------------------------------------------------------- strength tests --


def test_common_password_scores_zero():
    assert main.analyze_password("password")["score"] == 0


def test_random_password_scores_high():
    assert main.analyze_password(STRONG_PASSWORD)["score"] >= 3


@pytest.mark.parametrize("password", ["a", "password", "Tr0ub4dor&3", STRONG_PASSWORD])
def test_score_is_between_0_and_4(password):
    assert 0 <= main.analyze_password(password)["score"] <= 4


def test_long_passphrase_beats_short_complex_password():
    # The original rule-based checker got this the wrong way round.
    passphrase = main.analyze_password("correcthorsebatterystaple")["score"]
    predictable = main.analyze_password("Qwerty123!")["score"]
    assert passphrase > predictable


def test_detects_dictionary_word():
    assert "dictionary word" in main.analyze_password("password")["patterns"]


def test_detects_repeated_pattern():
    assert "repeated pattern" in main.analyze_password("abcabcabcabc")["patterns"]


def test_detects_predictable_sequence():
    assert "predictable sequence" in main.analyze_password("abcdefghijkl")["patterns"]


def test_detects_keyboard_pattern():
    assert "keyboard pattern" in main.analyze_password("zxcvbnm,./")["patterns"]


def test_random_password_has_no_patterns():
    assert main.analyze_password(STRONG_PASSWORD)["patterns"] == []


def test_weak_password_gets_feedback():
    result = main.analyze_password("Summer2019")
    assert result["warning"] or result["suggestions"]


def test_password_in_common_list_scores_zero():
    result = main.analyze_password(STRONG_PASSWORD, common_passwords={STRONG_PASSWORD})
    assert result["score"] == 0
    assert result["is_common"] is True


def test_common_list_check_ignores_case():
    result = main.analyze_password("My-Secret-Word", common_passwords={"my-secret-word"})
    assert result["is_common"] is True


def test_password_not_in_common_list():
    assert main.analyze_password(STRONG_PASSWORD, common_passwords={"abc"})["is_common"] is False


def test_empty_password_is_rejected():
    with pytest.raises(ValueError):
        main.analyze_password("")


def test_very_long_password_does_not_crash():
    assert main.analyze_password("Ab1!xY9?" * 20)["score"] >= 0  # 160 characters


def test_load_common_passwords(tmp_path):
    file = tmp_path / "common.txt"
    file.write_text("123456\nletmein\n", encoding="utf-8")
    assert main.load_common_passwords(file) == {"123456", "letmein"}


def test_load_common_passwords_missing_file(tmp_path):
    assert main.load_common_passwords(tmp_path / "nope.txt") == set()


# ----------------------------------------------------------- entropy tests --


def test_entropy_of_empty_password_is_zero():
    assert main.calculate_entropy("") == 0


def test_entropy_lowercase_only():
    assert main.calculate_entropy("abcdefgh") == pytest.approx(8 * math.log2(26))


def test_entropy_digits_only():
    assert main.calculate_entropy("123456") == pytest.approx(6 * math.log2(10))


def test_entropy_all_four_character_types():
    # pool = 26 + 26 + 10 + 32 = 94 characters
    assert main.calculate_entropy("Abcdef1!gh") == pytest.approx(10 * math.log2(94))


def test_entropy_grows_with_length():
    assert main.calculate_entropy("abcdefghij") > main.calculate_entropy("abcde")


def test_entropy_grows_with_more_character_types():
    assert main.calculate_entropy("abcdefgh") < main.calculate_entropy("abcdefG1")


def test_entropy_counts_spaces_and_unicode():
    assert main.calculate_entropy(" ") == pytest.approx(math.log2(32))
    assert main.calculate_entropy("é") == pytest.approx(math.log2(32))


# -------------------------------------------------------- generator tests --


@pytest.mark.parametrize("length", [4, 16, 128])
def test_generated_password_has_requested_length(length):
    assert len(main.generate_password(length)) == length


def test_generated_password_contains_every_selected_type():
    for _ in range(50):  # repeat: the result is random
        password = main.generate_password(8)
        assert any(c in string.ascii_lowercase for c in password)
        assert any(c in string.ascii_uppercase for c in password)
        assert any(c in string.digits for c in password)
        assert any(c in string.punctuation for c in password)


def test_digits_only_password():
    password = main.generate_password(12, lower=False, upper=False, digits=True, special=False)
    assert password.isdigit()


def test_lowercase_only_password():
    password = main.generate_password(12, lower=True, upper=False, digits=False, special=False)
    assert all(c in string.ascii_lowercase for c in password)


def test_no_character_type_selected_is_an_error():
    with pytest.raises(ValueError, match="at least one"):
        main.generate_password(12, lower=False, upper=False, digits=False, special=False)


@pytest.mark.parametrize("length", [0, 3, 129])
def test_invalid_length_is_an_error(length):
    with pytest.raises(ValueError, match="Length"):
        main.generate_password(length)


def test_generator_uses_the_secrets_module(monkeypatch):
    # Spy on the real standard-library secrets module, then count how often it is used.
    calls = []
    real_choice = secrets.choice

    def spy(sequence):
        calls.append(1)
        return real_choice(sequence)

    monkeypatch.setattr(secrets, "choice", spy)
    main.generate_password(20)
    assert len(calls) >= 20


def test_two_generated_passwords_differ():
    assert main.generate_password(20) != main.generate_password(20)


def test_generated_password_is_scored_strong():
    assert main.analyze_password(main.generate_password(20))["score"] >= 3


# ----------------------------------------------------- breach-check tests --


def test_breach_found_returns_count(monkeypatch):
    prefix, suffix = sha1_parts("password")
    assert prefix == "5BAA6"  # the well-known HIBP example prefix
    body = f"0018A45C4D1DEF81644B54AB7F969B88D65:3\r\n{suffix}:9545824\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1"
    mock_api(monkeypatch, FakeResponse(body))
    assert main.check_breach("password") == 9545824


def test_breach_not_found_returns_zero(monkeypatch):
    mock_api(monkeypatch, FakeResponse("0018A45C4D1DEF81644B54AB7F969B88D65:3\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1"))
    assert main.check_breach(TEST_PASSWORD) == 0


def test_padding_entry_with_zero_count_means_not_breached(monkeypatch):
    _, suffix = sha1_parts(TEST_PASSWORD)
    mock_api(monkeypatch, FakeResponse(f"{suffix}:0"))
    assert main.check_breach(TEST_PASSWORD) == 0


def test_only_five_hash_characters_are_sent(monkeypatch):
    prefix, suffix = sha1_parts(TEST_PASSWORD)
    calls = mock_api(monkeypatch, FakeResponse(""))
    main.check_breach(TEST_PASSWORD)

    assert len(calls) == 1
    url, _ = calls[0]
    assert url == main.HIBP_URL + prefix
    assert len(url.split("/")[-1]) == 5
    everything_sent = str(calls[0])
    assert TEST_PASSWORD not in everything_sent  # never the password
    assert suffix not in everything_sent  # never the rest of the hash


@pytest.mark.parametrize("error", [requests.ConnectionError(), requests.Timeout()])
def test_network_errors_return_none(monkeypatch, error):
    mock_api(monkeypatch, error)
    assert main.check_breach(TEST_PASSWORD) is None


def test_http_error_returns_none(monkeypatch):
    mock_api(monkeypatch, FakeResponse("", status_code=503))
    assert main.check_breach(TEST_PASSWORD) is None


def test_malformed_response_returns_none(monkeypatch):
    _, suffix = sha1_parts(TEST_PASSWORD)
    mock_api(monkeypatch, FakeResponse(f"{suffix}:not-a-number"))
    assert main.check_breach(TEST_PASSWORD) is None


def test_breach_messages():
    assert "Could not reach" in main.breach_message(None)
    assert "Not found" in main.breach_message(0)
    assert "1,234 times" in main.breach_message(1234)


# ---------------------------------------------------------------- display --


def test_strength_bar_is_empty_for_0_and_full_for_4():
    assert main.strength_bar(0) == "░" * 20
    assert main.strength_bar(4) == "█" * 20
