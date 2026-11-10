# Re-engineering Report: Python Password Strength Checker

**Original project:** <https://github.com/edeniyanda/Python-Password-Strength-Checker> (inspected by cloning the repository and running its code).

## 1. Existing System Analysis

**What the repository contains.** Three commits and three files: `main.py` (78 lines), `common.txt` (213,338 common passwords, 1.6 MB) and a one-paragraph `README.md`. It has no dependencies and no tests.

**Purpose.** According to its README, the tool judges a password by its length, complexity and the presence of certain characters, and checks it against a list of frequently used passwords.

**How it works.**

1. A `while True` loop asks `Enter password:` with `input()` (so the typed password is visible on screen) and calls `check_password()`. There is no menu and no way to quit except Ctrl+C.
2. `check_password()` opens `common.txt`, builds a set from it, and does an exact, case-sensitive match. A match prints "Password is too common. Your password strength is 0."
3. Otherwise `check_password_strength()` computes a score:
   - +1 for each character class present: uppercase, lowercase, digit, punctuation. The number of classes found is kept in a global variable `x`.
   - If fewer than four classes are present it returns immediately (score 0–3, length is ignored).
   - If all four are present it adds +1 each for length ≥ 8, ≥ 12, ≥ 16 and ≥ 20 (score 4–8).
4. A long `if/elif` chain turns the score into a message:

| Score | Message printed |
|---|---|
| 0 | Password is too weak |
| 1 | Password is weak |
| 2 | Password is average |
| 3 | Password is not that strong |
| 4 | Password is not that strong |
| 5 or more | Password is extremely strong |

When fewer than four classes are present it also prints a generic "must contain an uppercase letter, lowercase letter, special character and a digit" sentence.

## 2. Identified Shortcomings

**Rule-based scoring measures ingredients, not guessability.** Points are awarded for *having* character types and length, not for how hard the password is to guess. Running the original code produced "extremely strong" for `Qwerty123!`, `Monkey1!` and `Aa1!Aa1!Aa1!` (see the table in section 5), all of which are predictable. The thresholds are arbitrary: scores 3 and 4 print the same message, and any password with all four character types and 8 or more characters, that is not on the list, reaches "extremely strong".

**Character checks are shallow and can mislead.**
- Length only counts when all four character types are present, so `correcthorsebatterystaple` (25 characters) is rated "weak".
- The scheme rewards predictable substitutions such as `P@ssw0rd` and gives no credit to long passphrases.
- The common-password check is an exact, case-sensitive match. `Monkey1!` is simply not on the list, so it passes, even though it is a trivial variation of a common password.
- It cannot detect dictionary words, repeated patterns, sequences, keyboard patterns or dates, and it cannot explain *why* a password is weak. Every low score gets the same generic sentence.
- Code quality problems: the score is communicated through a global variable (`x`), and the `if x < 4` check inside the `score == 4` branch can never run (a score of 4 is only possible when all four classes are present).

**The terminal interface is minimal and fragile.**
- Plain `print` output with no colour or visual indicator; the same sentence is copy-pasted five times.
- The typed password is echoed to the screen.
- The module starts its input loop as soon as it is imported (there is no `if __name__ == "__main__"` guard), which makes the code impossible to import and test. I confirmed this: `import main` immediately waits for input.
- `common.txt` is opened with a relative path, so running the program from another directory crashes with `FileNotFoundError` (confirmed), and the 1.6 MB file is re-read on every check.

**No password generator.** The tool tells users what is missing but gives no help creating a strong password, which pushes people toward predictable "fixes" such as adding `1!` to the end.

**No breach checking.** A password can look complex yet already appear in leaked credential databases. A local list of 213,338 entries cannot cover that, and attackers try known leaked passwords first.

**No automated tests.** There are no tests, and because of the import problem above none could be written without restructuring. The behaviours described here (thresholds, matching rules) were never verified.

## 3. Proposed Re-engineering

The goal was to improve the tool while keeping it small: two Python files, no classes, short functions, no extra architecture.

| Improvement | Why it is beneficial |
|---|---|
| Replace point-scoring with **zxcvbn** (score 0–4) | Estimates how many guesses an attacker would need, using real password lists, dictionaries and pattern matching, instead of counting character types |
| Report **patterns and suggestions** | Tells the user *what* is wrong (dictionary word, repeat, sequence, keyboard pattern, date) and how to fix it |
| Show a simple **entropy estimate** | Gives a familiar "bits" figure; its limits are explained to the user rather than hidden |
| Use **Rich** for the interface | Colours, a table, panels and a strength bar make the result quick to read |
| Add a **secure generator** using `secrets` | Lets users get a strong password instead of guessing one; `secrets` is designed for security, unlike `random` |
| Add an **optional Have I Been Pwned check** (k-anonymity) | Detects breached passwords without ever sending the password |
| Add **pytest tests** with the API mocked | Makes behaviour verifiable and protects against regressions |
| Small clean-ups | A menu with a quit option, hidden password input, `common.txt` loaded once from the script's folder, an `__main__` guard, no global variable |

**Core functionality preserved:** the program still repeatedly asks for passwords, still rejects any password found in the original `common.txt` list (score 0), and still prints a strength verdict with advice.

## 4. Implementation and Technology Changes

The application is one file, `main.py` (about 250 lines including comments), organised into short functions:

| Function | Job |
|---|---|
| `load_common_passwords()` | Reads `common.txt` once; returns an empty set if the file is missing |
| `calculate_entropy()` | Simple entropy estimate |
| `analyze_password()` | Runs zxcvbn and the common-list check; returns a plain dictionary |
| `generate_password()` | Secure generator |
| `check_breach()` / `breach_message()` | Have I Been Pwned lookup and its user-facing message |
| `show_result()`, `strength_bar()` | Rich output |
| `check_flow()`, `generate_flow()`, `main()` | The interactive menu |

**zxcvbn.** `analyze_password()` calls `zxcvbn()` and keeps the 0–4 `score`, the feedback `warning` and `suggestions`, the matched pattern types (mapped to friendly names such as "repeated pattern"), and two crack-time estimates. Two practical details came out of testing:
- zxcvbn raises an error on an empty string, so `analyze_password("")` raises a clear `ValueError` and the menu asks the user to type something.
- zxcvbn 4.5.0 refuses passwords longer than 72 characters, so only the first 72 characters are analysed.

The original `common.txt` check is kept: a password on the list (compared as typed and in lower case) is forced to score 0.

**Entropy.** The calculation is deliberately simple:

```python
pool = sum(len(chars) for chars in CHARACTER_SETS.values() if any(c in chars for c in password))
entropy = len(password) * math.log2(pool)
```

The pool is 26 for lowercase, 26 for uppercase, 10 for digits and 32 for punctuation. Spaces and non-ASCII characters add a rough 32. **Limitation:** the formula assumes each character was chosen uniformly at random, so it overestimates the strength of human-made passwords. The app labels it "simple estimate", and section 5 shows concrete cases.

**Rich.** `show_result()` prints a panel containing a table (strength with a 20-character bar, entropy, crack times, patterns, and the breach result when requested), coloured from red to green by score, followed by a second panel of suggestions. Generated passwords are printed as `Text` objects rather than markup strings, so characters such as `[` in a password cannot be misread as formatting.

**Secrets.** `generate_password()` builds the password with `secrets.choice()`. The user chooses length (4–128) and any combination of lowercase, uppercase, numbers and special characters. It retries until every selected type appears at least once, which keeps the result uniformly random among valid passwords and avoids the bias of "fixing up" characters afterwards. It raises `ValueError` for invalid input.

**Have I Been Pwned.** `check_breach()` hashes the password with SHA-1 locally and sends only `hash[:5]`:

```python
sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
prefix, suffix = sha1[:5], sha1[5:]
response = requests.get(HIBP_URL + prefix, headers=headers, timeout=5)
```

It then looks for `suffix` in the returned `SUFFIX:COUNT` lines locally. Details:
- The request carries the `Add-Padding: true` header so the response size does not reveal how many real matches a prefix has; padded entries have a count of 0 and are treated as "not found".
- The check is opt-in: the app asks each time (default **No**).
- The function returns the count (0 means not found) or `None` if the check could not be completed (network error, timeout, HTTP error, malformed response). This keeps "I don't know" separate from "no", and the app then says it could not reach the service instead of claiming the password is clean.
- The password is never written anywhere and is not part of the URL, headers or body (a test checks this).

SHA-1 is used only because the service is indexed by SHA-1; it is not protecting anything here.

**Technology stack.** Only the requested technologies are used: Python, zxcvbn, Rich, `secrets` (plus the standard library's `hashlib`, `math`, `string` and `pathlib`), Requests and pytest. There are no classes, databases or web frameworks, and the project has two Python files.

## 5. Testing and Comparison

**Environment.** Python 3.12.3, pytest 9.2.0, zxcvbn 4.5.0, Rich 15.0.0, Requests 2.34.2. I did not run the project on Python 3.10 or 3.11.

**Test cases.** `test_password_checker.py` contains 50 tests (counting parametrised cases):

| Area | Tests | What is checked |
|---|---|---|
| Strength analysis and common list | 20 | Common password scores 0; random password scores high; score always within 0–4; a long passphrase beats a short "complex" one; dictionary, repeat, sequence and keyboard patterns are detected; random passwords show no patterns; weak passwords get feedback; common-list match forces score 0 and ignores case; empty input is rejected; 160-character input does not crash; list loading and missing file |
| Entropy | 7 | Empty = 0; exact values for lowercase-only, digits-only and all four types; grows with length and with more character types; spaces/Unicode counted |
| Password generation | 13 | Requested length (4, 16, 128); every selected type present (repeated 50 times); digits-only and lowercase-only; no type selected and bad lengths (0, 3, 129) raise `ValueError`; the standard-library `secrets` module is really used; two outputs differ; output scores as strong |
| Breach checking (API mocked) | 9 | Match returns the count; no match returns 0; padded zero-count entry means not breached; **only the 5-character prefix is sent** (the password and the rest of the hash appear nowhere in the request); connection error and timeout return `None`; HTTP 503 returns `None`; malformed response returns `None`; user messages |
| Display helper | 1 | Strength bar is empty for 0 and full for 4 |

An automatic safety net in the test file makes any test fail if it tries a real network request, so no test touches the real API.

**Actual test results.** Output of `pytest -v`:

```text
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.2.0, pluggy-1.7.0 -- /usr/bin/python3
collecting ... collected 50 items

test_password_checker.py::test_common_password_scores_zero PASSED        [  2%]
test_password_checker.py::test_random_password_scores_high PASSED        [  4%]
test_password_checker.py::test_score_is_between_0_and_4[a] PASSED        [  6%]
test_password_checker.py::test_score_is_between_0_and_4[password] PASSED [  8%]
test_password_checker.py::test_score_is_between_0_and_4[Tr0ub4dor&3] PASSED [ 10%]
test_password_checker.py::test_score_is_between_0_and_4[k9#Vq2$mL7!pZ4wX] PASSED [ 12%]
test_password_checker.py::test_long_passphrase_beats_short_complex_password PASSED [ 14%]
test_password_checker.py::test_detects_dictionary_word PASSED            [ 16%]
test_password_checker.py::test_detects_repeated_pattern PASSED           [ 18%]
test_password_checker.py::test_detects_predictable_sequence PASSED       [ 20%]
test_password_checker.py::test_detects_keyboard_pattern PASSED           [ 22%]
test_password_checker.py::test_random_password_has_no_patterns PASSED    [ 24%]
test_password_checker.py::test_weak_password_gets_feedback PASSED        [ 26%]
test_password_checker.py::test_password_in_common_list_scores_zero PASSED [ 28%]
test_password_checker.py::test_common_list_check_ignores_case PASSED     [ 30%]
test_password_checker.py::test_password_not_in_common_list PASSED        [ 32%]
test_password_checker.py::test_empty_password_is_rejected PASSED         [ 34%]
test_password_checker.py::test_very_long_password_does_not_crash PASSED  [ 36%]
test_password_checker.py::test_load_common_passwords PASSED              [ 38%]
test_password_checker.py::test_load_common_passwords_missing_file PASSED [ 40%]
test_password_checker.py::test_entropy_of_empty_password_is_zero PASSED  [ 42%]
test_password_checker.py::test_entropy_lowercase_only PASSED             [ 44%]
test_password_checker.py::test_entropy_digits_only PASSED                [ 46%]
test_password_checker.py::test_entropy_all_four_character_types PASSED   [ 48%]
test_password_checker.py::test_entropy_grows_with_length PASSED          [ 50%]
test_password_checker.py::test_entropy_grows_with_more_character_types PASSED [ 52%]
test_password_checker.py::test_entropy_counts_spaces_and_unicode PASSED  [ 54%]
test_password_checker.py::test_generated_password_has_requested_length[4] PASSED [ 56%]
test_password_checker.py::test_generated_password_has_requested_length[16] PASSED [ 58%]
test_password_checker.py::test_generated_password_has_requested_length[128] PASSED [ 60%]
test_password_checker.py::test_generated_password_contains_every_selected_type PASSED [ 62%]
test_password_checker.py::test_digits_only_password PASSED               [ 64%]
test_password_checker.py::test_lowercase_only_password PASSED            [ 66%]
test_password_checker.py::test_no_character_type_selected_is_an_error PASSED [ 68%]
test_password_checker.py::test_invalid_length_is_an_error[0] PASSED      [ 70%]
test_password_checker.py::test_invalid_length_is_an_error[3] PASSED      [ 72%]
test_password_checker.py::test_invalid_length_is_an_error[129] PASSED    [ 74%]
test_password_checker.py::test_generator_uses_the_secrets_module PASSED  [ 76%]
test_password_checker.py::test_two_generated_passwords_differ PASSED     [ 78%]
test_password_checker.py::test_generated_password_is_scored_strong PASSED [ 80%]
test_password_checker.py::test_breach_found_returns_count PASSED         [ 82%]
test_password_checker.py::test_breach_not_found_returns_zero PASSED      [ 84%]
test_password_checker.py::test_padding_entry_with_zero_count_means_not_breached PASSED [ 86%]
test_password_checker.py::test_only_five_hash_characters_are_sent PASSED [ 88%]
test_password_checker.py::test_network_errors_return_none[error0] PASSED [ 90%]
test_password_checker.py::test_network_errors_return_none[error1] PASSED [ 92%]
test_password_checker.py::test_http_error_returns_none PASSED            [ 94%]
test_password_checker.py::test_malformed_response_returns_none PASSED    [ 96%]
test_password_checker.py::test_breach_messages PASSED                    [ 98%]
test_password_checker.py::test_strength_bar_is_empty_for_0_and_full_for_4 PASSED [100%]

============================== 50 passed in 0.26s ==============================
```

**Extra verification beyond the unit tests.**
- *Repeat runs:* the suite was run 30 times in a row (several tests use randomness); all 30 runs passed all 50 tests.
- *Mutation check:* I deliberately broke the code in four ways and confirmed the tests failed each time: sending the full hash instead of the 5-character prefix, not handling network errors, dropping the "every selected type appears" rule in the generator, and replacing `secrets` with `random`. The last one initially **passed** because my first version of that test spied on the wrong object; I fixed the test and re-ran it, and it now fails as it should.
- *Manual run of the real program:* I drove `main.py` through a scripted session covering checking a password, an empty password, generating passwords, invalid generator input (length 3, no character types selected), and quitting. All behaved as designed.
- *Static check:* `pyflakes` reports no problems.

**What was not verified.**
- **The live Have I Been Pwned service.** My test environment cannot resolve `api.pwnedpasswords.com` (DNS failure), so the breach logic is tested only against mocked responses written from the API's documented format (`SUFFIX:COUNT` lines, `Add-Padding` header). The failed lookup did, however, exercise the real "could not reach the service" path in the running app, which handled it gracefully. Please try option 1 with the breach check on a machine with internet access.
- Colours were not visually inspected (my captured session was plain text), and the interface was not run on Windows or macOS.
- The interactive menu itself is checked by hand, not by automated tests.

**Comparison on real passwords.** Both versions were run on the same inputs. The original column is the actual output of the original `main.py`; the improved column uses the new `analyze_password()` with the same `common.txt`.

| Password | Original verdict | Improved verdict | Simple entropy (bits) | Patterns found |
|---|---|---|---|---|
| `password` | Password is too common. Your password strength is 0. | Very weak (0/4) | 37.6 | dictionary word |
| `P@ssw0rd` | Password is too common. Your password strength is 0. | Very weak (0/4) | 52.4 | dictionary word |
| `Qwerty123!` | Password is extremely strong. | Weak (1/4) | 65.5 | dictionary word |
| `Aa1!Aa1!Aa1!` | Password is extremely strong. | Weak (1/4) | 78.7 | repeated pattern |
| `Summer2019` | Password is not that strong. | Weak (1/4) | 59.5 | dictionary word, recent year |
| `Monkey1!` | Password is extremely strong. | Weak (1/4) | 52.4 | dictionary word |
| `correcthorsebatterystaple` | Password is weak. | Very strong (4/4) | 117.5 | dictionary word |
| `Tr0ub4dor&3` | Password is extremely strong. | Very strong (4/4) | 72.1 | none |
| `k9#Vq2$mL7!pZ4wX` | Password is extremely strong. | Very strong (4/4) | 104.9 | none |

Highlights: the original calls `Qwerty123!`, `Monkey1!` and `Aa1!Aa1!Aa1!` "extremely strong" but rates a 25-character passphrase "weak"; the improved version reverses both judgements. Where the two agree (for example `password`, or the random `k9#Vq2$mL7!pZ4wX`) the improved version also explains *why* through patterns and suggestions. `Tr0ub4dor&3` is rated strong by both, so the new version is not simply stricter.

**Why the entropy figure needs care.** For the same passwords, the simple formula is compared with zxcvbn's own guess count (converted to bits with log2):

| Password | Simple entropy (bits) | zxcvbn guesses (bits) |
|---|---|---|
| `Qwerty123!` | 65.5 | 14.3 |
| `Aa1!Aa1!Aa1!` | 78.7 | 14.9 |
| `Summer2019` | 59.5 | 14.5 |
| `correcthorsebatterystaple` | 117.5 | 48.0 |
| `Tr0ub4dor&3` | 72.1 | 36.5 |
| `k9#Vq2$mL7!pZ4wX` | 104.9 | 53.2 |

The simple formula is only reliable for truly random passwords (like the generated ones). For human-chosen passwords it can overstate strength by 50 bits or more, which is why the zxcvbn score is the headline result and entropy is shown as a secondary, clearly labelled figure.

**Summary comparison.**

| Original | Improved |
|---|---|
| Rule-based scoring | zxcvbn estimation |
| Basic character checks | Entropy and pattern analysis |
| Simple text output | Rich terminal interface |
| No password generator | Secure password generator |
| No automated tests | Pytest test suite |

The improved version additionally offers an optional breach check (the original had none).

## 6. Results

**Completed improvements.**
- zxcvbn strength score (0–4) with warnings, suggestions and detected patterns, replacing the point system.
- Entropy estimate shown next to the strength result, with its limitation stated.
- Rich interface: coloured panel, table, strength bar, suggestions panel.
- Secure password generator (`secrets`, selectable length and character types).
- Optional Have I Been Pwned check using k-anonymity, with graceful handling of network failures.
- 50 passing pytest tests, with the external API mocked.
- Delivered within the constraints: two Python files, no classes, only the permitted libraries, and the original `common.txt` check retained.

**Benefits.** Judgements now reflect how passwords are actually attacked; the user gets specific advice rather than one generic sentence; a strong password is one keypress away; the typed password is hidden; the code can be imported and tested; and the program no longer crashes when started from a different folder.

**Remaining limitations.**
- The entropy figure is only a rough estimate and is misleading for human-chosen passwords (see the table above).
- A score of 4 does not mean uncrackable: `Tr0ub4dor&3` scores 4/4 yet the fast-hash estimate is only about 10 seconds, which is why both crack-time estimates are displayed.
- zxcvbn is English-centred (in a quick manual check, a Cyrillic word plus digits scored 3/4), and only the first 72 characters are analysed.
- "Not found" in the breach database does not prove a password is safe, and the breach check needs an internet connection. It was not tested against the live service in my environment.
- A generated password stays visible in the terminal scrollback until cleared.
- `common.txt` is carried over from the original project unchanged; the project still ships this 1.6 MB data file.
- Tested on Python 3.12 only, and the interactive menu has no automated tests.
