# Password Strength Checker

A small terminal tool that tells you how strong a password really is, helps you generate a better one, and can
(optionally) check whether it has appeared in a known data breach.

This is a re-engineered version of
[edeniyanda/Python-Password-Strength-Checker](https://github.com/edeniyanda/Python-Password-Strength-Checker).
It keeps the original idea (check a password, reject common ones) and replaces the simple point-scoring with
[zxcvbn](https://pypi.org/project/zxcvbn/). See `reengineering_report.md` for the full story.

## Features

- **Strength score 0–4** from zxcvbn, with warnings and suggestions for improvement
- **Pattern detection**: dictionary words, repeated patterns, predictable sequences, keyboard patterns, dates/years
- **Entropy estimate** in bits (a simple formula, see *Limitations*)
- **Rich terminal interface**: colours, tables, panels and a strength bar
- **Password generator** using Python's `secrets` module (choose length and character types)
- **Optional Have I Been Pwned check** using k-anonymity (opt-in each time, never sends your password)
- **Common-password list** (`common.txt`) from the original project is still used
- **50 automated tests** with pytest (the breach API is always mocked)

## Setup

Requires Python 3.10 or newer.

```bash
pip install -r requirements.txt
```

## Run

```bash
python main.py
```

Choose **1** to check a password (what you type is hidden), **2** to generate one, or **3** to quit.

## Run the tests

```bash
pytest
```

## How the breach check protects you

1. Your password is hashed with SHA-1 **on your computer**.
2. Only the **first 5 characters** of that hash are sent to `api.pwnedpasswords.com`.
3. The service replies with every hash ending that starts with those 5 characters, and your computer looks for a
   match locally.

The password itself is never sent or stored. If the network is down, the app says so and carries on.

## Limitations

- **Entropy is a rough estimate.** It is `length × log2(character pool size)` and assumes every character was
  chosen at random. Human-chosen passwords follow patterns, so the zxcvbn score is the better guide. For example,
  `Qwerty123!` gets about 65 bits from the formula but is only a *Weak* (1/4) password.
- A score of 4 is not a guarantee. Against a very fast, unsalted hash an attacker can still be quick, which is why
  two crack-time estimates (slow hash / fast hash) are shown.
- zxcvbn is English-centred and only the first 72 characters of a password are analysed.
- "Not found in breaches" does not prove a password is safe, only that it is not in that database.
- A generated password stays visible in your terminal scrollback until you clear it.

## Files

| File | Purpose |
|---|---|
| `main.py` | The application |
| `test_password_checker.py` | Automated tests |
| `common.txt` | Common-password list kept from the original project |
| `requirements.txt` | Dependencies |
| `reengineering_report.md` | Analysis, changes, test results and comparison |
