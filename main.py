"""Password Strength Checker (re-engineered version).

Features:
  * Strength score 0-4 using the zxcvbn library
  * Simple entropy estimate in bits
  * Colourful terminal interface using Rich
  * Secure password generator using the secrets module
  * Optional Have I Been Pwned breach check (k-anonymity: only 5 hash characters are sent)

Run with:  python main.py
"""

import hashlib
import math
import secrets
import string
from pathlib import Path

import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table
from rich.text import Text
from zxcvbn import zxcvbn

console = Console()

COMMON_FILE = Path(__file__).with_name("common.txt")  # list kept from the original project
HIBP_URL = "https://api.pwnedpasswords.com/range/"

STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]
STRENGTH_COLOURS = ["red", "dark_orange", "yellow", "green", "bright_green"]

# Names shown to the user for the patterns zxcvbn can detect.
PATTERN_NAMES = {
    "dictionary": "dictionary word",
    "repeat": "repeated pattern",
    "sequence": "predictable sequence",
    "spatial": "keyboard pattern",
    "date": "date",
    "regex": "recent year",
}

# Character types used by both the entropy calculation and the generator.
CHARACTER_SETS = {
    "lowercase letters": string.ascii_lowercase,
    "uppercase letters": string.ascii_uppercase,
    "numbers": string.digits,
    "special characters": string.punctuation,
}
MIN_LENGTH, MAX_LENGTH = 4, 128
ZXCVBN_MAX_LENGTH = 72  # zxcvbn refuses longer input, so only the first 72 characters are analysed


# ---------------------------------------------------------------- analysis --


def load_common_passwords(path=COMMON_FILE):
    """Read the common-password list once. Returns an empty set if the file is missing."""
    try:
        return set(Path(path).read_text(encoding="utf-8", errors="ignore").splitlines())
    except OSError:
        return set()


def calculate_entropy(password):
    """Estimate entropy in bits: length x log2(size of the character pool).

    Limitation: this assumes every character was picked at random. Real passwords
    like "Password1!" follow patterns, so their true strength is much lower.
    """
    pool = sum(len(chars) for chars in CHARACTER_SETS.values() if any(c in chars for c in password))
    all_ascii = "".join(CHARACTER_SETS.values())
    if any(c not in all_ascii for c in password):
        pool += 32  # rough allowance for spaces, accents, emoji, ...
    return len(password) * math.log2(pool) if pool else 0.0


def analyze_password(password, common_passwords=frozenset()):
    """Analyse a password with zxcvbn and return the results in a simple dictionary."""
    if not password:  # zxcvbn raises an obscure IndexError on an empty string
        raise ValueError("Password is empty.")
    result = zxcvbn(password[:ZXCVBN_MAX_LENGTH])
    score = result["score"]
    warning = result["feedback"]["warning"]
    suggestions = list(result["feedback"]["suggestions"])

    is_common = password in common_passwords or password.lower() in common_passwords
    if is_common:  # the original project's rule: a listed password scores 0
        score = 0
        warning = "This password is in the list of commonly used passwords."

    patterns = {PATTERN_NAMES[m["pattern"]] for m in result["sequence"] if m["pattern"] in PATTERN_NAMES}
    return {
        "score": score,
        "entropy": calculate_entropy(password),
        "crack_time_slow": result["crack_times_display"]["offline_slow_hashing_1e4_per_second"],
        "crack_time_fast": result["crack_times_display"]["offline_fast_hashing_1e10_per_second"],
        "warning": warning,
        "suggestions": suggestions,
        "patterns": sorted(patterns),
        "is_common": is_common,
    }


# --------------------------------------------------------------- generator --


def generate_password(length=16, lower=True, upper=True, digits=True, special=True):
    """Generate a random password with the secrets module.

    Every selected character type appears at least once.
    """
    wanted = (lower, upper, digits, special)
    selected = [chars for chars, use in zip(CHARACTER_SETS.values(), wanted) if use]
    if not selected:
        raise ValueError("Choose at least one character type.")
    if not MIN_LENGTH <= length <= MAX_LENGTH:
        raise ValueError(f"Length must be between {MIN_LENGTH} and {MAX_LENGTH}.")

    pool = "".join(selected)
    while True:  # retry until every selected type is present (usually the first try)
        password = "".join(secrets.choice(pool) for _ in range(length))
        if all(any(c in chars for c in password) for chars in selected):
            return password


# ------------------------------------------------------------ breach check --


def check_breach(password):
    """Check Have I Been Pwned using k-anonymity.

    Returns how many times the password appears in known breaches (0 = not found),
    or None if the check could not be completed (network or server problem).
    Only the first 5 characters of the SHA-1 hash leave this computer. The password
    itself is never sent or stored.
    """
    # HIBP is indexed by SHA-1, so SHA-1 is required here (it is not protecting anything).
    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    headers = {"Add-Padding": "true", "User-Agent": "password-strength-checker"}

    try:
        response = requests.get(HIBP_URL + prefix, headers=headers, timeout=5)
        response.raise_for_status()
        for line in response.text.splitlines():  # each line looks like "HASH_SUFFIX:COUNT"
            line_suffix, _, count = line.partition(":")
            if line_suffix == suffix:
                return int(count)
        return 0
    except (requests.RequestException, ValueError):
        return None


def breach_message(count):
    """Turn the result of check_breach() into a message for the user."""
    if count is None:
        return "[yellow]Could not reach Have I Been Pwned. Check your connection and try again.[/yellow]"
    if count == 0:
        return "[green]Not found in known breaches[/green] [dim](this does not prove it is safe)[/dim]"
    return f"[red]Found {count:,} times in known breaches - do not use this password![/red]"


# ---------------------------------------------------------------- terminal --


def strength_bar(score):
    """A 20-character bar: empty for score 0, full for score 4."""
    filled = score * 5
    return "█" * filled + "░" * (20 - filled)


def show_result(result, breach_text=None):
    """Print the analysis in a Rich panel, followed by any suggestions."""
    score = result["score"]
    colour = STRENGTH_COLOURS[score]

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column(style="bold")
    table.add_column()
    table.add_row("Strength", f"[{colour}]{STRENGTH_LABELS[score]} ({score}/4)  {strength_bar(score)}[/{colour}]")
    table.add_row("Entropy", f"{result['entropy']:.1f} bits [dim](simple estimate)[/dim]")
    table.add_row("Crack time", f"{result['crack_time_slow']} [dim](slow hash)[/dim]  /  {result['crack_time_fast']} [dim](fast hash)[/dim]")
    table.add_row("Patterns", ", ".join(result["patterns"]) or "none found")
    if breach_text:
        table.add_row("Breach check", breach_text)
    console.print(Panel(table, title="Password analysis", border_style=colour))

    tips = ([result["warning"]] if result["warning"] else []) + result["suggestions"]
    if tips:
        console.print(Panel("\n".join(f"• {tip}" for tip in tips), title="Suggestions", border_style="yellow"))


def check_flow(common_passwords):
    """Ask for a password, analyse it and optionally check it against breaches."""
    password = Prompt.ask("Enter a password (typing is hidden)", password=True)
    if not password:
        console.print("[red]Please type a password first.[/red]")
        return
    result = analyze_password(password, common_passwords)

    breach_text = None
    if Confirm.ask("Check Have I Been Pwned? (sends only 5 characters of the hash)", default=False):
        breach_text = breach_message(check_breach(password))
    show_result(result, breach_text)


def generate_flow():
    """Ask the user what they want, then show a generated password and its analysis."""
    length = IntPrompt.ask("Password length", default=16)
    choices = [Confirm.ask(f"Include {name}?", default=True) for name in CHARACTER_SETS]
    try:
        password = generate_password(length, *choices)
    except ValueError as error:
        console.print(f"[red]{error}[/red]")
        return

    console.print("\n[bold]Generated password:[/bold]")
    console.print(Text(password, style="bold green"), soft_wrap=True)  # Text: no markup surprises
    show_result(analyze_password(password))


def main():
    console.print(Panel("[bold]Password Strength Checker[/bold]", style="cyan"))
    common_passwords = load_common_passwords()
    if not common_passwords:
        console.print("[dim]common.txt not found - using zxcvbn's built-in lists only.[/dim]")

    try:
        while True:
            console.print("\n1. Check a password\n2. Generate a password\n3. Quit")
            choice = Prompt.ask("Choose", choices=["1", "2", "3"], default="1")
            if choice == "1":
                check_flow(common_passwords)
            elif choice == "2":
                generate_flow()
            else:
                break
    except (KeyboardInterrupt, EOFError):
        console.print()
    console.print("Goodbye!")


if __name__ == "__main__":
    main()
