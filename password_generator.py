"""
Secure Password Generator
Uses Python's `secrets` module — cryptographically strong,
backed by the OS entropy source (CryptGenRandom on Windows).
No third-party dependencies required.
"""

import secrets
import string
import argparse
import sys

# ── Character pools ────────────────────────────────────────────────────────────
POOLS = {
    "upper":   string.ascii_uppercase,          # A-Z
    "lower":   string.ascii_lowercase,          # a-z
    "digits":  string.digits,                   # 0-9
    "symbols": "!@#$%^&*()-_=+[]{}|;:,.<>?",   # special chars
}

# ── Entropy estimator ──────────────────────────────────────────────────────────
def entropy_bits(length: int, charset_size: int) -> float:
    """Return the theoretical entropy in bits: length × log2(charset_size)."""
    import math
    if charset_size <= 0 or length <= 0:
        return 0.0
    return length * math.log2(charset_size)

# ── Strength label ─────────────────────────────────────────────────────────────
def strength_label(bits: float) -> str:
    if bits < 40:  return "❌ Very Weak  — do NOT use"
    if bits < 60:  return "⚠️  Weak       — risky"
    if bits < 80:  return "🟡 Fair        — acceptable"
    if bits < 100: return "🟢 Strong      — good"
    return              "🔒 Very Strong — excellent"

# ── Core generator ─────────────────────────────────────────────────────────────
def generate_password(
    length: int = 20,
    use_upper: bool = True,
    use_lower: bool = True,
    use_digits: bool = True,
    use_symbols: bool = True,
) -> str:
    """
    Generate a single cryptographically secure password.

    Strategy:
    1. Build the charset from active pools.
    2. Guarantee at least one character from every active pool
       (so the password always satisfies complexity rules).
    3. Fill the remaining slots from the full charset.
    4. Shuffle everything with secrets.SystemRandom (Fisher-Yates
       via random.shuffle backed by os.urandom).
    """
    active = {}
    if use_upper:   active["upper"]   = POOLS["upper"]
    if use_lower:   active["lower"]   = POOLS["lower"]
    if use_digits:  active["digits"]  = POOLS["digits"]
    if use_symbols: active["symbols"] = POOLS["symbols"]

    if not active:
        raise ValueError("At least one character set must be enabled.")

    charset = "".join(active.values())

    if length < len(active):
        raise ValueError(
            f"Length ({length}) must be ≥ number of active sets ({len(active)})."
        )

    # One guaranteed character from each active pool
    mandatory = [secrets.choice(pool) for pool in active.values()]

    # Fill the rest
    rest = [secrets.choice(charset) for _ in range(length - len(mandatory))]

    # Combine and shuffle using cryptographically secure RNG
    combined = mandatory + rest
    rng = secrets.SystemRandom()   # backed by os.urandom / CryptGenRandom
    rng.shuffle(combined)

    return "".join(combined)

# ── Batch generator ────────────────────────────────────────────────────────────
def generate_batch(count: int, **kwargs) -> list[str]:
    return [generate_password(**kwargs) for _ in range(count)]

# ── CLI ────────────────────────────────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="🔐 Secure Password Generator (uses Python secrets module)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_generator.py                  # 1 password, length 20, all sets
  python password_generator.py -l 32            # length 32
  python password_generator.py -l 24 -n 5       # 5 passwords, length 24
  python password_generator.py --no-symbols     # no special characters
  python password_generator.py -l 16 --only-digits  # PINs
        """,
    )
    p.add_argument("-l", "--length",  type=int, default=20,
                   help="Password length (default: 20, min: 8)")
    p.add_argument("-n", "--count",   type=int, default=1,
                   help="Number of passwords to generate (default: 1)")
    p.add_argument("--no-upper",      action="store_true", help="Exclude uppercase letters")
    p.add_argument("--no-lower",      action="store_true", help="Exclude lowercase letters")
    p.add_argument("--no-digits",     action="store_true", help="Exclude digits")
    p.add_argument("--no-symbols",    action="store_true", help="Exclude symbols")
    p.add_argument("--only-digits",   action="store_true", help="Digits only (e.g. PIN)")
    p.add_argument("--save",          type=str, default=None,
                   help="Save passwords to a text file (e.g. --save passwords.txt)")
    return p

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Validate length
    if args.length < 8:
        print("❌ Minimum length is 8. Setting to 8.")
        args.length = 8
    if args.length > 256:
        print("⚠️  Length capped at 256.")
        args.length = 256

    # Validate count
    count = max(1, min(args.count, 100))

    # Build options
    if args.only_digits:
        opts = dict(use_upper=False, use_lower=False,
                    use_digits=True, use_symbols=False)
    else:
        opts = dict(
            use_upper=   not args.no_upper,
            use_lower=   not args.no_lower,
            use_digits=  not args.no_digits,
            use_symbols= not args.no_symbols,
        )

    # Check at least one set active
    if not any(opts.values()):
        print("❌ All character sets disabled. Enable at least one.")
        sys.exit(1)

    # Generate
    try:
        passwords = generate_batch(count, length=args.length, **opts)
    except ValueError as e:
        print(f"❌ Error: {e}")
        sys.exit(1)

    # Charset size for entropy calc
    charset_size = sum(
        len(POOLS[k]) for k, v in zip(
            ["upper","lower","digits","symbols"], opts.values()
        ) if v
    )
    bits = entropy_bits(args.length, charset_size)

    # ── Display ────────────────────────────────────────────────────────────────
    print()
    print("━" * 54)
    print("  🔐  SECURE PASSWORD GENERATOR")
    print("━" * 54)
    print(f"  Length   : {args.length} characters")
    print(f"  Sets     : " + ", ".join(
        k for k, v in zip(["Upper","Lower","Digits","Symbols"], opts.values()) if v
    ))
    print(f"  Entropy  : {bits:.1f} bits  →  {strength_label(bits)}")
    print("━" * 54)
    print()

    for i, pw in enumerate(passwords, 1):
        prefix = f"  [{i:>2}]  " if count > 1 else "  "
        print(f"{prefix}{pw}")

    print()
    print("  ⚠️  Never share or store passwords in plain text.")
    print("  ✅  Use a password manager (e.g. Bitwarden, KeePass).")
    print("━" * 54)
    print()

    # ── Optional save ──────────────────────────────────────────────────────────
    if args.save:
        try:
            with open(args.save, "w", encoding="utf-8") as f:
                for pw in passwords:
                    f.write(pw + "\n")
            print(f"  💾 Saved to: {args.save}")
            print()
        except OSError as e:
            print(f"  ❌ Could not save file: {e}")


if __name__ == "__main__":
    main()
