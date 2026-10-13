#!/usr/bin/env python3
"""
Password Strength Assessment Tool
Evaluates passwords based on:
  - Length
  - Uppercase & Lowercase letters
  - Digits
  - Special characters
  - Common patterns, repetitions, and common weak passwords
  - Entropy and estimated crack time

Provides clear, actionable feedback to users.
"""

import re
import math
import string
import secrets
from typing import Dict, List, Tuple, Any

# Common weak passwords list for pattern detection
COMMON_PASSWORDS = {
    "password", "123456", "12345678", "123456789", "qwerty", "password123",
    "admin", "welcome", "iloveyou", "abc123", "letmein", "monkey", "dragon",
    "master", "sunshine", "football", "princess", "trustno1", "computer"
}

# Standard special characters
SPECIAL_CHARS = set("!@#$%^&*()_+-=[]{}|;':\",./<>?`~\\")


def calculate_entropy(password: str) -> float:
    """
    Calculates the Shannon entropy (in bits) of the password.
    Entropy = length * log2(pool_size)
    """
    if not password:
        return 0.0

    pool_size = 0
    if any(c.islower() for c in password):
        pool_size += 26
    if any(c.isupper() for c in password):
        pool_size += 26
    if any(c.isdigit() for c in password):
        pool_size += 10
    if any(c in SPECIAL_CHARS for c in password):
        pool_size += len(SPECIAL_CHARS)

    if pool_size == 0:
        pool_size = 1

    return len(password) * math.log2(pool_size)


def estimate_crack_time(entropy_bits: float) -> str:
    """
    Estimates the time needed to crack the password via brute-force
    assuming a modern offline GPU cluster (10 billion guesses/sec).
    """
    guesses = 2 ** entropy_bits
    rate = 1e10  # 10 billion guesses per second
    seconds = guesses / rate

    if seconds < 1:
        return "Instant (< 1 second)"
    elif seconds < 60:
        return f"{int(seconds)} seconds"
    elif seconds < 3600:
        return f"{int(seconds / 60)} minutes"
    elif seconds < 86400:
        return f"{int(seconds / 3600)} hours"
    elif seconds < 86400 * 30:
        return f"{int(seconds / 86400)} days"
    elif seconds < 86400 * 365:
        return f"{int(seconds / (86400 * 30))} months"
    elif seconds < 86400 * 365 * 100:
        return f"{int(seconds / (86400 * 365))} years"
    elif seconds < 86400 * 365 * 1_000_000:
        return f"{int(seconds / (86400 * 365 * 1000)):,} thousand years"
    else:
        return "Millions of years (Virtually uncrackable)"


def has_sequential_chars(password: str) -> bool:
    """Detects sequential alphabetical or numerical patterns (e.g., 'abc', '123')."""
    lower_pw = password.lower()
    for i in range(len(lower_pw) - 2):
        chunk = lower_pw[i:i + 3]
        if chunk.isalpha():
            if ord(chunk[1]) == ord(chunk[0]) + 1 and ord(chunk[2]) == ord(chunk[1]) + 1:
                return True
        elif chunk.isdigit():
            if int(chunk[1]) == int(chunk[0]) + 1 and int(chunk[2]) == int(chunk[1]) + 1:
                return True
    return False


def has_repeated_chars(password: str) -> bool:
    """Detects 3 or more repeated characters consecutively (e.g., 'aaa', '111')."""
    return bool(re.search(r"(.)\1\1", password))


def evaluate_password(password: str) -> Dict[str, Any]:
    """
    Evaluates password strength across multiple criteria.
    Returns score, rating, criteria details, and actionable feedback.
    """
    criteria = {
        "length_min": len(password) >= 8,
        "length_ideal": len(password) >= 12,
        "length_excellent": len(password) >= 16,
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_digit": bool(re.search(r"\d", password)),
        "has_special": any(c in SPECIAL_CHARS for c in password),
    }

    score = 0
    feedback_positive = []
    feedback_negative = []

    # 1. Length scoring
    pw_len = len(password)
    if pw_len == 0:
        return {
            "score": 0,
            "rating": "Very Weak",
            "entropy": 0,
            "crack_time": "Instant",
            "criteria": criteria,
            "positive_feedback": [],
            "suggestions": ["Password cannot be empty."]
        }

    if pw_len < 8:
        score += pw_len * 2
        feedback_negative.append(f"Too short ({pw_len} chars). Minimum recommended is 8 (ideally 12+).")
    elif pw_len < 12:
        score += 20 + (pw_len - 8) * 3
        feedback_positive.append(f"Acceptable length ({pw_len} chars).")
        feedback_negative.append("Consider making it 12+ characters for strong security.")
    elif pw_len < 16:
        score += 35 + (pw_len - 12) * 2
        feedback_positive.append(f"Good length ({pw_len} chars).")
    else:
        score += 45
        feedback_positive.append(f"Excellent length ({pw_len} chars).")

    # 2. Character types
    char_types_count = 0

    if criteria["has_lower"]:
        score += 15
        char_types_count += 1
        feedback_positive.append("Contains lowercase letters (a-z).")
    else:
        feedback_negative.append("Missing lowercase letters (a-z).")

    if criteria["has_upper"]:
        score += 15
        char_types_count += 1
        feedback_positive.append("Contains uppercase letters (A-Z).")
    else:
        feedback_negative.append("Missing uppercase letters (A-Z).")

    if criteria["has_digit"]:
        score += 15
        char_types_count += 1
        feedback_positive.append("Contains numbers (0-9).")
    else:
        feedback_negative.append("Missing numerical digits (0-9).")

    if criteria["has_special"]:
        score += 15
        char_types_count += 1
        feedback_positive.append("Contains special characters/symbols.")
    else:
        feedback_negative.append("Missing special symbols (!@#$%^&*...).")

    # Bonus for variety
    if char_types_count == 4:
        score += 10
        feedback_positive.append("Great character variety (covers all 4 character categories).")

    # 3. Penalties & Pattern Checks
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS or any(comm in lowered for comm in COMMON_PASSWORDS):
        score = min(score, 15)
        feedback_negative.append("Matches a commonly breached password or common keyword.")

    if has_repeated_chars(password):
        score -= 10
        feedback_negative.append("Avoid repeated consecutive characters (e.g. 'aaa', '111').")

    if has_sequential_chars(password):
        score -= 10
        feedback_negative.append("Avoid sequential patterns (e.g. 'abc', '123').")

    if password.isalpha():
        score -= 10
        feedback_negative.append("Password contains only letters.")
    elif password.isdigit():
        score -= 20
        feedback_negative.append("Password contains only numbers.")

    # Clamp score between 0 and 100
    score = max(0, min(100, score))

    # Determine Rating
    if score < 30:
        rating = "Very Weak"
    elif score < 55:
        rating = "Weak"
    elif score < 75:
        rating = "Moderate"
    elif score < 90:
        rating = "Strong"
    else:
        rating = "Very Strong"

    entropy = calculate_entropy(password)
    crack_time = estimate_crack_time(entropy)

    return {
        "score": score,
        "rating": rating,
        "entropy": round(entropy, 1),
        "crack_time": crack_time,
        "criteria": criteria,
        "positive_feedback": feedback_positive,
        "suggestions": feedback_negative
    }


def generate_strong_password(length: int = 16) -> str:
    """Generates a cryptographically strong random password meeting all criteria."""
    length = max(12, length)
    chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()_+-=[]{}|;:,.<>?")
    ]
    all_chars = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
    chars += [secrets.choice(all_chars) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


def render_progress_bar(score: int, length: int = 20) -> str:
    """Renders a text-based visual progress bar for password strength."""
    filled = int((score / 100) * length)
    unfilled = length - filled
    return f"[{'█' * filled}{'░' * unfilled}] {score}/100"


def display_report(password: str, results: Dict[str, Any]):
    """Prints a structured, user-friendly password strength assessment report."""
    rating_colors = {
        "Very Weak": "\033[91m",   # Red
        "Weak": "\033[31m",        # Light Red
        "Moderate": "\033[33m",    # Yellow
        "Strong": "\033[32m",      # Green
        "Very Strong": "\033[92m"  # Bright Green
    }
    reset_color = "\033[0m"

    rating = results["rating"]
    color = rating_colors.get(rating, "")

    print("\n" + "=" * 60)
    print("           PASSWORD STRENGTH ASSESSMENT REPORT")
    print("=" * 60)
    print(f" Password Length    : {len(password)} characters")
    print(f" Strength Rating    : {color}{rating.upper()}{reset_color}")
    print(f" Strength Score     : {render_progress_bar(results['score'])}")
    print(f" Shannon Entropy    : {results['entropy']} bits")
    print(f" Est. Offline Crack : {results['crack_time']}")
    print("-" * 60)

    # Checklist
    c = results["criteria"]
    print(" Criteria Checklist:")
    print(f"   [{'✔' if c['length_min'] else '✘'}] Minimum length (>= 8 characters)")
    print(f"   [{'✔' if c['length_ideal'] else '✘'}] Recommended length (>= 12 characters)")
    print(f"   [{'✔' if c['has_lower'] else '✘'}] Lowercase letters (a-z)")
    print(f"   [{'✔' if c['has_upper'] else '✘'}] Uppercase letters (A-Z)")
    print(f"   [{'✔' if c['has_digit'] else '✘'}] Numbers (0-9)")
    print(f"   [{'✔' if c['has_special'] else '✘'}] Special characters (!@#$%...)")
    print("-" * 60)

    # Strengths
    if results["positive_feedback"]:
        print(" Strengths:")
        for item in results["positive_feedback"]:
            print(f"   + {item}")

    # Suggestions
    if results["suggestions"]:
        print("\n Suggestions for Improvement:")
        for item in results["suggestions"]:
            print(f"   - {item}")
    else:
        print("\n Excellent! Your password meets all recommended security criteria.")

    print("=" * 60)


def main():
    print("=" * 60)
    print("            PASSWORD STRENGTH CHECKER TOOL")
    print("=" * 60)

    while True:
        print("\nMenu:")
        print("  [1] Check Password Strength")
        print("  [2] Generate a Strong Password")
        print("  [3] Exit")
        choice = input("Enter your choice (1/2/3): ").strip()

        if choice == "1":
            pw = input("\nEnter password to evaluate: ")
            if not pw:
                print("[!] Password cannot be empty.")
                continue
            report = evaluate_password(pw)
            display_report(pw, report)

        elif choice == "2":
            length_input = input("\nEnter desired password length [default 16]: ").strip()
            length = int(length_input) if length_input.isdigit() else 16
            generated = generate_strong_password(length)
            print(f"\nGenerated Password: {generated}")
            report = evaluate_password(generated)
            display_report(generated, report)

        elif choice in ("3", "exit", "q", "quit"):
            print("\nExiting tool. Stay secure!")
            break
        else:
            print("[!] Invalid option. Please enter 1, 2, or 3.")


if __name__ == "__main__":
    main()
