"""
Password Security Analyzer
A beginner-friendly Python cybersecurity project.

Features:
- Checks password length and character variety
- Detects predictable patterns
- Loads common passwords from an external text file
- Saves analysis history to a CSV file
- Does NOT save the actual password
"""

import csv
import os
from datetime import datetime

COMMON_PASSWORDS_FILE = "common_passwords.txt"
HISTORY_FILE = "analysis_history.csv"


def check_length(password):
    return len(password) >= 8


def has_uppercase(password):
    return any(char.isupper() for char in password)


def has_lowercase(password):
    return any(char.islower() for char in password)


def has_number(password):
    return any(char.isdigit() for char in password)


def has_special_character(password):
    special_characters = "!@#$%^&*()_+-=[]{}|;:',.<>?/"
    return any(char in special_characters for char in password)


def has_common_pattern(password):
    patterns = ["123", "abc", "qwerty", "000", "111"]
    lower_password = password.lower()

    for pattern in patterns:
        if pattern in lower_password:
            return True

    return False


def load_common_passwords(filename):
    """Read common passwords from a text file and return them as a set."""
    common_passwords = set()

    try:
        with open(filename, "r", encoding="utf-8") as file:
            for line in file:
                password = line.strip().lower()

                if password:
                    common_passwords.add(password)

    except FileNotFoundError:
        print(f"Warning: {filename} was not found.")
        print("Common-password checking will be skipped.")

    return common_passwords


def is_common_password(password, common_passwords):
    return password.lower() in common_passwords


def analyze_password(password, common_passwords):
    score = 0
    recommendations = []

    if check_length(password):
        score += 1
    else:
        recommendations.append("Use at least 8 characters.")

    if has_uppercase(password):
        score += 1
    else:
        recommendations.append("Add at least one uppercase letter.")

    if has_lowercase(password):
        score += 1
    else:
        recommendations.append("Add at least one lowercase letter.")

    if has_number(password):
        score += 1
    else:
        recommendations.append("Add at least one number.")

    if has_special_character(password):
        score += 1
    else:
        recommendations.append("Add at least one special character.")

    common = is_common_password(password, common_passwords)
    pattern = has_common_pattern(password)

    if common:
        recommendations.append("This password appears in the common-password list.")

        if score > 0:
            score -= 1

    if pattern:
        recommendations.append("Avoid common or predictable patterns such as 123 or qwerty.")

        if score > 0:
            score -= 1

    return score, recommendations, common, pattern


def get_strength(score):
    if score <= 2:
        return "WEAK"
    elif score <= 4:
        return "MODERATE"
    else:
        return "STRONG"


def save_analysis(filename, score, strength, common_password, predictable_pattern):
    """
    Save non-sensitive results to a CSV file.

    Important:
    The actual password is intentionally NOT stored.
    """
    file_exists = os.path.exists(filename)

    with open(filename, "a", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)

        if not file_exists:
            writer.writerow([
                "date_time",
                "score",
                "strength",
                "common_password",
                "predictable_pattern"
            ])

        writer.writerow([
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            score,
            strength,
            common_password,
            predictable_pattern
        ])


def display_results(score, strength, recommendations):
    print("\n" + "-" * 45)
    print(f"Security Score: {score} / 5")
    print(f"Password Strength: {strength}")
    print("-" * 45)

    if recommendations:
        print("\nSecurity Recommendations:")

        for recommendation in recommendations:
            print(f"- {recommendation}")
    else:
        print("\nNo major weaknesses detected by this analyzer.")


def main():
    print("=" * 45)
    print("        PASSWORD SECURITY ANALYZER")
    print("=" * 45)

    common_passwords = load_common_passwords(COMMON_PASSWORDS_FILE)

    password = input("\nEnter a password to analyze: ")

    score, recommendations, common, pattern = analyze_password(
        password,
        common_passwords
    )

    strength = get_strength(score)

    display_results(score, strength, recommendations)

    save_analysis(
        HISTORY_FILE,
        score,
        strength,
        common,
        pattern
    )

    print("\nAnalysis saved to analysis_history.csv.")
    print("For privacy, your actual password was NOT saved.")
    print("=" * 45)


if __name__ == "__main__":
    main()
