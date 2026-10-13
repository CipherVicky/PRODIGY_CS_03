# Prodigy Infotech CS Internship — Task 03
## 🔐 Password Strength Checker

A Python-based **Password Strength Assessment Tool** developed as **Task 3** of my Prodigy InfoTech Cybersecurity Internship. This project evaluates password strength using password length, character diversity, common weak passwords, repeated characters, sequential patterns, and estimated entropy.

It also provides actionable feedback and generates cryptographically strong random passwords.

## 🎯 Project Objective

To develop a password checker that helps users understand password security, identify weaknesses, and create stronger passwords using Python.

## ✨ Features

- **Password Strength Assessment:** Rates passwords as Very Weak, Weak, Moderate, Strong, or Very Strong.
- **Strength Score:** Assigns a score from 0 to 100 with a visual progress bar.
- **Length Analysis:** Checks minimum, recommended, and excellent password lengths.
- **Character Analysis:** Checks for uppercase letters, lowercase letters, digits, and special characters.
- **Weak Password Detection:** Identifies common weak passwords and keywords.
- **Pattern Detection:** Detects sequential characters such as `abc` and `123`, as well as repeated characters such as `aaa`.
- **Entropy Calculation:** Estimates password entropy in bits based on length and character categories.
- **Crack-Time Estimation:** Calculates an illustrative brute-force cracking time using an assumed guessing rate.
- **Strong Password Generator:** Generates random passwords using Python's `secrets` module.
- **Actionable Feedback:** Provides suggestions to improve password strength.
- **Terminal Interface:** Offers a simple interactive menu with colored strength ratings.

## 🛠️ Technologies Used

- **Programming Language:** Python 3
- **Modules:** `re`, `math`, `string`, `secrets`, and `typing`
- **Interface:** Command-line interface (CLI)

All required modules are included with Python, so no additional package installation is needed.

## 📋 Requirements

- Python 3.8 or later
- Linux, Windows, or macOS terminal

## 🚀 Installation and Usage

### 1. Clone the repository

```bash
git clone https://github.com/YOUR-USERNAME/YOUR-REPOSITORY.git
```

Replace `YOUR-USERNAME` and `YOUR-REPOSITORY` with your GitHub username and repository name.

### 2. Navigate to the project directory

```bash
cd YOUR-REPOSITORY
```

### 3. Run the program

If your Python file is named `password_checker.py`, execute:

```bash
python3 password_checker.py
```

### 4. Select an option

The program provides three menu options:

1. **Check Password Strength** — evaluates a password and displays its strength report.
2. **Generate a Strong Password** — generates a random password of the requested length (at least 12 characters).
3. **Exit** — closes the program.

## 📊 Password Evaluation Criteria

| Criterion | Description |
|---|---|
| Length | Rewards longer passwords, with 12+ characters recommended by the tool |
| Lowercase letters | Checks for `a-z` |
| Uppercase letters | Checks for `A-Z` |
| Numbers | Checks for `0-9` |
| Special characters | Checks for symbols such as `!@#$%` |
| Common passwords | Penalizes passwords matching known weak entries or containing common password keywords |
| Repeated characters | Detects three or more consecutive identical characters |
| Sequential patterns | Detects ascending alphabetical or numerical sequences |
| Entropy | Estimates theoretical password search-space entropy |
| Crack time | Estimates brute-force time under an assumed guessing rate |

### Strength Ratings

| Score | Rating |
|---|---|
| 0–29 | Very Weak |
| 30–54 | Weak |
| 55–74 | Moderate |
| 75–89 | Strong |
| 90–100 | Very Strong |

*Note: These are the scoring thresholds implemented in this project.*

## 🧪 Example Usage

Example of a weak password assessment:

```text
============================================================
           PASSWORD STRENGTH ASSESSMENT REPORT
============================================================
 Password Length    : 8 characters
 Strength Rating    : VERY WEAK
 Strength Score     : [....] 
============================================================
```

The actual score, progress bar, entropy, cracking-time estimate, and suggestions depend on the password entered.

To generate a password, select option `2` from the main menu and enter your desired length. The tool will generate a random password and assess its strength.

## 📁 Project Structure

```text
password-strength-checker/
├── password_checker.py
└── README.md
```

The Python filename shown above is an example. Replace it with your actual filename if it differs.

## 🔒 Security Considerations

- Use long, unique passwords for every account.
- Prefer a password manager to store and generate passwords securely.
- Never share real passwords in screenshots, public repositories, or issue reports.
- This tool evaluates passwords locally and does not intentionally transmit them to an external service.
- Passwords entered into the terminal may remain visible while typing, depending on the terminal interface.
- Entropy and cracking-time results are theoretical estimates, not guarantees of real-world security. Actual cracking difficulty depends on password predictability, attacker capabilities, hashing algorithms, and their configurations.
- The common-password list is limited and does not cover every compromised password.

**Important:** This tool is intended for educational purposes and basic password-strength assessment. It is not a replacement for professional password-security auditing.

## 🎓 Learning Outcomes

Through this project, I explored:

- Python programming and modular code organization.
- Regular expressions for password-pattern detection.
- Password-strength scoring and entropy estimation.
- Secure random password generation using the `secrets` module.
- Basic cybersecurity principles and password hygiene.
- Command-line interface development and user feedback.
