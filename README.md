# password_strength_analyzer
import re
import random
import string
import hashlib


class PasswordStrengthAnalyzer:

    def __init__(self):
        self.old_passwords = set()

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def save_password(self, password):
        hashed = self.hash_password(password)
        self.old_passwords.add(hashed)

    def is_reused(self, password):
        hashed = self.hash_password(password)
        return hashed in self.old_passwords

    def analyze(self, password):
        score = 0
        feedback = []

        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password should be at least 8 characters long.")

        if re.search(r"[A-Z]", password):
            score += 1
        else:
            feedback.append("Add uppercase letters.")

        if re.search(r"[a-z]", password):
            score += 1
        else:
            feedback.append("Add lowercase letters.")

        if re.search(r"\d", password):
            score += 1
        else:
            feedback.append("Add numbers.")

        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
            score += 1
        else:
            feedback.append("Add special characters.")

        common_passwords = [
            "password", "123456", "qwerty",
            "admin", "welcome", "password123"
        ]

        if password.lower() in common_passwords:
            score = 0
            feedback.append("This is a very common password.")

        if self.is_reused(password):
            feedback.append("Password was used before. Choose a new one.")
            score -= 1

        if score <= 2:
            strength = "Weak"
        elif score <= 4:
            strength = "Moderate"
        else:
            strength = "Strong"

        return {
            "strength": strength,
            "score": score,
            "feedback": feedback
        }


    def suggest_password(self, length=14):
        characters = (
            string.ascii_letters +
            string.digits +
            "!@#$%^&*"
        )

        while True:
            password = ''.join(random.choice(characters) for _ in range(length))

            if (
                re.search(r"[A-Z]", password) and
                re.search(r"[a-z]", password) and
                re.search(r"\d", password) and
                re.search(r"[!@#$%^&*]", password)
            ):
                return password
if __name__ == "__main__":

    analyzer = PasswordStrengthAnalyzer()

    # Example previously used password
    analyzer.save_password("OldPassword@123")

    print("=== Password Strength Analyzer ===")

    user_password = input("Enter password: ")

    result = analyzer.analyze(user_password)

    print("\nPassword Strength:", result["strength"])
    print("Score:", result["score"])

    if result["feedback"]:
        print("\nSuggestions:")
        for item in result["feedback"]:
            print("-", item)

    if result["strength"] != "Strong":
        print("\nSuggested Strong Password:")
        print(analyzer.suggest_password())
