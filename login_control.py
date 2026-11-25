import hashlib
import time


MAX_FAILED_ATTEMPTS = 3
LOCKOUT_DURATION_SECONDS = 30

# Demo user store with SHA-256 hashed passwords
USER_CREDENTIALS = {
    "student": hashlib.sha256("SecurePass@123".encode("utf-8")).hexdigest(),
    "admin": hashlib.sha256("AdminAccess#99".encode("utf-8")).hexdigest(),
}

login_state = {
    username: {"failed_attempts": 0, "locked_until": 0.0}
    for username in USER_CREDENTIALS
}


def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()


def check_lockout(username: str) -> float:
    """Return remaining lockout seconds if locked, otherwise 0.0."""
    state = login_state[username]
    now = time.time()
    if state["locked_until"] > now:
        return round(state["locked_until"] - now, 1)
    if state["locked_until"] != 0.0:
        # Lockout period expired; reset counter for a fresh window
        state["locked_until"] = 0.0
        state["failed_attempts"] = 0
    return 0.0


def attempt_login(username: str, password: str) -> tuple[bool, str]:
    username = username.strip().lower()
    if username not in USER_CREDENTIALS:
        return False, "Invalid username or password."

    remaining = check_lockout(username)
    if remaining > 0:
        return False, f"Account temporarily locked. Try again in {remaining} seconds."

    if hash_password(password) == USER_CREDENTIALS[username]:
        login_state[username]["failed_attempts"] = 0
        login_state[username]["locked_until"] = 0.0
        return True, f"Login successful! Welcome back, {username}."

    state = login_state[username]
    state["failed_attempts"] += 1
    attempts_left = MAX_FAILED_ATTEMPTS - state["failed_attempts"]

    if state["failed_attempts"] >= MAX_FAILED_ATTEMPTS:
        state["locked_until"] = time.time() + LOCKOUT_DURATION_SECONDS
        return (
            False,
            f"Too many failed attempts ({MAX_FAILED_ATTEMPTS}). "
            f"Account locked for {LOCKOUT_DURATION_SECONDS} seconds.",
        )

    return False, f"Incorrect password. {attempts_left} attempt(s) remaining before lockout."


def main():
    print("=== Login Attempt Control System ===")
    print(f"Policy: Lock account for {LOCKOUT_DURATION_SECONDS}s after {MAX_FAILED_ATTEMPTS} failed attempts.")
    print("Demo users: 'student' or 'admin' (type 'exit' as username to quit)\n")

    while True:
        username = input("Username: ").strip()
        if username.lower() == "exit":
            print("Exiting login system.")
            break

        password = input("Password: ")
        success, message = attempt_login(username, password)
        print(f"[{ 'ALLOWED' if success else 'BLOCKED' }] {message}\n")


if __name__ == "__main__":
    main()
