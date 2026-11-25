# Login Attempt Control System

A Python command-line authentication simulation that tracks failed sign-in attempts, enforces a temporary lockout window after repeated failures, and hashes stored credentials with SHA-256.

## Features
- **Brute-Force Mitigation:** Locks an account temporarily after a fixed number of consecutive failed password attempts.
- **Timed Cooldown & Reset:** Blocks sign-ins until the lockout duration expires, then resets attempt counters cleanly.
- **Hashed Credential Checks:** Compares SHA-256 password hashes rather than storing plain-text passwords in memory.

## How to Run
1. Ensure Python 3 is installed on your system.
2. Run the script in your terminal:
   ```bash
   python login_control.py
