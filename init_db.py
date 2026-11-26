"""Create the SQLite database and load 10 sample (fictional) borrowers.

Usage:  python init_db.py
Every borrower also gets a demo login: borrower1 ... borrower10 / GreenLeaf@123
"""
import sqlite3
from pathlib import Path

import bcrypt

BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DB = BASE_DIR / "greenleaf.db"

SAMPLE_BORROWERS = [
    (1, "Ayesha Khan", "35202-1111111-1", 25000.00),
    (2, "Bilal Ahmed", "35202-2222222-2", 48000.00),
    (3, "Sana Malik", "35202-3333333-3", 12500.00),
    (4, "Usman Tariq", "35202-4444444-4", 60000.00),
    (5, "Hira Javed", "35202-5555555-5", 8000.00),
    (6, "Kamran Ali", "35202-6666666-6", 33000.00),
    (7, "Fatima Noor", "35202-7777777-7", 15000.00),
    (8, "Zeeshan Raza", "35202-8888888-8", 72000.00),
    (9, "Mariam Iqbal", "35202-9999999-9", 21000.00),
    (10, "Hamza Shah", "35202-1010101-0", 40000.00),
]

DEMO_PASSWORD = "GreenLeaf@123"


def init_db(db_path=DEFAULT_DB):
    conn = sqlite3.connect(db_path)
    conn.executescript((BASE_DIR / "schema.sql").read_text())
    conn.executemany(
        "INSERT INTO borrowers (id, name, national_id, loan_balance) VALUES (?, ?, ?, ?)",
        SAMPLE_BORROWERS,
    )
    for borrower_id, *_ in SAMPLE_BORROWERS:
        pw_hash = bcrypt.hashpw(DEMO_PASSWORD.encode(), bcrypt.gensalt()).decode()
        conn.execute(
            "INSERT INTO users (username, password_hash, borrower_id) VALUES (?, ?, ?)",
            (f"borrower{borrower_id}", pw_hash, borrower_id),
        )
    conn.commit()
    conn.close()


if __name__ == "__main__":
    init_db()
    print(f"Database created at {DEFAULT_DB}")
