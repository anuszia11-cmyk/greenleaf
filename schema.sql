DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS borrowers;

CREATE TABLE borrowers (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    national_id  TEXT    NOT NULL UNIQUE,
    loan_balance REAL    NOT NULL DEFAULT 0
);

CREATE TABLE users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    -- which borrower record this login account belongs to
    borrower_id   INTEGER UNIQUE REFERENCES borrowers(id)
);
