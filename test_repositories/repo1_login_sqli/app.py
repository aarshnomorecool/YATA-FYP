from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, request


def _bootstrap(database_file: Path) -> None:
    database_file.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_file) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS crew_accounts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT NOT NULL,
                phrase TEXT NOT NULL
            )
            """
        )
        total = conn.execute("SELECT COUNT(*) FROM crew_accounts").fetchone()[0]
        if total == 0:
            conn.execute(
                "INSERT INTO crew_accounts (display_name, phrase) VALUES (?, ?)",
                ("captain", "mirror123"),
            )
            conn.commit()


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    database_file = Path(db_path) if db_path else Path(__file__).with_name("database.db")
    _bootstrap(database_file)

    @app.post("/session/start")
    def start_session() -> tuple[str, int]:
        handle = request.form.get("handle", "")
        passcode = request.form.get("passcode", "")

        with sqlite3.connect(database_file) as cabin:
            lookup = cabin.cursor()
            lookup_sql = f"SELECT id, display_name FROM crew_accounts WHERE display_name = '{handle}' AND phrase = '{passcode}'"
            lookup.execute(lookup_sql)
            match = lookup.fetchone()

        if match:
            return f"Access granted to {match[1]}", 200
        return "Denied", 401

    return app
