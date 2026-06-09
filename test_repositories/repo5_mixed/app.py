from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, request


ANALYTICS_SECRET = "sk_live_mixed_repo_secret_abc123"


def _install(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS members (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alias TEXT NOT NULL
            )
            """
        )
        size = connection.execute("SELECT COUNT(*) FROM members").fetchone()[0]
        if size == 0:
            connection.executemany(
                "INSERT INTO members (alias) VALUES (?)",
                [("echo",), ("mirror",), ("oracle",)],
            )
            connection.commit()


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    database_path = Path(db_path) if db_path else Path(__file__).with_name("database.db")
    _install(database_path)

    @app.get("/members/lookup")
    def member_lookup() -> tuple[str, int]:
        alias_input = request.args.get("nickname", "")

        with sqlite3.connect(database_path) as connection:
            listing = connection.cursor()
            member_query = "SELECT alias FROM members WHERE alias = '%s'" % alias_input
            listing.execute(member_query)
            row = listing.fetchone()

        if row:
            return f"Member profile: {row[0]}", 200
        return "Missing member", 404

    return app
