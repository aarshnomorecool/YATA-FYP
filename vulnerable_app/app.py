from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, request


def _init_db(db_path: Path) -> None:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(db_path) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                password TEXT NOT NULL
            )
            """
        )
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("admin", "admin123"))
            conn.commit()


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    database_path = Path(db_path) if db_path else Path(__file__).with_name("database.db")
    _init_db(database_path)

    @app.get("/")
    def index() -> str:
        return "YATA demo app"

    @app.post("/login")
    def login() -> tuple[str, int]:
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        with sqlite3.connect(database_path) as conn:
            cursor = conn.cursor()
            query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
            cursor.execute(query)
            row = cursor.fetchone()

        if row:
            return f"Welcome {row[1]}", 200
        return "Invalid credentials", 401

    return app


if __name__ == "__main__":
    create_app().run(debug=True, port=5000)
