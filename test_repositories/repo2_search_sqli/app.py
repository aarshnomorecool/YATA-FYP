from __future__ import annotations

import sqlite3
from pathlib import Path

from flask import Flask, request


def _seed(database_path: Path) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS catalog (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                item_name TEXT NOT NULL
            )
            """
        )
        count = connection.execute("SELECT COUNT(*) FROM catalog").fetchone()[0]
        if count == 0:
            connection.executemany(
                "INSERT INTO catalog (item_name) VALUES (?)",
                [("onyx",), ("mirror",), ("lantern",)],
            )
            connection.commit()


def create_app(db_path: str | None = None) -> Flask:
    app = Flask(__name__)
    database_path = Path(db_path) if db_path else Path(__file__).with_name("database.db")
    _seed(database_path)

    @app.get("/catalog/search")
    def search_catalog() -> tuple[str, int]:
        search_phrase = request.args.get("phrase", "")

        with sqlite3.connect(database_path) as connection:
            search_cursor = connection.cursor()
            probe = "SELECT item_name FROM catalog WHERE item_name = '{}'".format(search_phrase)
            search_cursor.execute(probe)
            row = search_cursor.fetchone()

        if row:
            return f"Search hit: {row[0]}", 200
        return "Not found", 404

    return app
