import sqlite3
from pathlib import Path

from alembic import command
from alembic.config import Config
from sqlalchemy import URL, Engine, create_engine, event


def create_database_engine(path: Path) -> Engine:
    path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(URL.create("sqlite+pysqlite", database=str(path)))

    @event.listens_for(engine, "connect")
    def configure_sqlite(connection: sqlite3.Connection, _: object) -> None:
        connection.execute("PRAGMA foreign_keys = ON")

    return engine


def upgrade_database(engine: Engine) -> None:
    config = Config()
    config.set_main_option("script_location", "event_switch_manager:migrations")
    with engine.connect() as connection:
        # Take the SQLite writer lock before reading the migration version.
        connection.exec_driver_sql("BEGIN IMMEDIATE")
        config.attributes["connection"] = connection
        command.upgrade(config, "head")
        connection.commit()
