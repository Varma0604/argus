from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import DATABASE_URL


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


def get_db():
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def ensure_schema():
    """Create fresh tables and apply additive columns for the pre-migration prototype."""
    Base.metadata.create_all(bind=engine)
    additions = {
        "dependencies": {"ecosystem": "VARCHAR(30) DEFAULT 'PyPI'", "manifest_path": "VARCHAR(500)"},
        "scans": {"lease_owner": "VARCHAR(120)", "lease_expires_at": "TIMESTAMP"},
    }
    with engine.begin() as connection:
        for table, columns in additions.items():
            existing = {column["name"] for column in inspect(connection).get_columns(table)}
            for name, sql_type in columns.items():
                if name not in existing:
                    connection.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {sql_type}"))
