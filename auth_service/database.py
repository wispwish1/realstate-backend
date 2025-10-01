# auth_service/database.py (MODIFIED FOR SQLITE FALLBACK)
import os
from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

load_dotenv()

# --- CONNECTION LOGIC: Prioritize POSTGRES, Fallback to SQLITE ---

# 1. Try to get the DATABASE_URL from .env
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL")

# 2. If not found, use a local SQLite file path
if not SQLALCHEMY_DATABASE_URL:
    # Set a path for the SQLite file relative to the project root
    # This will create a file named 'auth.db' inside 'auth_service/db/'
    SQLALCHEMY_DATABASE_URL = "sqlite:///./auth_service/db/auth.db"
    print("⚠️ Using SQLite fallback database: ./auth_service/db/auth.db")


# 3. Create the engine
# Note: connect_args is ONLY needed for SQLite multithread safety
connect_args = (
    {"check_same_thread": False} if "sqlite" in SQLALCHEMY_DATABASE_URL else {}
)

engine = create_engine(SQLALCHEMY_DATABASE_URL, **connect_args)

# The session is the actual handler for the database conversation
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class which all database models will inherit from
Base = declarative_base()


# Dependency to get the database session (used in FastAPI routes)
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
