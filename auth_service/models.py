# auth_service/models.py
from sqlalchemy import Column, Integer, String, DateTime
from .database import Base  # Import Base from our new database module


# --- Database Model: User ---
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    phone_number = Column(String, nullable=True)
    password_hash = Column(String)
    role = Column(String, default="user")
    reset_otp = Column(String, nullable=True)
    reset_otp_expires = Column(DateTime, nullable=True)
