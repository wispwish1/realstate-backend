# auth_service/app.py (FINAL FIXED VERSION)
import os
import random
import string
import datetime
from typing import List, Optional
import asyncio

from dotenv import load_dotenv

# FastAPI/Auth Core
from fastapi import FastAPI, Depends, HTTPException, status, APIRouter, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import create_engine, Column, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
from jose import JWTError, jwt
from flask_cors import CORS

from datetime import datetime, timedelta


# SendGrid & Twilio Imports
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail as SendGridMail
from twilio.rest import Client as TwilioClient

# --- Load Environment Variables ---
load_dotenv()
CORS(app)  # Allow sab origins ke liye (development ke liye theek hai)
CORS(app, resources={r"/*": {"origins": "http://localhost:5173"}})

# --- Configuration ---
AUTH_SECRET_KEY = os.environ.get("AUTH_SECRET_KEY")
if not AUTH_SECRET_KEY:
    raise RuntimeError(
        "AUTH_SECRET_KEY is not set. Please configure it in the environment."
    )

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60  # 1 hour
OTP_EXPIRE_MINUTES = 10

# Twilio & SendGrid Clients
TWILIO_ACCOUNT_SID = os.environ.get("TWILIO_ACCOUNT_SID")
TWILIO_AUTH_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN")
TWILIO_PHONE_NUMBER = os.environ.get("TWILIO_PHONE_NUMBER")
SENDGRID_API_KEY = os.environ.get("SENDGRID_API_KEY")
MAIL_FROM_EMAIL = os.environ.get("MAIL_FROM_EMAIL")

# --- Database Setup (Simple Auto-Create) ---
SQLALCHEMY_DATABASE_URL = os.environ.get("DATABASE_URL")
if not SQLALCHEMY_DATABASE_URL:
    SQLALCHEMY_DATABASE_URL = "sqlite:///./db/auth.db"
    print("⚠️ Using SQLite fallback database: ./db/auth.db")

if SQLALCHEMY_DATABASE_URL.startswith("sqlite"):
    engine = create_engine(
        SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
    )
else:
    engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# --- Pydantic Schemas ---
class RegisterData(BaseModel):
    username: str
    email: EmailStr
    password: str
    phone_number: Optional[str] = None


class LoginData(BaseModel):
    email: EmailStr
    password: str


class LoginResponse(BaseModel):
    access_token: str
    token_type: str
    role: str
    user_id: int


class OTPRequest(BaseModel):
    email: EmailStr
    send_via_sms: bool = False


class PasswordReset(BaseModel):
    email: EmailStr
    otp: str
    new_password: str


class MessageResponse(BaseModel):
    msg: str


# Password Hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


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


# --- Dependencies ---
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_password_hash(password):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, AUTH_SECRET_KEY, algorithm=ALGORITHM)


def get_current_user_claims(authorization: str = Header(None)):
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header missing",
        )
    try:
        token = authorization.split(" ")[1]
        payload = jwt.decode(token, AUTH_SECRET_KEY, algorithms=["HS256"])
        return payload
    except (JWTError, IndexError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token"
        )


def admin_required(claims: dict = Depends(get_current_user_claims)):
    if claims.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administration rights required",
        )
    return claims


# --- Helper Functions: SendGrid & Twilio ---
async def send_otp_email(email: str, otp: str):
    if not SENDGRID_API_KEY or not MAIL_FROM_EMAIL:
        print(f"⚠️ SendGrid not configured. OTP for {email}: {otp}")
        return

    message = SendGridMail(
        from_email=MAIL_FROM_EMAIL,
        to_emails=email,
        subject="Password Reset OTP",
        html_content=f"<h1>OTP</h1><p>Code: {otp}</p>",
    )

    try:
        loop = asyncio.get_event_loop()
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        # Run in a thread to avoid blocking async loop
        response = await loop.run_in_executor(None, sg.send, message)
        print(f"✅ Email sent to {email}, status: {response.status_code}")
    except Exception as e:
        print(f"❌ Error sending email via SendGrid: {e}")


async def send_otp_sms(phone_number: str, otp: str):
    if not all([TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_PHONE_NUMBER]):
        print(f"⚠️ Twilio not configured. OTP for SMS {phone_number}: {otp}")
        return
    try:
        client = TwilioClient(TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN)
        client.messages.create(
            to=phone_number, from_=TWILIO_PHONE_NUMBER, body=f"OTP: {otp}"
        )
    except Exception as e:
        print(f"❌ Error sending SMS via Twilio: {e}")


def generate_otp_for_user(db, user):
    otp = str(random.randint(100000, 999999))
    user.reset_otp = otp
    user.reset_otp_expires = datetime.utcnow() + timedelta(minutes=10)
    db.commit()
    db.refresh(user)
    return otp


# ------------------------------------------------------------------
# --- APPLICATION SETUP ---
# ------------------------------------------------------------------
app = FastAPI(title="FastAPI Auth Service")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://haseeb467.pythonanywhere.com" , "http://localhost:3000" , "http://localhost:5173/" ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Routers
auth_router = APIRouter(prefix="/auth", tags=["Authentication"])
admin_router = APIRouter(prefix="/admin", tags=["Admin Management"])


# ------------------------------------------------------------------
# --- ROUTES DEFINITIONS ---
# ------------------------------------------------------------------
@auth_router.post("/register", response_model=MessageResponse)
async def register_user(user: RegisterData, db: Session = Depends(get_db)):
    if (
        db.query(User).filter(User.username == user.username).first()
        or db.query(User).filter(User.email == user.email).first()
    ):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already registered",
        )
    role = "admin" if db.query(User).count() == 0 else "user"
    db_user = User(
        username=user.username,
        email=user.email,
        phone_number=user.phone_number,
        password_hash=get_password_hash(user.password),
        role=role,
    )
    db.add(db_user)
    db.commit()
    return {"msg": "User created successfully"}


@auth_router.post("/login", response_model=LoginResponse)
async def login_for_access_token(data: LoginData, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials"
        )
    access_token = create_access_token(
        data={"sub": user.username},
        expires_delta=timedelta(minutes=60),  # ✅ just timedelta
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "user_id": user.id,
    }


@auth_router.post("/forgot-password/request-otp", response_model=MessageResponse)
async def request_password_otp(data: OTPRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if user:
        otp = generate_otp_for_user(db, user)
        if data.send_via_sms:
            if not user.phone_number:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="User has no phone number registered for SMS OTP.",
                )
            await send_otp_sms(user.phone_number, otp)
        else:
            await send_otp_email(user.email, otp)
    send_method = "SMS" if data.send_via_sms else "email"
    return {
        "msg": f"If the email is in our system, an OTP has been sent via {send_method}."
    }


@auth_router.post("/forgot-password/reset", response_model=MessageResponse)
async def reset_password_with_otp(data: PasswordReset, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Invalid email."
        )
    now = datetime.datetime.utcnow()
    is_otp_valid = (
        user.reset_otp == data.otp
        and user.reset_otp_expires
        and user.reset_otp_expires > now
    )
    if is_otp_valid:
        user.password_hash = get_password_hash(data.new_password)
        user.reset_otp = None
        user.reset_otp_expires = None
        db.commit()
        return {"msg": "Password reset successfully."}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired OTP."
        )


# --- ADMIN ROUTES ---
@admin_router.get(
    "/users", response_model=List[RegisterData]
)  # Replace with UserDB model later
async def get_all_users(
    db: Session = Depends(get_db), claims: dict = Depends(admin_required)
):
    users = db.query(User).all()
    return users


# ------------------------------------------------------------------
# --- INCLUDE ROUTERS (must be at the END) ---
# ------------------------------------------------------------------
app.include_router(auth_router)
app.include_router(admin_router)


# --- CREATE TABLES ON STARTUP ---
@app.on_event("startup")
def startup_event():
    Base.metadata.create_all(bind=engine)
    print("Database tables checked/created.")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
