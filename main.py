from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, func
from sqlalchemy.orm import relationship, Session
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker, declarative_base
from passlib.context import CryptContext
import jwt
from datetime import datetime, timedelta
import secrets
import re
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from starlette.middleware.sessions import SessionMiddleware

# Database Configuration
DATABASE_URL = "sqlite+aiosqlite:///./test.db"  # Change this to PostgreSQL in production
engine = create_async_engine(DATABASE_URL, echo=True)
SessionLocal = sessionmaker(bind=engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# Security and Authentication
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
SECRET_KEY = "your_secret_key"
ALGORITHM = "HS256"
TOKEN_EXPIRE_MINUTES = 30
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# FastAPI App Initialization
app = FastAPI(title="FastAPI Backend for Linktr")
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)

# Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    referral_code = Column(String, unique=True, index=True)
    referred_by = Column(Integer, ForeignKey("users.id"), nullable=True)
    created_at = Column(DateTime, default=func.now())
    referrals = relationship("Referral", back_populates="referrer")

class Referral(Base):
    __tablename__ = "referrals"
    id = Column(Integer, primary_key=True, index=True)
    referrer_id = Column(Integer, ForeignKey("users.id"))
    referred_user_id = Column(Integer, ForeignKey("users.id"))
    date_referred = Column(DateTime, default=func.now())
    status = Column(String, default="pending")
    referrer = relationship("User", foreign_keys=[referrer_id])

# Dependency: Get Database Session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Utility Functions
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_jwt_token(data: dict, expires_delta: timedelta):
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Root Endpoint
@app.get("/", tags=["Root"])
async def read_root():
    return {"message": "FastAPI is working!"}

# User Registration
@app.post("/api/register", tags=["User Authentication"])
async def register_user(username: str, email: str, password: str, referral_code: str = None, db: Session = Depends(get_db)):
    if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w{2,}$", email):
        raise HTTPException(status_code=400, detail="Invalid email format")
    hashed_password = hash_password(password)
    new_user = User(
        username=username,
        email=email,
        password_hash=hashed_password,
        referral_code=secrets.token_hex(5),
    )
    if referral_code:
        referrer = db.query(User).filter(User.referral_code == referral_code).first()
        if referrer:
            new_user.referred_by = referrer.id
            referral_entry = Referral(referrer_id=referrer.id, referred_user_id=new_user.id, status="successful")
            db.add(referral_entry)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return {"message": "User registered successfully"}

# User Login
@app.post("/api/login", tags=["User Authentication"])
async def login_user(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_jwt_token({"sub": user.username}, timedelta(minutes=TOKEN_EXPIRE_MINUTES))
    return {"access_token": token, "token_type": "bearer"}

# Password Reset Request
@app.post("/api/forgot-password", tags=["User Authentication"])
async def forgot_password(email: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    reset_token = secrets.token_urlsafe(32)
    return {"message": "Password reset link sent to email", "reset_token": reset_token}

# Referral Stats
@app.get("/api/referral-stats", tags=["Referrals"])
async def referral_stats(username: str, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    count = db.query(Referral).filter(Referral.referrer_id == user.id, Referral.status == "successful").count()
    return {"total_referrals": count}

# Run Database Setup
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
