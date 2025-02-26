from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from sqlalchemy.orm import Session
from database import engine, SessionLocal, Base
import models
import jwt
from passlib.context import CryptContext
import os

# Initialize FastAPI app
app = FastAPI()

# Initialize database tables
Base.metadata.create_all(bind=engine)

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Secret key for JWT
SECRET_KEY = os.getenv("SECRET_KEY", "mysecretkey")

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# User model for API requests
class UserCreate(BaseModel):
    username: str
    email: str
    password: str
    referral_code: str = None

class UserLogin(BaseModel):
    email: str
    password: str

# Register API
@app.post("/api/register")
def register_user(user: UserCreate, db: Session = Depends(get_db)):
    # Hash password
    hashed_password = pwd_context.hash(user.password)
    
    # Create user object
    db_user = models.User(
        username=user.username, 
        email=user.email, 
        password=hashed_password, 
        referral_code=user.referral_code
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return {"message": "User registered successfully"}

# Login API
@app.post("/api/login")
def login_user(user: UserLogin, db: Session = Depends(get_db)):
    db_user = db.query(models.User).filter(models.User.email == user.email).first()
    
    if not db_user or not pwd_context.verify(user.password, db_user.password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate JWT token
    token = jwt.encode({"sub": db_user.email}, SECRET_KEY, algorithm="HS256")
    return {"access_token": token, "token_type": "bearer"}

# API Root
@app.get("/")
def read_root():
    return {"message": "FastAPI backend is working!"}
