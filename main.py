import os
from datetime import datetime, timedelta, timezone

import dotenv
import jwt
from fastapi import FastAPI, HTTPException
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel, EmailStr

from db import get_connection, init_db

dotenv.load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseException):
    username: str | None = None


class User(BaseModel):
    username: str
    email: EmailStr
    disabled: bool | None = None


class NewUser(User):
    password: str | None = None


class UserInDB(User):
    hashed_password: str


app = FastAPI()
init_db()

password_hash = PasswordHash.recommended()
DUMMY_HASH = password_hash.hash("dummypassword")


def verify_password(plain_password, hashed_password):
    return password_hash.verify(plain_password, hashed_password)


def get_passwrod_hash(password):
    return password_hash.hash(password)


def get_user(db, username: str):
    if username in db:
        user_dict = db[username]
        return UserInDB(**user_dict)


def authenticate_user(fake_db, username: str, password: str):
    user = get_user(fake_db, username)
    if not user:
        verify_password(password, DUMMY_HASH)
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


@app.get("/")
def all_users():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("select * from users")
    rows = cursor.fetchall()
    if rows:
        links = {row["username"]: (row["email"], row["password_hash"]) for row in rows}
        conn.close()
        return links
    else:
        return "NOT FOUND!!"


@app.post("/login")
def user_login(user: UserInDB):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("select * from users where username = ?", (user.username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    print(f"{user.username} is trying to login!!")
    if not password_hash.verify(user.hashed_password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    print(f"{user.username} has logged in successfully!!")
    token = create_access_token({"sub": user.username})
    return Token(access_token=token, token_type="bearer")


@app.post("/register")
def add_user(user: NewUser):
    print(f"Username: {user.username} is recieved!!!")
    print(f"Email: {user.email} is recieved!!!")
    print(f"Password: {user.password} is recieved!!!")
    conn = get_connection()
    cursor = conn.cursor()
    hashed_pass = password_hash.hash(user.password)
    print(f"Hashed Password: {hashed_pass} is recieved!!!")
    cursor.execute("select username from users where username=?", (user.username,))
    row = cursor.fetchone()
    if row:
        conn.close()
        raise HTTPException(status_code=400, detail="Username Not Available!")
    cursor.execute(
        "insert into users (username, email, password_hash) values (?,?,?)",
        (user.username, user.email, hashed_pass),
    )
    conn.commit()
    conn.close()
    print(f"\nNew user: {user.username} registered!!\n")
    return {f"{user.username}": "ADDED!!!"}
