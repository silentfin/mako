import os
from datetime import datetime, timedelta, timezone

import dotenv
import jwt
from fastapi import FastAPI, HTTPException
from jwt.exceptions import InvalidTokenError
from pwdlib import PasswordHash
from pydantic import BaseModel

from db import get_connection, init_db

dotenv.load_dotenv()

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 5

app = FastAPI()
init_db()

password_hash = PasswordHash.recommended()


class User(BaseModel):
    username: str
    email: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class Token(BaseModel):
    access_token: str
    token_type: str


def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt


#
# @app.get("/")
# def all_users():
#     conn = get_connection()
#     cursor = conn.cursor()
#     cursor.execute("select * from users")
#     rows = cursor.fetchall()
#     if rows:
#         links = {row["username"]: (row["email"], row["password_hash"]) for row in rows}
#         conn.close()
#         return links
#     else:
#         return "NOT FOUND!!"
#


@app.post("/auth/login")
def user_login(user: LoginRequest):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("select * from users where username = ?", (user.username,))
    row = cursor.fetchone()
    conn.close()
    print(f"{user.username} is trying to login!!")
    if not row:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not password_hash.verify(user.password, row["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    print(f"{user.username} has logged in successfully!!")
    token = create_access_token({"sub": user.username})
    # return {"SUCCESS!!": f"Welcome {user.username} !!!!"}
    return Token(access_token=token, token_type="bearer")


@app.post("/auth/register")
def add_user(user: User):
    print(f"Username: {user.username} is recieved!!!")
    print(f"Email: {user.email} is recieved!!!")
    print(f"Password: {user.password} is recieved!!!")
    conn = get_connection()
    cursor = conn.cursor()
    hashed_pass = password_hash.hash(user.password)
    cursor.execute("select username from users where username=?", (user.username,))
    row = cursor.fetchone()
    if row:
        conn.close()
        raise HTTPException(
            status_code=400, detail="username already exists! login instead"
        )
    cursor.execute(
        "insert into users (username, email, password_hash) values (?,?,?)",
        (user.username, user.email, hashed_pass),
    )
    conn.commit()
    conn.close()
    print(f"\nNew user: {user.username} registered!!\n")
    return {f"{user.username}": "ADDED!!!"}
