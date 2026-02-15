from fastapi import FastAPI
from pwdlib import PasswordHash
from pydantic import BaseModel

from db import get_connection, init_db

app = FastAPI()
init_db()

password_hash = PasswordHash.recommended()


class User(BaseModel):
    username: str
    email: str
    password: str

class oldUser(BaseModel):
    username: str
    password: str


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


@app.post("/auth/login")
def user_login(user: oldUser):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("select * from users where username = ?", (user.username,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return {"error": "enter correct username"}
    if not password_hash.verify(user.password, row["password_hash"]):
        return {"error": "wrong password"}
    return {"SUCCESS!!": f"Welcome {user.username} !!!!"}


@app.post("/auth/register")
def add_user(user: User):
    print(f"{user.username} is recieved!!!")
    print(f"{user.email} is recieved!!!")
    print(f"{user.password} is recieved!!!")
    conn = get_connection()
    cursor = conn.cursor()
    hashed_pass = password_hash.hash(user.password)
    cursor.execute(
        "insert into users (username, email, password_hash) values (?,?,?)",
        (user.username, user.email, hashed_pass),
    )
    conn.commit()
    conn.close()
    return {f"{user.username}":"ADDED!!!"}
