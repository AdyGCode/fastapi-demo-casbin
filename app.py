# FastAPI & Casbin Demonstration
#
# Author:           YOUR NAME <EMAIL_ADDRESS>
# Version:          1.0

import csv
import pdb

import casbin
from fastapi import FastAPI, Depends, HTTPException, Request

# Create application instance
app = FastAPI()

# ------------------------------------
# Create/Activate the Casbin Enforcer
# ------------------------------------

enforcer = casbin.Enforcer(
    "casbin_model.conf",
    "casbin_policy.csv"
)

# ------------------------------------
# Helpers
# ------------------------------------

USERS_FILE = "users.csv"


def get_users():
    with open(USERS_FILE, newline="") as csvfile:
        return list(csv.DictReader(csvfile))


def authenticate(request: Request):
    username = request.headers.get("x-username")
    password = request.headers.get("x-password")

    if not username or not password:
        return None

    for user in get_users():
        if user["username"] == username and user["password"] == password:
            return username

    return None


def authorize(username: str, obj: str, act: str):
    if not enforcer.enforce(username, obj, act):
        return HTTPException(status_code=401, detail="Incorrect username or password")


# ------------------------------------
# Routes
# ------------------------------------

@app.get('/insecure')
def insecure():
    return {"detail": "Welcome to Insecure Endpoint"}


@app.get('/secure')
def secure(request: Request):
    user = authenticate(request)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")
    return {"detail": "Authenticated"}


@app.get('/secure/users/list')
def list_users(request: Request):
    user = authenticate(request)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    authorize(user, "/secure/users/list", "GET")

    return {
        "users": [{"name": a_user["username"]} for a_user in get_users()]
    }


@app.post('/secure/users/add')
def add_user(data: dict, request: Request):
    user=authenticate(request)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect username or password")

    authorize(user, "/secure/users/add", "POST")

    new_user = data.get("user")
    if not new_user or "name" not in new_user or "password" not in new_user:
        raise HTTPException(status_code=400,
                            detail="Invalid data payload, missing user and/or password fields")

    # Add the user to the users file
    with open("users.csv", "a") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([new_user["name"], new_user["password"]])

    return {"detail": "User added successfully", "user": {"name": new_user["name"]}}
