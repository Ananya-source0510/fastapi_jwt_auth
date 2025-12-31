from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm

from app.schemas import UserCreate, Token
from app.database import users_db
from app.auth import hash_password, verify_password, create_access_token
from app.dependencies import get_current_user

app = FastAPI(title="FastAPI JWT Auth Example")

# -------------------------------
# Signup
# -------------------------------
@app.post("/signup", status_code=201)
def signup(user: UserCreate):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="User already exists")

    users_db[user.username] = {
        "username": user.username,
        "hashed_password": hash_password(user.password),
    }
    return {"message": "User created successfully"}

# -------------------------------
# Login
# -------------------------------
@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = users_db.get(form_data.username)

    if not user or not verify_password(
        form_data.password, user["hashed_password"]
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )

    access_token = create_access_token(
        data={"sub": user["username"]}
    )

    return {"access_token": access_token, "token_type": "bearer"}

# -------------------------------
# Protected Route
# -------------------------------
@app.get("/protected")
def protected_route(current_user: dict = Depends(get_current_user)):
    return {
        "message": "You have access!",
        "user": current_user["username"],
    }
