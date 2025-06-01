import uvicorn
from fastapi import FastAPI, Depends, HTTPException
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from database import get_session, SessionDep
from dotenv import load_dotenv
from model import PublicUser, SignInUser, PrivateUser
import security
import os

load_dotenv()

app = FastAPI()

ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))

oauth2_dep = OAuth2PasswordBearer(tokenUrl="/token")


def unauthed():
    raise HTTPException(
        status_code=401,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.post("/token")
async def create_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """username 과 password를 OAuth 폼에서 꺼내고
    JWT 액세스 토큰을 반환"""
    user = security.auth_user(form_data.username, form_data.password)
    if not user:
        unauthed()
    expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(data={"sub": user.name}, expires=expires) # type: ignore
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/token")
def get_access_token(token: str = Depends(oauth2_dep)) -> dict:
    """현재 액세스 토큰을 반환"""
    return {"token": token}

@app.get("/")
def get_all() -> list[PublicUser]:
    return security.get_all()


@app.get("/{name}")
def get_one(name) -> PublicUser:
    try:
        return security.get_one(name)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.post("/", status_code=201)
def create(user: SignInUser) -> PublicUser:
    """새로운 유저를 생성"""
    if not user.name or not user.password:
        raise HTTPException(status_code=400, detail="Username and password are required")
    if security.lookup_user(user.name):
        raise HTTPException(status_code=409, detail="Username already exists")
    user_create = PrivateUser(name=user.name, hash=security.get_hash(user.password))
    try:
        return security.create(user_create)
    except Exception as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@app.patch("/{name}")
def modify(name: str, user: PublicUser) -> PublicUser:
    """유저 정보를 수정"""
    if not user.name:
        raise HTTPException(status_code=400, detail="Username is required")
    if not security.lookup_user(name, is_public=False):
        raise HTTPException(status_code=404, detail="User not found")
    try:
        return security.modify(name, user)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@app.delete("/{name}")
def delete(name: str) -> None:
    try:
        return security.delete(name)
    except Exception as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)