import uvicorn
from fastapi import FastAPI, Depends, HTTPException, UploadFile, Form, Header
from datetime import timedelta
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles
from database import SessionDep
from dotenv import load_dotenv
from model import *
from sqlmodel import select
import security
import os
import uuid
import database

load_dotenv()

app = FastAPI()
app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")

ACCESS_TOKEN_EXPIRE_MINUTES: int = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30))
SERVER_URL: str = os.getenv("SERVER_URL", "http://localhost:8000")

oauth2_dep = OAuth2PasswordBearer(tokenUrl="/token")


def unauthed():
    raise HTTPException(
        status_code=401,
        detail="Incorrect username or password",
        headers={"WWW-Authenticate": "Bearer"},
    )


@app.post("/login", description="로그인 (토큰 발급)")
async def create_access_token(form_data: OAuth2PasswordRequestForm = Depends()):
    """username 과 password를 OAuth 폼에서 꺼내고
    JWT 액세스 토큰을 반환"""
    user = security.auth_user(form_data.username, form_data.password)
    if not user:
        unauthed()
    expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = security.create_access_token(data={"sub": user.name}, expires=expires) # type: ignore
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/")
def get_all() -> list[PublicUser]:
    return security.get_all()


@app.post("/register", status_code=201, description="회원가입")
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

    
@app.post("/upload", response_model=PublicObject, description="파일 업로드 (JWT 필요)")
async def upload_file(
    file: UploadFile, 
    session: SessionDep, 
    permission: str = Form(...),
    password: str = Form(...),
    current_user: PublicUser = Depends(security.get_current_user_from_header)):
    """파일 업로드 엔드포인트"""
    create_object = CreateObject(permission=permission, password=password)
    if not file.filename:
        raise HTTPException(status_code=400, detail="Filename is required")
    if create_object.permission not in ["public", "private", "password"]:
        raise HTTPException(status_code=400, detail="Invalid permission type")
    if create_object.permission == "password" and not create_object.password:
        raise HTTPException(status_code=400, detail="Password is required for password-protected files")

    file_uuid = uuid.uuid4()
    file_upload = database.Object(
        id=file_uuid,
        size=file.size, # type: ignore
        permission=create_object.permission,
        path="uploads/" + file_uuid.hex + os.path.splitext(file.filename)[1],
        hashed_pw=security.get_hash(create_object.password) if create_object.permission == "password" else None, # type: ignore
        user_id=current_user.name
    )

    try:
        session.add(file_upload)
        session.commit()
        session.refresh(file_upload)  # Refresh to get the updated object with ID
        with open(file_upload.path, "wb") as f:
            f.write(await file.read())
        return PublicObject.model_validate(file_upload)
    except Exception as exc:
        session.rollback()
        raise HTTPException(status_code=500, detail=str(exc))


@app.get("/files", description="내가 업로드한 파일 목록 조회")
async def get_files(
    session: SessionDep, 
    current_user: PublicUser = Depends(security.get_current_user_from_header)):
    """현재 로그인한 유저가 업로드한 파일 목록을 반환"""
    files = session.exec(select(database.Object).where(database.Object.user_id == current_user.name)).all()
    uploaded_files = [PublicObject.model_validate(file) for file in files]
    return uploaded_files


@app.get("/files/{file_id}", response_model=PublicObject, description="파일 메타데이터 조회")
async def get_file(
    file_id: uuid.UUID,
    session: SessionDep,
    x_file_password: str = Header(alias="X-File-Password"),
    current_user: PublicUser = Depends(security.get_current_user_from_header)):
    """파일 ID로 파일 메타데이터 (파일명, 크기, 업로드 시간, 소유자, 접근 권한 등) 조회"""
    file = session.exec(select(database.Object).where(database.Object.id == file_id)).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    if file.user_id != current_user.name and file.permission != "public":
        raise HTTPException(status_code=403, detail="You do not have permission to access this file")
    if file.permission == "password":
        if not security.verify_password(x_file_password, file.hashed_pw): # type: ignore
            raise HTTPException(status_code=403, detail="Invalid password for this file")
    
    return PublicObject.model_validate(file)


@app.put("/files/{file_id}/permission", response_model=PublicObject, description="파일 접근 권한 변경")
async def update_file_permission(
    file_id: uuid.UUID,
    create_object: CreateObject,
    session: SessionDep,
    current_user: PublicUser = Depends(security.get_current_user_from_header)):
    """파일 접근 권한을 변경"""
    if create_object.permission not in ["public", "private", "password"]:
        raise HTTPException(status_code=400, detail="Invalid permission type")
    
    file = session.exec(select(database.Object).where(database.Object.id == file_id)).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    if file.user_id != current_user.name:
        raise HTTPException(status_code=403, detail="You do not have permission to access this file")
    
    file.permission = create_object.permission
    file.hashed_pw = security.get_hash(create_object.password) if create_object.permission == "password" else None
    
    session.add(file)
    session.commit()
    session.refresh(file)
    
    return PublicObject.model_validate(file)


@app.delete("/files/{file_id}", description="파일 삭제")
async def delete_file(
    file_id: uuid.UUID,
    session: SessionDep,
    current_user: PublicUser = Depends(security.get_current_user_from_header)):
    """업로드한 파일을 삭제"""
    file = session.exec(select(database.Object).where(database.Object.id == file_id)).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    if file.user_id != current_user.name:
        raise HTTPException(status_code=403, detail="You do not have permission to delete this file")
    
    session.delete(file)
    session.commit()
    
    # 파일 시스템에서 실제 파일 삭제
    if os.path.exists(file.path):
        os.remove(file.path)
    
    return {"detail": "File deleted successfully"}


@app.get("/download/{file_id}", description="파일 다운로드")
async def download_file(
    file_id: uuid.UUID,
    session: SessionDep,
    x_file_password: str = Header(alias="X-File-Password"),
    current_user: PublicUser = Depends(security.get_current_user_from_header)):
    """파일 ID로 파일 다운로드"""
    file = session.exec(select(database.Object).where(database.Object.id == file_id)).first()
    if not file:
        raise HTTPException(status_code=404, detail="File not found")
    
    if file.user_id != current_user.name and file.permission != "public":
        raise HTTPException(status_code=403, detail="You do not have permission to access this file")
    if file.permission == "password":
        if not security.verify_password(x_file_password, file.hashed_pw): # type: ignore
            raise HTTPException(status_code=403, detail="Invalid password for this file")

    return {"file_url": SERVER_URL + "/" + file.path}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)