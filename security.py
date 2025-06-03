from model import PublicUser, PrivateUser, SignInUser
from sqlmodel import create_engine, Session, select
from sqlalchemy.exc import IntegrityError
from database import engine, User
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from jose.exceptions import JWTError
from datetime import timedelta, datetime, timezone
from dotenv import load_dotenv
import bcrypt
import os

load_dotenv()

SECRET_KEY: str = os.getenv("SECRET_KEY", "")
ALGORITHM : str = os.getenv("ALGORITHM", "")

security = HTTPBearer()

# is_public 인자에 따라 나가는 모델이 분기된다.
def row_to_model(row: User, is_public: bool = True) -> PublicUser | PrivateUser:
    name, hash = row.id, row.hashed_pw
    if is_public:
        return PublicUser(name=name)
    else:
        return PrivateUser(name=name, hash=hash)


def model_to_dict(user: PrivateUser) -> dict:
    return user.model_dump()


# 유저 조회는 is_public에 따라  PublicUser 또는 PrivateUser를 리턴한다.
def get_one(name: str, is_public: bool = True) -> PublicUser | PrivateUser:
    with Session(engine) as session:
        curs = session.exec(select(User).where(User.id == name))
        if curs.first() is None:
            raise Exception(f"User {name} not found")
        return row_to_model(curs.one(), is_public=is_public)


# 유저리스트 조회에서는 민감정보(hash)를 포함할 일이 없기 때문에 PublicUser 모델 집합을 리턴한다.
def get_all() -> list[PublicUser]:
    with Session(engine) as session:
        curs = session.exec(select(User))
        return [row_to_model(row) for row in curs]


# 유저 생성을 위해서는 password를 암호화한 hash 값을 저장해야 한다.
# create 함수는 user 인자가 hash 값을 가지고 있는 것으로 간주한다.
# 저장이 완료되면 외부로 노출되도 되는 PublicUser를 리턴한다.
def create(user: PrivateUser) -> PublicUser: # type: ignore
    """user 테이블에 유저를 생성"""
    with Session(engine) as session:
        user_instance = User(id=user.name, hashed_pw=user.hash)
        User.model_validate(user_instance)  # Validate the model
        try:
            session.add(user_instance)
            session.commit()
            session.refresh(user_instance)  # Refresh to get the latest state
            return row_to_model(user_instance, is_public=True)
        except IntegrityError:
            session.rollback()
            raise Exception(f"user {user.name} already exists")


def modify(name: str, user: PublicUser) -> PublicUser:
    """name으로 조회한 유저의 이름을 수정"""
    with Session(engine) as session:
        curs = session.exec(select(User).where(User.id == name))
        user_instance: User = curs.one()
        user_instance.id = user.name
        User.model_validate(user_instance)
        session.add(user_instance)
        session.commit()
        return row_to_model(user_instance, is_public=True)


def delete(name: str) -> None:
    """name으로 user 테이블에서 조회한 유저를 삭제"""
    with Session(engine) as session:
        curs = session.exec(select(User).where(User.id == name))
        user: User = curs.one()
        session.delete(user)
        session.commit()


def verify_password(plain: str, hash: str) -> bool:
    """plain을 해시 값과, 데이터베이스의 hash 값과 비교"""
    password_bytes = plain.encode("utf-8")
    hash_bytes = hash.encode("utf-8")
    is_valid = bcrypt.checkpw(password_bytes, hash_bytes)
    return is_valid


def get_hash(plain: str) -> str:
    """plain의 해시값을 반환"""
    password_bytes = plain.encode("utf-8")
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password_bytes, salt)
    return hashed_password.decode("utf-8")


def get_jwt_username(token: str) -> str | None:
    """JWT 액세스 토큰으로부터 username을 반환"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not (username := payload.get("sub")):
            return None
    except JWTError:
        return None
    return username


def get_current_user(token: str) -> PublicUser | None:
    """OAuth 토큰을 풀어서 PublicUser를 반환한다"""
    if not (username := get_jwt_username(token)):
        return None
    if user := lookup_user(username):
        return user
    return None


def lookup_user(username: str, is_public=True) -> PublicUser | PrivateUser | None:
    """데이터베이스에서 username에 매칭되는 User를 반환한다
    is_public이 True이면 PublicUser를 반환하고, False이면 PrivateUser를 반환한다.
    hash 속성은 PrivateUser만 가지고 있다. 비밀번호 인증을 위해서 hash 속성이 필요하다.
    """
    with Session(engine) as session:
        curs = session.exec(select(User).where(User.id == username))
        user: User | None = curs.one_or_none()
        if user:
            return row_to_model(user, is_public=is_public)
    return None


def auth_user(name: str, plain: str) -> PublicUser | PrivateUser | None:
    """name과 plain 암호로 유저를 인증"""
    if not (user := lookup_user(name, is_public=False)):
        return None
    if not verify_password(plain, user.hash): # type: ignore
        return None
    return user


def create_access_token(data: dict, expires: timedelta | None = None):
    """JWT 액세스 토큰을 반환"""
    src = data.copy()
    now = datetime.now(tz=timezone.utc)
    if not expires:
        expires = timedelta(minutes=15)
    src.update({"exp": now + expires})
    encoded_jwt = jwt.encode(src, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user_from_header(credentials: HTTPAuthorizationCredentials = Depends(security)) -> PublicUser:
    token = credentials.credentials
    user = get_current_user(token)
    
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    return user