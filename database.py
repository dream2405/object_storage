from dotenv import load_dotenv
from typing import Annotated
from fastapi import Depends
from sqlmodel import Field, Session, SQLModel, create_engine, Relationship, UniqueConstraint
from datetime import datetime, timezone
import os
import uuid

load_dotenv()

USERNAME = os.getenv("DB_USERNAME")
PASSWORD = os.getenv("DB_PASSWORD")
HOST = os.getenv("DB_HOST")
PORT = os.getenv("DB_PORT")
DATABASE = os.getenv("DB_NAME")
DATABASE_URL = f"mysql+pymysql://{USERNAME}:{PASSWORD}@{HOST}:{PORT}/{DATABASE}"

engine = create_engine(DATABASE_URL, echo=True)

def get_session():
    """Create a new SQLModel session."""
    with Session(engine) as session:
        yield session

SessionDep = Annotated[Session, Depends(get_session)]

class User(SQLModel, table=True):
    id: str = Field(default=None, primary_key=True)
    hashed_pw: str = Field(default=None, nullable=False)
    objects: list["Object"] = Relationship(back_populates="user")

class Object(SQLModel, table=True):
    id: uuid.UUID = Field(default_factory=uuid.uuid4, primary_key=True)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc), nullable=False)
    size: float = Field(nullable=False)
    permission: str = Field(nullable=False, sa_column_kwargs={"comment": "공개/비공개/비밀번호"})
    path: str = Field(nullable=False)
    user_id: str = Field(foreign_key="user.id", nullable=False)
    user: User = Relationship(back_populates="objects")

if __name__ == "__main__":
    SQLModel.metadata.drop_all(engine)
    SQLModel.metadata.create_all(engine)
    print(DATABASE_URL)
    print("Database tables created successfully.")