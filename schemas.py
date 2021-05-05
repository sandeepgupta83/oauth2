from typing import List, Optional
from pydantic import BaseModel


class Token(BaseModel):
    access_token: str
    token_type: str


class TokenData(BaseModel):
    username: Optional[str] = None


class OAuthUser(BaseModel):
    username: str


class OAuthUserInDB(OAuthUser):
    hashed_password: str


class OAuthUserCreate(OAuthUser):
    password: str


class OAuthUserResponse(OAuthUserInDB):
    is_active: Optional[bool] = None
    id: int

#================================================


class ItemBase(BaseModel):
    title: str
    description: Optional[str] = None


class ItemCreate(ItemBase):
    pass


class Item(ItemBase):
    id: int
    owner_id: int

    class Config:
        orm_mode = True


class UserBase(BaseModel):
    email: str


class UserCreate(UserBase):
    password: str


class User(UserBase):
    id: int
    is_active: bool
    items: List[Item] = []

    class Config:
        orm_mode = True
