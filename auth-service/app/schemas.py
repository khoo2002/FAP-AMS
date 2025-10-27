from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime

class UserCreate(BaseModel):
    email: str
    password: str

class AdminUserCreate(BaseModel):
    email: str
    password: str
    roles: list[str] = []

class ApproveUser(BaseModel):
    email: str
    approve: bool = True

class ChangePassword(BaseModel):
    email: str
    new_password: str

class RolePayload(BaseModel):
    role: str
    description: Optional[str] = None

class RoleUpdate(BaseModel):
    role: str  # current name
    new_name: Optional[str] = None
    description: Optional[str] = None

class AssignRoleUnassign(BaseModel):
    email: str
    role: str
    unassign: bool = False

class RemoveUser(BaseModel):
    email: str

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class AssignRole(BaseModel):
    email: str
    role: str

class UserOut(BaseModel):
    id: int
    email: str
    roles: List[str] = []
    created_at: Optional[datetime] = None
    last_login: Optional[datetime] = None
    is_active: Optional[bool] = None
    class Config:
        orm_mode = True

class RoleOut(BaseModel):
    name: str
    description: Optional[str] = None
    class Config:
        orm_mode = True

class PasswordResetCreate(BaseModel):
    email: str

class PasswordResetUse(BaseModel):
    token: str
    new_password: str
