from fastapi import FastAPI, HTTPException, Depends, status, BackgroundTasks
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from typing import List, Optional
from datetime import datetime, timedelta
from jose import JWTError, jwt
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, ForeignKey, Text, Enum
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship, Session
import hashlib, difflib
from enum import Enum as PyEnum

# Database setup
SQLALCHEMY_DATABASE_URL = "sqlite:///./test.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Auth settings
SECRET_KEY = "secret"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

# FastAPI app
app = FastAPI()

# Roles
class RoleEnum(PyEnum):
    OWNER = "Owner"
    EDITOR = "Editor"
    VIEWER = "Viewer"

# Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    password = Column(String)

class Event(Base):
    __tablename__ = "events"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String)
    description = Column(Text)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    is_recurring = Column(Boolean, default=False)
    recurrence_pattern = Column(String, nullable=True)
    owner_id = Column(Integer, ForeignKey("users.id"))

class Permission(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True, index=True)
    event_id = Column(Integer, ForeignKey("events.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    role = Column(Enum(RoleEnum))

class EventVersion(Base):
    __tablename__ = "event_versions"
    id = Column(Integer, primary_key=True)
    event_id = Column(Integer)
    version_number = Column(Integer)
    title = Column(String)
    description = Column(Text)
    start_time = Column(DateTime)
    end_time = Column(DateTime)
    edited_by = Column(Integer)
    timestamp = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

# DB Schemas
class UserCreate(BaseModel):
    username: str
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class EventCreate(BaseModel):
    title: str
    description: Optional[str]
    start_time: datetime
    end_time: datetime
    is_recurring: Optional[bool] = False
    recurrence_pattern: Optional[str] = None

class EventOut(EventCreate):
    id: int
    owner_id: int

    class Config:
        orm_mode = True

class PermissionUpdate(BaseModel):
    user_id: int
    role: RoleEnum

class ShareRequest(BaseModel):
    users: List[PermissionUpdate]

# Utility functions
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def create_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_user_by_token(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")

# Auth routes
@app.post("/api/auth/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    db_user = User(username=user.username, email=user.email, password=hash_password(user.password))
    db.add(db_user)
    db.commit()
    return {"message": "User created"}

@app.post("/api/auth/login", response_model=Token)
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form.username).first()
    if not user or hash_password(form.password) != user.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token({"sub": str(user.id)})
    return {"access_token": token, "token_type": "bearer"}

@app.post("/api/auth/refresh", response_model=Token)
def refresh_token(user: User = Depends(get_user_by_token)):
    new_token = create_token({"sub": str(user.id)})
    return {"access_token": new_token, "token_type": "bearer"}

@app.post("/api/auth/logout")
def logout():
    # With JWTs, logout is handled client-side unless token blacklisting is implemented.
    return {"message": "Client should delete the token. JWT stateless logout."}

# Event routes
@app.post("/api/events", response_model=EventOut)
def create_event(event: EventCreate, db: Session = Depends(get_db), user: User = Depends(get_user_by_token)):
    db_event = Event(**event.dict(), owner_id=user.id)
    db.add(db_event)
    db.commit()
    db.refresh(db_event)
    return db_event

@app.get("/api/events", response_model=List[EventOut])
def list_events(db: Session = Depends(get_db), user: User = Depends(get_user_by_token)):
    # Lists only events where the user is the owner.
    return db.query(Event).filter(Event.owner_id == user.id).all()

@app.put("/api/events/{id}")
def update_event(id: int, update: EventCreate, db: Session = Depends(get_db), user: User = Depends(get_user_by_token)):
    event = db.query(Event).filter(Event.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.owner_id != user.id:
        perm = db.query(Permission).filter(Permission.event_id == id, Permission.user_id == user.id).first()
        if not perm or perm.role not in [RoleEnum.OWNER, RoleEnum.EDITOR]:
            raise HTTPException(status_code=403, detail="Insufficient permission to update event")
    for k, v in update.dict().items():
        setattr(event, k, v)
    version = EventVersion(
        event_id=id,
        version_number=int(datetime.utcnow().timestamp()),
        title=event.title,
        description=event.description,
        start_time=event.start_time,
        end_time=event.end_time,
        edited_by=user.id
    )
    db.add(version)
    db.commit()
    return {"message": "Updated"}

@app.delete("/api/events/{id}")
def delete_event(id: int, db: Session = Depends(get_db), user: User = Depends(get_user_by_token)):
    event = db.query(Event).filter(Event.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Insufficient permission to delete event")
    db.delete(event)
    db.commit()
    return {"message": "Deleted"}

# Permissions and Collaboration routes
@app.post("/api/events/{id}/share")
def share_event(
    id: int,
    req: ShareRequest,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    # Check if the event exists and if the current user is the owner
    event = db.query(Event).filter(Event.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Only event owner can share the event")
    
    for u in req.users:
        perm = Permission(event_id=id, user_id=u.user_id, role=u.role)
        db.add(perm)
    db.commit()
    return {"message": "Shared"}

@app.get("/api/events/{id}/permissions")
def get_permissions(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    perms = db.query(Permission).filter(Permission.event_id == id).all()
    return [f"user: {p.user_id}, role: {p.role.value}" for p in perms]

@app.put("/api/events/{id}/permissions/{user_id}")
def update_permission(
    id: int,
    user_id: int,
    update: PermissionUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    perm = db.query(Permission).filter_by(event_id=id, user_id=user_id).first()
    if not perm:
        raise HTTPException(status_code=404, detail="Permission not found")
    perm.role = update.role
    db.commit()
    return {"detail": "Permission updated"}

# Version History and Diff routes
@app.get("/api/events/{id}/history/{version_id}")
def history(
    id: int,
    version_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    version = (
        db.query(EventVersion)
          .filter(EventVersion.id == version_id, EventVersion.event_id == id)
          .first()
    )
    if not version:
        raise HTTPException(status_code=404, detail="Version not found for the specified event")
    return version

@app.post("/api/events/{id}/rollback/{version_id}")
def rollback(
    id: int,
    version_id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    version = (
        db.query(EventVersion)
          .filter(EventVersion.id == version_id, EventVersion.event_id == id)
          .first()
    )
    if not version:
        raise HTTPException(status_code=404, detail="Version not found for the specified event")
    
    event = db.query(Event).filter(Event.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.owner_id != user.id:
        raise HTTPException(status_code=403, detail="Insufficient permissions to roll back the event")
    
    event.title = version.title
    event.description = version.description
    event.start_time = version.start_time
    event.end_time = version.end_time
    db.commit()
    return {"message": "Rolled back"}

@app.get("/api/events/{id}/diff/{v1}/{v2}")
def diff(
    id: int,
    v1: int,
    v2: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    ver1 = db.query(EventVersion).filter(EventVersion.id == v1, EventVersion.event_id == id).first()
    ver2 = db.query(EventVersion).filter(EventVersion.id == v2, EventVersion.event_id == id).first()
    if not ver1 or not ver2:
        raise HTTPException(status_code=404, detail="One or both versions not found for the specified event")
    
    diffs = {}
    for field in ["title", "description"]:
        old = getattr(ver1, field)
        new = getattr(ver2, field)
        if old != new:
            diffs[field] = list(difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm=""))
    return diffs

@app.get("/api/events/{id}", response_model=EventOut)
def get_event(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    event = db.query(Event).filter(Event.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    
    if event.owner_id != user.id:
        perm = db.query(Permission).filter(Permission.event_id == id, Permission.user_id == user.id).first()
        if not perm:
            raise HTTPException(status_code=403, detail="Access forbidden")
    return event

@app.get("/api/events/{id}/changelog")
def changelog(
    id: int,
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    event = db.query(Event).filter(Event.id == id).first()
    if not event:
        raise HTTPException(status_code=404, detail="Event not found")
    if event.owner_id != user.id:
        perm = db.query(Permission).filter(Permission.event_id == id, Permission.user_id == user.id).first()
        if not perm:
            raise HTTPException(status_code=403, detail="Access forbidden")
    
    versions = db.query(EventVersion).filter_by(event_id=id).order_by(EventVersion.version_number).all()
    return [
        {
            "version": v.version_number,
            "edited_by": v.edited_by,
            "timestamp": v.timestamp,
        } for v in versions
    ]

@app.post("/api/events/batch")
def create_batch(
    events: List[EventCreate],
    db: Session = Depends(get_db),
    user: User = Depends(get_user_by_token)
):
    created = []
    for e in events:
        event = Event(**e.dict(), owner_id=user.id)
        db.add(event)
        created.append(event)
    db.commit()
    return {"created_count": len(created)}