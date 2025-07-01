import asyncio
from enum import Enum
import logging
import os
import platform
import signal
from fastapi import APIRouter, FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr, field_validator, validator
from typing import Optional
from sqlalchemy import create_engine, Column, String, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import uuid
import jwt
import uvicorn
from pyapi.modules.snt_logger import JSONLogFormatter, ModuleLoggerAdapter, setup_root_logger
from importlib.metadata import version
__version__ = version("pyapi")
from dotenv import load_dotenv
load_dotenv(os.environ.get("PYAPI_ENV_FILE", ".env.example"))

MODULE_NAME = os.path.splitext(os.path.basename(__file__))[0]
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

PORT  = int(os.environ.get(f"{MODULE_NAME.upper()}_PORT",5253))


LOG_LEVEL = os.environ.get(f"{MODULE_NAME.upper()}_LOG_LEVEL","INFO")
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_PATH = os.environ.get("LOG_PATH","logs")
LOG_DIR = f"{LOG_PATH}/app"

if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR, exist_ok=True)
formatter = JSONLogFormatter(
    service_name=None,
    environment=None,
    event_type="main"
)
setup_root_logger(
    logfile=f"{LOG_DIR}/main.log",
    formatter=formatter,
    to_console=True,
    level=LOG_LEVEL
)
root_logger = logging.getLogger()
logger = ModuleLoggerAdapter(root_logger, {"event_type": "main"})


stop_event = asyncio.Event()

def _signal_handler():
    logger.info("Запущен процесс завершения PyAPI")
    stop_event.set()

DB_HOST=os.environ.get(f"DB_HOST","")
DB_USER=os.environ.get(f"DB_USER","")
DB_PASS=os.environ.get(f"DB_PASS","")
DB_DATABASE=os.environ.get(f"DB_DATABASE","")
print(DB_DATABASE)
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}/{DB_DATABASE}"
JWT_SECRET = os.environ.get(f"JWT_SECRET","VerRytStrongJWT_SECRETsdvkt@DkdkFE$$")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

app = FastAPI(title="PyAPI",version=__version__)

Base.metadata.create_all(bind=engine)

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    email = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    name = Column(String, nullable=False)
    bio = Column(String, nullable=True)
    avatarUrl = Column(String, nullable=True)
    incomeRange = Column(String, nullable=True)
    education = Column(String, nullable=True)
    createdAt = Column(DateTime, default=datetime.utcnow)
    updatedAt = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class IncomeRangeEnum(str, Enum):
    below_30k = "<30k"
    from_30_to_70k = "30-70k"
    above_70k = ">70k"

class EducationEnum(str, Enum):
    school = "school"
    college = "college"
    master = "master"
    phd = "phd"


class UserCreate(BaseModel):
    email: EmailStr
    password: str
    name: str

    @field_validator('password')
    def password_min_length(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        return v

class UserOut(BaseModel):
    id: str
    email: EmailStr
    name: str
    bio: Optional[str]
    avatarUrl: Optional[str]
    incomeRange: Optional[IncomeRangeEnum]
    education: Optional[EducationEnum]
    createdAt: datetime
    updatedAt: datetime

    model_config = {
        "from_attributes": True
    }

    @field_validator("id", mode="before")
    @classmethod
    def id_to_str(cls, v):
        return str(v)

class UserUpdate(BaseModel):
    name: Optional[str]
    bio: Optional[str]
    avatarUrl: Optional[str]
    incomeRange: IncomeRangeEnum
    education: EducationEnum

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=ALGORITHM)

def decode_access_token(token: str):
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[ALGORITHM])
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
        return user_id
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    user_id = decode_access_token(token)
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")
    return user


routerAuth = APIRouter(
)

protected_router = APIRouter(
    dependencies=[Depends(get_current_user)],
)

@routerAuth.post("/api/auth/signup", response_model=Token)
def signup(user_create: UserCreate, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.email == user_create.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    new_user = User(
        email=user_create.email,
        name=user_create.name,
        password_hash=get_password_hash(user_create.password)
    )
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token = create_access_token(data={"sub": str(new_user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@routerAuth.post("/api/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form_data.username).first()
    if not user or not verify_password(form_data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(data={"sub": str(user.id)})
    return {"access_token": access_token, "token_type": "bearer"}

@protected_router.get("/api/users/me", response_model=UserOut)
def read_profile(current_user: User = Depends(get_current_user)):
    return  UserOut.model_validate(current_user)

@protected_router.patch("/api/users/me", response_model=UserOut)
def update_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    for field, value in user_update.model_dump(exclude_unset=True).items():
        if isinstance(value, Enum):
            value = value.value  
        setattr(current_user, field, value)
    current_user.updatedAt = datetime.now(timezone.utc)
    db.commit()
    db.refresh(current_user)
    return UserOut.model_validate(current_user)


app.include_router(routerAuth)
app.include_router(protected_router)

app.openapi_schema = app.openapi()

app.openapi_schema["components"]["securitySchemes"] = {
    "OAuth2PasswordBearer": {
        "type": "oauth2",
        "flows": {
            "password": {
                "tokenUrl": "/api/auth/login",
                "scopes": {}
            }
        }
    }
}
app.openapi_schema["security"] = [{"OAuth2PasswordBearer": []}]

async def async_main():
    try:
        config = uvicorn.Config(app, host="0.0.0.0", port=PORT, log_level=LOG_LEVEL.lower(), loop="asyncio", log_config=None)
        server = uvicorn.Server(config)
        servertask = asyncio.create_task(server.serve())
        await stop_event.wait()
        server.should_exit = True
        await servertask
    except Exception as ex:
        logger.exception(f"Необработанная ошибка API: {ex}")

def main():
    if platform.system() == "Windows":
        # На Windows можно просто ловить Ctrl+C через asyncio.run + KeyboardInterrupt
        try:
            asyncio.run(async_main())
        except KeyboardInterrupt:
            logger.info("PyAPI остановлен пользователем (Ctrl+C)")
    else:
        # На Linux/Unix вешаем обработчики сигналов SIGINT и SIGTERM
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, _signal_handler)
        try:
            loop.run_until_complete(async_main())
        except Exception as ex:
            logger.exception(f"Необработанная ошибка main: {ex}")
            raise
        finally:
            loop.close()


if __name__ == "__main__":
    main()