# Mejores Prácticas para App Statica API

## 1. Manejo Funcional de Errores con Returns.Result

### Principio
Utilizamos `returns.Result` para manejar errores de forma funcional, evitando excepciones no controladas y proporcionando un flujo de control más predecible y tipado.

### Implementación
- Todos los repositorios devuelven `Result[T, E]` donde T es el tipo de éxito y E el tipo de error
- Los servicios procesan estos resultados mediante pattern matching o métodos como `map`, `bind`, `alt`, etc.
- Se evita el uso de excepciones para el flujo de control normal

### Ejemplo
```python
# En repository.py
async def create_user(user_data: UserCreate) -> Result[User, UserCreateError]:
    try:
        # Lu00f3gica para crear usuario
        return Success(created_user)
    except UniqueViolationError:
        return Failure(UserCreateError("Email ya registrado"))

# En service.py
async def register_user(user_data: UserCreate) -> Result[User, UserError]:
    return await user_repository.create_user(user_data).bind(
        lambda user: send_welcome_email(user).map(lambda _: user)
    )
```

## 2. Hashing Seguro con Argon2

### Principio
Utilizamos Argon2 como algoritmo de hashing para contraseñas, siguiendo las recomendaciones de seguridad actuales.

### Implementación
- Configuración centralizada en `common/security.py`
- Parámetros optimizados para seguridad y rendimiento
- Funciones de utilidad para verificación y generación de hashes

### Ejemplo
```python
# En common/security.py
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
```

## 3. Separación Estricta de Capas en Slices

### Principio
Cada dominio (slice) tiene sus propias capas claramente separadas, con responsabilidades bien definidas.

### Implementación
- **models.py**: Solo definiciones de tablas SQLAlchemy
- **schemas.py**: Solo modelos Pydantic para validación y serialización
- **repository.py**: Solo acceso a datos
- **service.py**: Solo lógica de negocio
- **handlers.py**: Solo endpoints y routing

### Reglas
- Los handlers solo pueden llamar a servicios
- Los servicios pueden llamar a repositorios y otros servicios
- Los repositorios son los únicos que acceden directamente a la base de datos

## 4. Sin Lógica en Endpoints

### Principio
Los endpoints (handlers) solo deben encargarse de la validación de entrada, invocación de servicios y transformación de respuestas.

### Implementación
- Endpoints concisos que delegan toda la lógica a los servicios
- Uso de dependencias FastAPI para inyección
- Manejo de errores HTTP consistente

### Ejemplo
```python
@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(user_data: UserCreate, db: Database = Depends(get_db)):
    result = await user_service.create_user(user_data, db)
    return result.map(
        lambda user: user,
        lambda error: handle_error(error)  # Funciu00f3n que convierte errores en HTTPException
    ).unwrap()
```

## 5. Modelos SQLAlchemy Separados de Pydantic

### Principio
Separamos completamente los modelos de base de datos (SQLAlchemy) de los esquemas de API (Pydantic).

### Implementación
- Modelos SQLAlchemy en `models.py`
- Esquemas Pydantic en `schemas.py`
- Funciones de conversión entre ambos cuando sea necesario

### Ejemplo
```python
# En models.py
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    # ...

# En schemas.py
class UserBase(BaseModel):
    email: EmailStr

class UserCreate(UserBase):
    password: str

class UserResponse(UserBase):
    id: int

    class Config:
        from_attributes = True
```

## 6. Configuración Segura con Pydantic-Settings

### Principio
Utilizamos pydantic-settings para una configuración tipada, validada y segura.

### Implementación
- Configuración centralizada en `common/config.py`
- Carga automática desde variables de entorno y archivo .env
- Validación de tipos y valores

### Ejemplo
```python
from pydantic_settings import BaseSettings
from typing import List, Optional

class Settings(BaseSettings):
    PROJECT_NAME: str
    API_PREFIX: str
    BACKEND_CORS_ORIGINS: List[str]
    SECRET_KEY: str
    ALGORITHM: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

    # Database
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str
    POSTGRES_DB: str
    POSTGRES_HOST: str
    POSTGRES_PORT: str

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

## 7. Manejo Explícito de Errores con Tipado Fuerte

### Principio
Definimos errores específicos para cada dominio y los manejamos de forma explícita con tipado fuerte.

### Implementación
- Jerarquía de errores en cada `errors.py`
- Mapeo explícito a códigos HTTP
- Uso de `Result[T, E]` para propagación tipada

### Ejemplo
```python
# En errors.py
from common.errors import AppError

class UserError(AppError):
    """Error base para el dominio de usuarios"""

class UserNotFoundError(UserError):
    """Usuario no encontrado"""
    status_code = 404

class UserAlreadyExistsError(UserError):
    """Usuario ya existe"""
    status_code = 409

# En common/errors.py
from fastapi import HTTPException

def handle_error(error: AppError) -> HTTPException:
    return HTTPException(status_code=error.status_code, detail=str(error))
```

## 8. Endpoints Asincrónicos por Defecto

### Principio
Todos los endpoints y funciones de acceso a datos son asincrónicos para maximizar el rendimiento.

### Implementación
- Uso de `async def` en todos los handlers
- SQLAlchemy con modo asincrónico
- Operaciones I/O siempre asincrónicas

### Ejemplo
```python
@router.get("/{user_id}", response_model=UserResponse)
async def get_user(user_id: int, db: AsyncSession = Depends(get_db)):
    result = await user_service.get_user_by_id(user_id, db)
    return result.map(
        lambda user: user,
        lambda error: handle_error(error)
    ).unwrap()
```

## 9. Tipado Estricto y Análisis Estático

### Principio
Utilizamos tipado estricto en todo el código y herramientas de análisis estático para detectar errores temprano.

### Implementación
- Anotaciones de tipo en todas las funciones y variables
- Configuración estricta de mypy
- Ruff para linting y formateo

### Configuración
```toml
# pyproject.toml
[tool.mypy]
strict = true
disallow_untyped_defs = true
disallow_incomplete_defs = true
check_untyped_defs = true
disallow_untyped_decorators = true
no_implicit_optional = true
strict_optional = true

[tool.ruff]
target-version = "py310"
line-length = 88
select = ["E", "F", "B", "I", "N", "UP", "ANN", "RUF"]
```

## 10. Testing Profesional

### Principio
Implementamos pruebas exhaustivas para garantizar la calidad y facilitar el mantenimiento.

### Implementación
- Pruebas unitarias para servicios y repositorios
- Pruebas de integración para endpoints
- Fixtures reutilizables
- Base de datos de prueba aislada

### Ejemplo
```python
# En tests/users/test_service.py
async def test_create_user_success(db_session):
    user_data = UserCreate(email="test@example.com", password="securepass")
    result = await user_service.create_user(user_data, db_session)
    assert isinstance(result, Success)
    assert result.unwrap().email == "test@example.com"

# En tests/users/test_handlers.py
async def test_create_user_endpoint(client):
    response = await client.post(
        "/api/users/",
        json={"email": "test@example.com", "password": "securepass"}
    )
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "test@example.com"
    assert "id" in data
```
