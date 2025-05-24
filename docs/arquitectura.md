# Arquitectura de App Statica API

## Principios de Arquitectura Limpia en Rebanadas (Clean Architecture with Vertical Slices)

Esta API sigue una arquitectura que combina los principios de la Arquitectura Limpia (Clean Architecture) con el enfoque de Rebanadas Verticales (Vertical Slices). Esta combinación nos permite:

1. **Organizar por funcionalidad**: Cada dominio de negocio (usuarios, autenticación, contactos) tiene su propia carpeta con todas las capas necesarias.
2. **Mantener la separación de responsabilidades**: Cada capa tiene una responsabilidad clara y bien definida.
3. **Facilitar el testing**: Al tener componentes desacoplados, es más fácil escribir pruebas unitarias e integración.
4. **Permitir cambios con mínimo impacto**: Los cambios en una funcionalidad afectan solo a su "rebanada" correspondiente.

## Estructura de Capas en cada Rebanada

Cada rebanada vertical (slice) contiene las siguientes capas:

### 1. Modelos (models.py)
- Definición de entidades para SQLAlchemy
- Representación de las tablas en la base de datos
- Sin lógica de negocio, solo estructura de datos

### 2. Esquemas (schemas.py)
- Modelos Pydantic para validación y serialización
- Separados de los modelos de SQLAlchemy
- Utilizados para la entrada y salida de datos en la API

### 3. Repositorio (repository.py)
- Acceso a la base de datos
- Operaciones CRUD básicas
- Devuelve Result<T> para manejo funcional de errores
- Utiliza tipado estricto

### 4. Servicio (service.py)
- Lógica de negocio
- Orquestación de operaciones
- Implementación de casos de uso
- No accede directamente a la base de datos, usa el repositorio

### 5. Handlers (handlers.py)
- Endpoints FastAPI
- Sin lógica de negocio, solo validación e invocación de servicios
- Asincrónicos por defecto
- Manejo de respuestas HTTP y errores

### 6. Errores (errors.py)
- Excepciones específicas del dominio
- Mapeo a códigos HTTP correspondientes

## Buenas Prácticas Implementadas

### Returns.Result para Manejo Funcional de Errores

```python
# Ejemplo en repository.py
from returns.result import Result, Success, Failure

async def get_user_by_id(user_id: int) -> Result[User, UserNotFoundError]:
    user = await db.fetch_one(query, values={"id": user_id})
    if not user:
        return Failure(UserNotFoundError(f"Usuario con ID {user_id} no encontrado"))
    return Success(User(**user))
```

### Argon2 como Estándar de Hashing Seguro

```python
# Implementado en common/security.py
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)
```

### Separación Estricta de Capas

- Los handlers solo llaman a servicios, nunca acceden directamente a repositorios
- Los servicios orquestan la lógica de negocio y llaman a repositorios
- Los repositorios son los únicos que interactúan con la base de datos

### Configuración con Pydantic Settings

```python
# Implementado en common/config.py
from pydantic_settings import BaseSettings
from typing import List

class Settings(BaseSettings):
    PROJECT_NAME: str
    API_PREFIX: str
    BACKEND_CORS_ORIGINS: List[str]
    # ... otras configuraciones

    class Config:
        env_file = ".env"
        case_sensitive = True

settings = Settings()
```

### Tipado Estricto y Análisis Estático

- Uso de mypy para verificación de tipos
- Ruff para análisis estático y formateo
- Tipos explícitos en todas las funciones y métodos

### Testing Profesional

- Pytest para pruebas unitarias e integración
- Httpx para pruebas de endpoints
- Fixtures para configuración de pruebas
- Mocks para aislar componentes

## Flujo de Datos

1. **Request HTTP** → Llega al endpoint en handlers.py
2. **Validación** → Pydantic valida los datos de entrada
3. **Servicio** → El handler llama al servicio correspondiente
4. **Lógica de Negocio** → El servicio implementa la lógica y llama al repositorio
5. **Acceso a Datos** → El repositorio interactúa con la base de datos
6. **Result<T>** → El repositorio devuelve un Result (Success/Failure)
7. **Manejo de Resultado** → El servicio procesa el resultado y lo devuelve al handler
8. **Respuesta HTTP** → El handler convierte el resultado en una respuesta HTTP

## Manejo de Errores

Se utiliza un enfoque funcional con `returns.Result` para evitar excepciones no controladas:

1. Los repositorios devuelven `Result[T, E]` donde T es el tipo de éxito y E el tipo de error
2. Los servicios manejan estos resultados y pueden añadir contexto adicional
3. Los handlers convierten los errores en respuestas HTTP apropiadas

Esto permite un flujo de control predecible y tipado, sin necesidad de bloques try/except en todo el código.
