# API para la Gestión de Contactos y Usuarios

API RESTful moderna desarrollada con FastAPI siguiendo una arquitectura de vertical slices (por funcionalidades), enfocada en la gestión de contactos y usuarios con autenticación JWT.

## Características Principales

- ✅ **Arquitectura por Dominios**: Cada módulo es un slice vertical completo con todas sus capas
- ✅ **Autenticación Segura**: JWT con refresh tokens y Argon2 para hashing de contraseñas
- ✅ **Manejo Funcional de Errores**: Usando returns.Result para un código más predecible y tipado
- ✅ **Endpoints RESTful Completos**: CRUD para contactos, grupos de contactos y usuarios
- ✅ **Documentación OpenAPI**: Interfaz Swagger completamente documentada
- ✅ **Tests Unitarios**: Cobertura completa de la lógica de negocio
- ✅ **Validación de Datos**: Esquemas Pydantic para validación y serialización
- ✅ **Dockerizado**: Configuración lista para desarrollo y producción

## Estructura del Proyecto

```
app/
├── common/                 # Utilidades compartidas
│   ├── config.py           # Configuración con pydantic-settings
│   ├── database.py         # Conexión a la BD y sesiones
│   ├── hashing.py          # Argon2 para contraseñas
│   ├── errors.py           # Manejo de errores globales
│   └── schemas.py          # Esquemas compartidos (paginación, etc)
│
├── users/                  # Dominio de usuarios
│   ├── models.py           # Modelos SQLAlchemy
│   ├── schemas.py          # Esquemas Pydantic
│   ├── repository.py       # Acceso a datos
│   ├── service.py          # Lógica de negocio
│   ├── handlers.py         # Endpoints FastAPI
│   └── errors.py           # Errores específicos
│
├── roles/                  # Dominio de roles
│   ├── models.py
│   ├── schemas.py
│   ├── repository.py
│   ├── service.py
│   ├── handlers.py
│   └── errors.py
│
├── auth/                   # Dominio de autenticación
│   ├── service.py          # Lógica de autenticación
│   ├── handlers.py         # Endpoints
│   ├── jwt.py              # Implementación de tokens
│   ├── schemas.py          # Esquemas de autenticación
│   └── errors.py           # Errores de autenticación
│
├── contacts/               # Dominio de contactos
│   ├── models.py           # Modelos de contactos y grupos
│   ├── schemas.py          # Esquemas de contactos
│   ├── repository.py       # Acceso a datos
│   ├── service.py          # Lógica de negocio
│   ├── handlers.py         # Endpoints
│   ├── errors.py           # Errores específicos
│   └── tests/              # Tests unitarios
│
├── main.py                 # Punto de entrada
└── __init__.py             # Inicialización de la app
```

## Tecnologías Utilizadas

- **FastAPI**: Framework web asíncrono de alto rendimiento
- **SQLAlchemy 2.0**: ORM con soporte para consultas asíncronas
- **Pydantic v2**: Validación de datos y serialización
- **PostgreSQL**: Base de datos relacional
- **Docker & Docker Compose**: Contenedores para desarrollo y despliegue
- **Alembic**: Migraciones de base de datos
- **Passlib con Argon2**: Hashing seguro de contraseñas
- **Python-Jose**: Implementación de JWT para autenticación
- **Returns**: Manejo funcional de errores y resultados
- **uv**: Gestor de paquetes moderno y rápido para Python

## Configuración del Entorno

### Requisitos Previos

- Docker y Docker Compose
- Python 3.10+
- [uv](https://github.com/astral-sh/uv) - Gestor de paquetes recomendado

### Variables de Entorno

Todas las variables de entorno están centralizadas en un único archivo `.env` en la raíz del proyecto:

```env
# PostgreSQL
POSTGRES_USER=postgres
POSTGRES_PASSWORD=postgres
POSTGRES_DB=app_statica
POSTGRES_HOST=db
POSTGRES_PORT=5432

# FastAPI
PROJECT_NAME=app-statica
API_PREFIX=/api
CORS_ORIGINS=*

# Security
SECRET_KEY=tuclavesecretsupersegura
ACCESS_TOKEN_EXPIRE_MINUTES=30
ALGORITHM=HS256
```

### Instalación y Ejecución

#### Con Docker (Recomendado)

1. Clonar el repositorio:
```bash
git clone https://github.com/Ponce1969/API-para-la-gesti-n-de-contactos-y-usuarios.git
cd API-para-la-gesti-n-de-contactos-y-usuarios
```

2. Configurar las variables de entorno en el archivo `.env`

3. Ejecutar con Docker Compose:
```bash
docker-compose up -d
```

4. La API estará disponible en: http://localhost:8080
5. La documentación Swagger: http://localhost:8080/docs

#### Desarrollo Local con uv

1. Instalar dependencias:
```bash
uv venv .venv
source .venv/bin/activate
uv pip install -e .
```

2. Configurar variables de entorno para desarrollo local

3. Ejecutar la aplicación:
```bash
uvicorn app.main:app --reload --port 8080
```

### Migraciones de Base de Datos

Para crear una nueva migración:
```bash
docker-compose exec api alembic revision --autogenerate -m "descripción"
```

Para aplicar las migraciones:
```bash
docker-compose exec api alembic upgrade head
```

## Mejores Prácticas Implementadas

El proyecto sigue una arquitectura de "vertical slices" (por funcionalidades), donde cada dominio de la aplicación (usuarios, autenticación, contactos, etc.) tiene su propia carpeta con todas las capas necesarias (modelos, esquemas, repositorios, servicios y endpoints).
