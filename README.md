# App Statica API

API RESTful desarrollada con FastAPI siguiendo una arquitectura de vertical slices (por funcionalidades).

## Estructura del Proyecto

```
app/
├── common/                 # Utilidades compartidas (tipos, helpers, errores, seguridad)
│   ├── config.py
│   ├── database.py
│   ├── errors.py
│   ├── security.py         # Argon2 aquí
│   └── result.py           # Setup de returns.Result
│
├── users/                  # Slice para usuarios
│   ├── models.py           # Modelos SQLAlchemy
│   ├── schemas.py          # Pydantic
│   ├── repository.py       # Acceso a datos
│   ├── service.py          # Lógica de dominio
│   ├── handlers.py         # Endpoints FastAPI
│   └── errors.py
│
├── roles/                  # Slice para roles
│   ├── models.py           # Modelos SQLAlchemy
│   ├── schemas.py          # Pydantic
│   ├── repository.py       # Acceso a datos
│   ├── service.py          # Lógica de dominio
│   ├── handlers.py         # Endpoints FastAPI
│   └── errors.py
│
├── auth/                   # Slice para autenticación
│   ├── service.py
│   ├── handlers.py
│   ├── jwt.py
│   ├── schemas.py
│   └── errors.py
│
├── contacts/               # Slice para contactos
│   ├── models.py
│   ├── schemas.py
│   ├── repository.py
│   ├── service.py
│   ├── handlers.py
│   └── errors.py
│
├── main.py                 # Punto de entrada
└── __init__.py
```

## Tecnologías Utilizadas

- **FastAPI**: Framework web de alto rendimiento
- **SQLAlchemy**: ORM para la base de datos
- **Pydantic**: Validación de datos y serialización
- **PostgreSQL**: Base de datos relacional
- **Docker**: Contenedores para desarrollo y despliegue
- **Alembic**: Migraciones de base de datos
- **Passlib con Argon2**: Hashing seguro de contraseñas
- **Python-Jose**: Implementación de JWT para autenticación
- **Returns**: Manejo funcional de errores y resultados

## Configuración del Entorno

### Requisitos

- Docker y Docker Compose
- Python 3.10+

### Variables de Entorno

Todas las variables de entorno están centralizadas en un único archivo `.env` en la raíz del proyecto.

### Instalación y Ejecución

1. Clonar el repositorio
2. Configurar las variables de entorno en el archivo `.env`
3. Ejecutar con Docker Compose:

```bash
docker-compose up -d
```

4. La API está disponible en: http://localhost:8000
5. La documentación de la API está en: http://localhost:8000/docs

### Migraciones de Base de Datos

Para crear una nueva migración:

```bash
docker-compose exec api alembic revision --autogenerate -m "descripción"
```

Para aplicar las migraciones:

```bash
docker-compose exec api alembic upgrade head
```

## Arquitectura

El proyecto sigue una arquitectura de "vertical slices" (por funcionalidades), donde cada dominio de la aplicación (usuarios, autenticación, contactos, etc.) tiene su propia carpeta con todas las capas necesarias (modelos, esquemas, repositorios, servicios y endpoints).
