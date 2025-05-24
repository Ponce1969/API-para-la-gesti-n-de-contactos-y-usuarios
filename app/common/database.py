"""Módulo de configuración de la base de datos.

Este módulo proporciona la configuración inicial para SQLAlchemy,
incluyendo la creación de la sesión de base de datos y la clase Base para los modelos.
"""
from typing import Any, AsyncGenerator, Optional

from sqlalchemy import MetaData
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.common.config import settings

# Convenciones de nombres para constraints
# Ver: https://alembic.sqlalchemy.org/en/latest/naming.html
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

# Metadatos con las convenciones de nombres
metadata = MetaData(naming_convention=convention)


class Base(DeclarativeBase):
    """Clase base para todos los modelos SQLAlchemy.
    
    Proporciona metadatos comunes y métodos de utilidad para todos los modelos.
    """
    metadata = metadata
    
    def dict(self) -> dict[str, Any]:
        """Convierte el modelo a un diccionario."""
        return {c.name: getattr(self, c.name) for c in self.__table__.columns}
    
    def update(self, **kwargs: Any) -> None:
        """Actualiza los atributos del modelo con los valores proporcionados."""
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)


# Motor de base de datos asíncrono
# Aseguramos que la URL de la base de datos sea una cadena
DATABASE_URL = str(settings.DATABASE_URL)
engine = create_async_engine(
    DATABASE_URL,
    echo=settings.DATABASE_ECHO,
    pool_pre_ping=True,  # Verifica la conexión antes de usarla
    pool_size=settings.DATABASE_POOL_SIZE,  # Tamaño del pool de conexiones
    max_overflow=settings.DATABASE_MAX_OVERFLOW,  # Conexiones adicionales que se pueden crear temporalmente
)

# Fábrica de sesiones asíncronas
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,  # Importante para operaciones asíncronas
    autoflush=False,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Obtiene una sesión de base de datos.
    
    Uso:
        async with get_db() as db:
            # Usar la sesión db aquí
            result = await db.execute(query)
    
    Yields:
        AsyncSession: Sesión de base de datos asíncrona
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


# Alias para compatibilidad
SessionLocal = AsyncSessionLocal

# Exportar la base de datos para migraciones
db = AsyncSessionLocal