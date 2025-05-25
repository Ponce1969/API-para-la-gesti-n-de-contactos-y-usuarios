"""Módulo común con utilidades y configuraciones compartidas.

Este paquete proporciona componentes reutilizables y utilidades comunes
a través de toda la aplicación, incluyendo:

- Configuración centralizada
- Manejo de base de datos
- Manejo de errores
- Utilidades de seguridad
- Funciones de ayuda
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Dict, List, Optional, Type, TypeVar, Union

# Importaciones condicionales para type checking
if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from app.common.config import Settings
    from app.common.database import Base, SessionLocal
    from app.common.errors import (
        AppError,
        ConflictError,
        DatabaseError,
        ErrorCode,
        ForbiddenError,
        ResourceNotFoundError,
        ServiceError,
        UnauthorizedError,
        ValidationError,
    )
    from app.common.result import (
        Failure,
        Result,
        Success,
        apply,
        async_safe_try,
        from_ioresult,
        from_ioresult_e,
        get_or_default,
        get_or_raise,
        map_failure,
        safe_try,
        sequence,
        to_ioresult,
        to_maybe,
    )
    from app.common.security import (
        create_access_token,
        get_current_active_superuser,
        get_current_active_user,
        get_current_user,
        get_password_hash,
        verify_password,
    )
    from app.users.models import User as UserModel

# Type variables para uso en anotaciones de tipo
T = TypeVar("T")

# Intenta importar módulos opcionales
try:
    from app.common.config import Settings, get_settings
    from app.common.database import Base, SessionLocal, get_db
    from app.common.errors import (
        AppError,
        ConflictError,
        DatabaseError,
        ErrorCode,
        ForbiddenError,
        ResourceNotFoundError,
        ServiceError,
        UnauthorizedError,
        ValidationError,
    )
    from app.common.result import (
        Failure,
        Result,
        Success,
        apply,
        async_safe_try,
        from_ioresult,
        from_ioresult_e,
        get_or_default,
        get_or_raise,
        map_failure,
        safe_try,
        sequence,
        to_ioresult,
        to_maybe,
    )
    from app.common.security import (
        create_access_token,
        get_current_active_superuser,
        get_current_active_user,
        get_current_user,
        get_password_hash,
        verify_password,
    )

    # Configuración de logging (opcional)
    try:
        from app.common.logging import configure_logging

        logger = configure_logging()
    except ImportError:
        import logging

        logger = logging.getLogger(__name__)
        logger.addHandler(logging.NullHandler())

    __all__ = [
        # Configuración
        "Settings",
        "get_settings",
        # Base de datos
        "Base",
        "SessionLocal",
        "get_db",
        # Errores
        "AppError",
        "ConflictError",
        "DatabaseError",
        "ErrorCode",
        "ForbiddenError",
        "ResourceNotFoundError",
        "ServiceError",
        "UnauthorizedError",
        "ValidationError",
        # Result
        "Result",
        "Success",
        "Failure",
        "apply",
        "async_safe_try",
        "from_ioresult",
        "from_ioresult_e",
        "get_or_default",
        "get_or_raise",
        "map_failure",
        "safe_try",
        "sequence",
        "to_ioresult",
        "to_maybe",
        # Seguridad
        "create_access_token",
        "get_current_active_superuser",
        "get_current_active_user",
        "get_current_user",
        "get_password_hash",
        "verify_password",
        # Logging
        "logger",
    ]

except ImportError as e:
    # Manejo de dependencias faltantes para importaciones opcionales
    import logging
    import warnings

    warnings.warn(f"No se pudieron importar todos los módulos comunes: {e}")

    # Configuración básica de logging
    logger = logging.getLogger(__name__)
    logger.addHandler(logging.NullHandler())

    # Exportar solo lo básico
    __all__ = [
        "logger",
    ]

    # Definir tipos básicos para type checking
    if TYPE_CHECKING:
        Base = object
        SessionLocal = object

        class Settings:
            pass

    # Funciones básicas para evitar errores de importación
    def get_settings() -> Settings:
        raise ImportError("No se pudo cargar la configuración")

    async def get_db() -> None:
        raise ImportError("No se pudo inicializar la base de datos")
