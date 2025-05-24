"""Módulo común con utilidades y componentes compartidos.

Este módulo contiene utilidades y componentes que son utilizados en toda la aplicación,
como manejo de resultados, configuración, seguridad y más.
"""
from .config import Settings, get_settings
from .database import Base, get_db, SessionLocal
from .errors import (
    AppError,
    ErrorCode,
    ResourceNotFoundError,
    UnauthorizedError,
    ForbiddenError,
    ValidationError,
    ConflictError,
    DatabaseError,
    ServiceError,
)
from .result import (
    Result,
    Success,
    Failure,
    map_failure,
    to_async,
    to_io,
    safe_try,
    async_try,
    unwrap_result,
    unwrap_or_raise,
)
from .security import (
    create_access_token,
    verify_password,
    get_password_hash,
    get_current_user,
    get_current_active_user,
    get_current_active_superuser,
)

__all__ = [
    # Configuración
    'Settings',
    'get_settings',
    
    # Base de datos
    'Base',
    'get_db',
    'SessionLocal',
    
    # Manejo de errores
    'AppError',
    'ErrorCode',
    'ResourceNotFoundError',
    'UnauthorizedError',
    'ForbiddenError',
    'ValidationError',
    'ConflictError',
    'DatabaseError',
    'ServiceError',
    
    # Result
    'Result',
    'Success',
    'Failure',
    'map_failure',
    'to_async',
    'to_io',
    'safe_try',
    'async_try',
    'unwrap_result',
    'unwrap_or_raise',
    
    # Seguridad
    'create_access_token',
    'verify_password',
    'get_password_hash',
    'get_current_user',
    'get_current_active_user',
    'get_current_active_superuser',
]
