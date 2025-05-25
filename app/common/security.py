"""Módulo de seguridad para autenticación y autorización.

Este módulo proporciona funciones para:
- Generar y verificar tokens JWT
- Hashear y verificar contraseñas
- Obtener el usuario actual desde el token
- Verificar permisos de usuario
"""

from datetime import datetime, timedelta
from typing import Any, Optional, Union, TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.config import settings
from app.auth.errors import (
    CREDENTIALS_EXCEPTION,
    INACTIVE_USER_EXCEPTION,
    INSUFFICIENT_PRIVILEGES_EXCEPTION,
)
from app.common.result import Failure, Result, Success
if TYPE_CHECKING:
    from app.users.models import User as UserModel
from app.users.schemas import UserInDB

# Configuración de seguridad
oauth2_scheme = OAuth2PasswordBearer(tokenUrl=f"{settings.API_V1_STR}/auth/login", auto_error=False) # auto_error=False was in dependencies.py, ensure consistency or verify correct place


def create_access_token(
    subject: Union[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """Crea un token JWT de acceso.

    Args:
        subject: El sujeto del token (generalmente el ID de usuario o email)
        expires_delta: Tiempo de expiración del token

    Returns:
        str: Token JWT codificado
    """
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(
            minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES
        )

    to_encode = {"exp": expire, "sub": str(subject)}
    encoded_jwt = jwt.encode(
        to_encode, settings.SECRET_KEY, algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


async def get_current_user(
    db: AsyncSession, token: str = Depends(oauth2_scheme)
) -> 'UserModel':
    """Obtiene el usuario actual a partir del token JWT.

    Args:
        db: Sesión de base de datos
        token: Token JWT

    Returns:
        UserModel: Usuario autenticado

    Raises:
        HTTPException: Si el token es inválido o el usuario no existe
    """
    try:
        payload = jwt.decode(
            token, settings.SECRET_KEY, algorithms=[settings.JWT_ALGORITHM]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise CREDENTIALS_EXCEPTION
    except JWTError:
        raise CREDENTIALS_EXCEPTION

    # Buscar el usuario en la base de datos
    user = await UserModel.get(db, id=user_id)
    if user is None:
        raise CREDENTIALS_EXCEPTION

    return user


async def get_current_active_user(
    current_user: 'UserModel' = Depends(get_current_user),
) -> 'UserModel':
    """Obtiene el usuario actual si está activo.

    Args:
        current_user: Usuario actual obtenido del token

    Returns:
        UserModel: Usuario activo

    Raises:
        HTTPException: Si el usuario está inactivo
    """
    if not current_user.is_active:
        raise INACTIVE_USER_EXCEPTION
    return current_user


async def get_current_active_superuser(
    current_user: 'UserModel' = Depends(get_current_user),
) -> 'UserModel':
    """Obtiene el usuario actual si es superusuario.

    Args:
        current_user: Usuario actual obtenido del token

    Returns:
        UserModel: Usuario superusuario

    Raises:
        HTTPException: Si el usuario no es superusuario
    """
    if not current_user.is_superuser:
        raise INSUFFICIENT_PERMISSIONS_EXCEPTION
    return current_user


# Funciones de utilidad para verificación de permisos
def has_permission(user: 'UserModel', permission: str) -> bool:
    """Verifica si un usuario tiene un permiso específico.

    Args:
        user: Usuario a verificar
        permission: Nombre del permiso requerido

    Returns:
        bool: True si el usuario tiene el permiso, False en caso contrario
    """
    if user.is_superuser:
        return True

    user_permissions = {p.name for p in (user.permissions or [])}
    return permission in user_permissions


def check_permission(user: 'UserModel', permission: str) -> Result[None, str]:
    """Verifica si un usuario tiene un permiso específico.

    Args:
        user: Usuario a verificar
        permission: Nombre del permiso requerido

    Returns:
        Result[None, str]: Éxito si tiene permiso, error en caso contrario
    """
    if has_permission(user, permission):
        return Success(None)
    return Failure("Permiso insuficiente")


# Dependencias de seguridad
async def get_current_user_optional(
    db: AsyncSession, token: Optional[str] = Depends(oauth2_scheme)
) -> Optional['UserModel']:
    """Obtiene el usuario actual si está autenticado, None en caso contrario."""
    if not token:
        return None
    try:
        return await get_current_user(db, token)
    except HTTPException:
        return None
