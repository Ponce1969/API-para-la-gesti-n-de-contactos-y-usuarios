"""
Dependencias de autenticación y autorización.

Este módulo proporciona dependencias de FastAPI para manejar la autenticación
y autorización en los endpoints de la API.
"""
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import service as auth_service
from app.auth.errors import CREDENTIALS_EXCEPTION, INACTIVE_USER_EXCEPTION
from app.auth.models import User
from app.auth.schemas import TokenData
from app.common.database import get_db
from app.users import service as user_service
from app.users.schemas import User as UserSchema

# Configuración del esquema OAuth2 para extraer el token del encabezado Authorization
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login",
    auto_error=False
)

async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """
    Obtiene el usuario actual a partir del token JWT.
    
    Args:
        token: Token JWT del encabezado Authorization.
        db: Sesión de base de datos.
        
    Returns:
        El usuario autenticado.
        
    Raises:
        HTTPException: Si el token es inválido o el usuario no existe.
    """
    if not token:
        raise CREDENTIALS_EXCEPTION
        
    try:
        # Decodificar el token JWT
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False},
        )
        
        # Extraer el email del token
        email: str = payload.get("sub")
        if email is None:
            raise CREDENTIALS_EXCEPTION
            
        # Validar los datos del token
        token_data = TokenData(email=email)
    except (JWTError, ValidationError):
        raise CREDENTIALS_EXCEPTION
    
    # Obtener el usuario de la base de datos
    user = await user_service.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise CREDENTIALS_EXCEPTION
        
    return user

async def get_current_active_user(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Obtiene el usuario actual si está activo.
    
    Args:
        current_user: Usuario autenticado.
        
    Returns:
        El usuario si está activo.
        
    Raises:
        HTTPException: Si el usuario está inactivo.
    """
    if not current_user.is_active:
        raise INACTIVE_USER_EXCEPTION
    return current_user

async def get_current_active_superuser(
    current_user: User = Depends(get_current_user),
) -> User:
    """
    Obtiene el usuario actual si es superusuario.
    
    Args:
        current_user: Usuario autenticado.
        
    Returns:
        El usuario si es superusuario.
        
    Raises:
        HTTPException: Si el usuario no es superusuario.
    """
    if not current_user.is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tiene suficientes privilegios",
        )
    return current_user

def get_optional_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional[User]:
    """
    Obtiene el usuario actual si está autenticado, de lo contrario devuelve None.
    
    Args:
        token: Token JWT del encabezado Authorization (opcional).
        db: Sesión de base de datos.
        
    Returns:
        El usuario autenticado o None si no está autenticado.
    """
    if not token:
        return None
        
    try:
        user = get_current_user(token, db)
        return user
    except HTTPException:
        return None
