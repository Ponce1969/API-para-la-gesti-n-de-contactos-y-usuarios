"""
Dependencias de autenticación y autorización.

Este módulo proporciona dependencias de FastAPI para manejar la autenticación
y autorización en los endpoints de la API.
"""

from typing import Optional, TYPE_CHECKING

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import ValidationError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import service as auth_service
from app.auth.errors import CREDENTIALS_EXCEPTION, INACTIVE_USER_EXCEPTION
if TYPE_CHECKING:
    from app.users.models import User  # Correct: User model is in the users slice
from app.auth.schemas import TokenData
from app.common.database import get_db
from app.users import service as user_service
# from app.users.schemas import User as UserSchema # This schema doesn't exist / not used here
from app.common.config import settings # Import settings object

# Configuración del esquema OAuth2 para extraer el token del encabezado Authorization
oauth2_scheme = OAuth2PasswordBearer(
    tokenUrl=f"{settings.API_V1_STR}/auth/login", auto_error=False
)



async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> 'User':
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
            settings.JWT_SECRET_KEY.get_secret_value(), # Use JWT_SECRET_KEY
            algorithms=[settings.JWT_ALGORITHM], # Use JWT_ALGORITHM
            options={"verify_aud": False}, # Consider if audience verification is needed
        )

        # Extraer el email (subject) del token
        subject: Optional[str] = payload.get("sub")
        if subject is None:
            logger.warning("Token JWT no contiene 'sub' (subject).")
            raise CREDENTIALS_EXCEPTION

        # Validar los datos del token (email is stored in sub)
        token_data = TokenData(sub=subject)
    except JWTError as e:
        logger.warning(f"Error de decodificación/validación de JWT: {e}")
        raise CREDENTIALS_EXCEPTION
    except ValidationError as e:
        logger.warning(f"Error de validación de Pydantic para TokenData: {e}")
        raise CREDENTIALS_EXCEPTION

    # Obtener el usuario de la base de datos
    user_result = await user_service.get_user_by_email(db, email=token_data.sub)
    if user_result.is_failure():
        error = user_result.error()
        logger.warning(f"Usuario no encontrado o error de BD para sub '{token_data.sub}': {error}")
        # Distinguish between UserNotFoundError and other DB errors if needed for logging
        raise CREDENTIALS_EXCEPTION
    
    user: 'User' = user_result.unwrap()
    return user


async def get_current_active_user(
    current_user: 'User' = Depends(get_current_user),
) -> 'User':
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
    current_user: 'User' = Depends(get_current_user),
) -> 'User':
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


async def get_optional_current_user(
    token: str = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> Optional['User']:
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
        # get_current_user is async, so it needs to be awaited
        user = await get_current_user(token, db)
        return user
    except HTTPException:
        # This will catch CREDENTIALS_EXCEPTION if token is invalid or user not found
        return None
