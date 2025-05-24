"""
Servicio de autenticación.

Este módulo proporciona funciones para manejar la autenticación de usuarios,
generación y verificación de tokens JWT, y operaciones relacionadas con la seguridad.
"""
from datetime import datetime, timedelta
from typing import Any, Dict, Optional, Union

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.config import settings
from app.common.errors import DatabaseError, ResourceNotFoundError
from app.users import service as user_service
from app.users.models import User
from . import errors
from .schemas import TokenData

# Configuración de contraseñas
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica si una contraseña en texto plano coincide con un hash.
    
    Args:
        plain_password: Contraseña en texto plano.
        hashed_password: Hash de la contraseña almacenado.
        
    Returns:
        bool: True si la contraseña es válida, False en caso contrario.
    """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """
    Genera un hash seguro de una contraseña.
    
    Args:
        password: Contraseña en texto plano.
        
    Returns:
        str: Hash de la contraseña.
    """
    return pwd_context.hash(password)

async def authenticate_user(
    db: AsyncSession, email: str, password: str
) -> Optional[User]:
    """
    Autentica a un usuario con su correo electrónico y contraseña.
    
    Args:
        db: Sesión de base de datos.
        email: Correo electrónico del usuario.
        password: Contraseña en texto plano.
        
    Returns:
        User: El usuario autenticado si las credenciales son válidas, None en caso contrario.
        
    Raises:
        errors.InvalidCredentialsError: Si las credenciales son inválidas.
        errors.InactiveUserError: Si el usuario está inactivo.
        errors.UnverifiedAccountError: Si la cuenta no ha sido verificada.
    """
    try:
        user = await user_service.get_user_by_email(db, email)
        if not user:
            raise errors.InvalidCredentialsError("Email o contraseña incorrectos")
            
        if not verify_password(password, user.hashed_password):
            raise errors.InvalidCredentialsError("Email o contraseña incorrectos")
            
        if not user.is_active:
            raise errors.InactiveUserError("Usuario inactivo")
            
        if not user.is_verified:
            raise errors.UnverifiedAccountError("Por favor, verifique su correo electrónico")
            
        return user
        
    except ResourceNotFoundError:
        raise errors.InvalidCredentialsError("Email o contraseña incorrectos")

def create_access_token(
    data: Dict[str, Any], 
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Crea un token de acceso JWT.
    
    Args:
        data: Datos a incluir en el token.
        expires_delta: Tiempo de expiración del token.
        
    Returns:
        str: Token JWT firmado.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(
        to_encode, 
        settings.SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt

def create_refresh_token(
    data: Dict[str, Any],
    expires_delta: Optional[timedelta] = None
) -> str:
    """
    Crea un token de actualización JWT.
    
    Args:
        data: Datos a incluir en el token.
        expires_delta: Tiempo de expiración del token.
        
    Returns:
        str: Token JWT de actualización firmado.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(days=30)
    
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.REFRESH_SECRET_KEY or settings.SECRET_KEY,
        algorithm=settings.ALGORITHM
    )
    return encoded_jwt

async def verify_token(
    token: str, 
    token_type: str = "access"
) -> TokenData:
    """
    Verifica y decodifica un token JWT.
    
    Args:
        token: Token JWT a verificar.
        token_type: Tipo de token ('access' o 'refresh').
        
    Returns:
        TokenData: Datos del token decodificados.
        
    Raises:
        errors.InvalidTokenError: Si el token es inválido o ha expirado.
    """
    credentials_exception = errors.InvalidTokenError("No se pudo validar el token")
    
    try:
        secret_key = (
            settings.REFRESH_SECRET_KEY 
            if token_type == "refresh" and settings.REFRESH_SECRET_KEY
            else settings.SECRET_KEY
        )
        
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False},
        )
        
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
            
        token_type_payload = payload.get("type")
        if token_type_payload != token_type:
            raise errors.InvalidTokenError(f"Tipo de token inválido: se esperaba {token_type}")
            
        token_data = TokenData(email=email)
        return token_data
        
    except JWTError:
        raise credentials_exception

async def verify_refresh_token(token: str) -> TokenData:
    """
    Verifica un token de actualización.
    
    Args:
        token: Token de actualización JWT.
        
    Returns:
        TokenData: Datos del token decodificados.
        
    Raises:
        errors.InvalidTokenError: Si el token es inválido o ha expirado.
    """
    return await verify_token(token, "refresh")

async def register_user(
    db: AsyncSession, 
    user_data: dict
) -> User:
    """
    Registra un nuevo usuario en el sistema.
    
    Args:
        db: Sesión de base de datos.
        user_data: Datos del nuevo usuario.
        
    Returns:
        User: El usuario creado.
        
    Raises:
        errors.EmailAlreadyExistsError: Si el correo electrónico ya está registrado.
        DatabaseError: Si ocurre un error al crear el usuario.
    """
    # Verificar si el usuario ya existe
    existing_user = await user_service.get_user_by_email(db, user_data["email"])
    if existing_user:
        raise errors.EmailAlreadyExistsError("El correo electrónico ya está registrado")
    
    try:
        # Crear el usuario
        user_data["hashed_password"] = get_password_hash(user_data.pop("password"))
        user = await user_service.create_user(db, user_data)
        
        # Enviar correo de verificación
        await send_verification_email(db, user.email)
        
        return user
        
    except Exception as e:
        raise DatabaseError(f"Error al registrar el usuario: {str(e)}")

async def send_verification_email(
    db: AsyncSession, 
    email: str
) -> None:
    """
    Envía un correo electrónico de verificación al usuario.
    
    Args:
        db: Sesión de base de datos.
        email: Correo electrónico del usuario.
        
    Raises:
        ResourceNotFoundError: Si el usuario no existe.
    """
    user = await user_service.get_user_by_email(db, email)
    if not user:
        raise ResourceNotFoundError("Usuario no encontrado")
    
    # Crear token de verificación
    token_data = {"sub": user.email}
    token = create_access_token(
        token_data, 
        expires_delta=timedelta(hours=settings.EMAIL_VERIFY_TOKEN_EXPIRE_HOURS)
    )
    
    # TODO: Implementar el envío real del correo electrónico
    # Por ahora, solo imprimimos el token para pruebas
    print(f"Token de verificación para {user.email}: {token}")

async def verify_email_token(
    db: AsyncSession,
    token: str
) -> User:
    """
    Verifica un token de verificación de correo electrónico.
    
    Args:
        db: Sesión de base de datos.
        token: Token de verificación JWT.
        
    Returns:
        User: El usuario verificado.
        
    Raises:
        errors.InvalidTokenError: Si el token es inválido o ha expirado.
        ResourceNotFoundError: Si el usuario no existe.
    """
    try:
        token_data = await verify_token(token, "access")
        user = await user_service.get_user_by_email(db, email=token_data.email)
        
        if not user:
            raise ResourceNotFoundError("Usuario no encontrado")
            
        # Marcar el correo como verificado
        user.is_verified = True
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        return user
        
    except JWTError as e:
        raise errors.InvalidTokenError("Token de verificación inválido o expirado") from e

async def send_password_reset_email(
    db: AsyncSession,
    email: str
) -> None:
    """
    Envía un correo electrónico para restablecer la contraseña.
    
    Args:
        db: Sesión de base de datos.
        email: Correo electrónico del usuario.
        
    Raises:
        ResourceNotFoundError: Si el usuario no existe.
    """
    user = await user_service.get_user_by_email(db, email)
    if not user:
        # Por seguridad, no revelamos si el correo existe o no
        return
    
    # Crear token de restablecimiento
    token_data = {"sub": user.email}
    token = create_access_token(
        token_data,
        expires_delta=timedelta(hours=settings.RESET_PASSWORD_TOKEN_EXPIRE_HOURS)
    )
    
    # TODO: Implementar el envío real del correo electrónico
    # Por ahora, solo imprimimos el token para pruebas
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    print(f"Enlace de restablecimiento para {user.email}: {reset_url}")

async def reset_password(
    db: AsyncSession,
    token: str,
    new_password: str
) -> User:
    """
    Restablece la contraseña de un usuario usando un token de restablecimiento.
    
    Args:
        db: Sesión de base de datos.
        token: Token de restablecimiento JWT.
        new_password: Nueva contraseña en texto plano.
        
    Returns:
        User: El usuario con la contraseña actualizada.
        
    Raises:
        errors.InvalidTokenError: Si el token es inválido o ha expirado.
        ResourceNotFoundError: Si el usuario no existe.
    """
    try:
        token_data = await verify_token(token, "access")
        user = await user_service.get_user_by_email(db, email=token_data.email)
        
        if not user:
            raise ResourceNotFoundError("Usuario no encontrado")
            
        # Actualizar la contraseña
        hashed_password = get_password_hash(new_password)
        user.hashed_password = hashed_password
        db.add(user)
        await db.commit()
        await db.refresh(user)
        
        # TODO: Enviar notificación por correo electrónico
        
        return user
        
    except JWTError as e:
        raise errors.InvalidTokenError("Token de restablecimiento inválido o expirado") from e

async def revoke_token(
    db: AsyncSession,
    token: str
) -> None:
    """
    Revoca un token JWT agregándolo a la lista negra.
    
    Args:
        db: Sesión de base de datos.
        token: Token JWT a revocar.
        
    Raises:
        errors.InvalidTokenError: Si el token es inválido.
    """
    try:
        # Verificar el token para obtener la fecha de expiración
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False, "verify_exp": False},
        )
        
        # Calcular el tiempo restante hasta la expiración
        expire_timestamp = payload.get("exp")
        if not expire_timestamp:
            raise errors.InvalidTokenError("Token sin fecha de expiración")
            
        expire = datetime.utcfromtimestamp(expire_timestamp)
        now = datetime.utcnow()
        
        # Si el token ya expiró, no es necesario revocarlo
        if expire < now:
            return
            
        # Agregar el token a la lista negra
        # TODO: Implementar la lógica de lista negra en la base de datos
        # Por ahora, solo imprimimos el token revocado para pruebas
        print(f"Token revocado: {token}")
        
    except JWTError as e:
        raise errors.InvalidTokenError("Token inválido") from e