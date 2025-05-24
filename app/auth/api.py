"""
Módulo de rutas de la API para autenticación y autorización.

Este módulo define los endpoints para el inicio de sesión, registro,
renovación de tokens y recuperación de contraseñas.
"""
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from app.common.config import settings
from app.common.database import get_db
from app.common.errors import AuthenticationError, DatabaseError
from sqlalchemy.ext.asyncio import AsyncSession

from . import schemas, service
from .models import User
from .schemas import Token, UserCreate, UserResponse

router = APIRouter()

@router.post(
    "/login",
    response_model=Token,
    summary="Iniciar sesión",
    description="Autentica un usuario y devuelve un token de acceso.",
)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> Token:
    """
    Autentica un usuario y devuelve un token de acceso.
    
    Args:
        form_data: Datos del formulario con username y password.
        db: Sesión de base de datos.
        
    Returns:
        Token de acceso JWT.
        
    Raises:
        HTTPException: Si las credenciales son inválidas.
    """
    try:
        user = await service.authenticate_user(
            db, email=form_data.username, password=form_data.password
        )
        if not user:
            raise AuthenticationError("Email o contraseña incorrectos")
            
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = service.create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            user=user,
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar nuevo usuario",
    description="Crea una nueva cuenta de usuario.",
)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> Any:
    """
    Crea un nuevo usuario en el sistema.
    
    Args:
        user_data: Datos del nuevo usuario.
        db: Sesión de base de datos.
        
    Returns:
        El usuario creado.
        
    Raises:
        HTTPException: Si el email ya está registrado.
    """
    try:
        user = await service.register_user(db, user_data)
        return user
    except service.EmailAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El correo electrónico ya está registrado.",
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el usuario.",
        )

@router.post(
    "/token/refresh",
    response_model=Token,
    summary="Renovar token",
    description="Renueva el token de acceso usando un refresh token.",
)
async def refresh_token(
    token_data: schemas.TokenRefresh,
    db: AsyncSession = Depends(get_db),
) -> Token:
    """
    Renueva un token de acceso usando un refresh token.
    
    Args:
        token_data: Datos del token de actualización.
        db: Sesión de base de datos.
        
    Returns:
        Nuevo token de acceso.
        
    Raises:
        HTTPException: Si el refresh token es inválido o ha expirado.
    """
    try:
        # Verificar el refresh token
        email = service.verify_refresh_token(token_data.refresh_token)
        if not email:
            raise AuthenticationError("Token de actualización inválido o expirado")
            
        # Obtener el usuario
        user = await service.get_user_by_email(db, email)
        if not user:
            raise AuthenticationError("Usuario no encontrado")
            
        # Generar nuevo access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = service.create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            user=user,
        )
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )

@router.post(
    "/password-recovery/{email}",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Solicitar recuperación de contraseña",
    description="Envía un correo con un enlace para restablecer la contraseña.",
)
async def recover_password(
    email: str,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Inicia el proceso de recuperación de contraseña.
    
    Args:
        email: Correo electrónico del usuario.
        db: Sesión de base de datos.
        
    Returns:
        Mensaje de confirmación.
    """
    try:
        await service.send_password_reset_email(db, email)
        return {"message": "Si el correo existe, se ha enviado un enlace de recuperación"}
    except Exception as e:
        # No revelar si el correo existe o no por razones de seguridad
        return {"message": "Si el correo existe, se ha enviado un enlace de recuperación"}

@router.post(
    "/reset-password/",
    status_code=status.HTTP_200_OK,
    summary="Restablecer contraseña",
    description="Restablece la contraseña usando un token de restablecimiento.",
)
async def reset_password(
    reset_data: schemas.ResetPassword,
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Restablece la contraseña de un usuario.
    
    Args:
        reset_data: Datos para el restablecimiento de contraseña.
        db: Sesión de base de datos.
        
    Returns:
        Mensaje de confirmación.
        
    Raises:
        HTTPException: Si el token es inválido o ha expirado.
    """
    try:
        await service.reset_password(
            db, reset_data.token, reset_data.new_password
        )
        return {"message": "Contraseña actualizada correctamente"}
    except AuthenticationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
