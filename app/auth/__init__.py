"""
Módulo de autenticación y autorización.

Este módulo maneja la autenticación de usuarios, generación de tokens JWT,
recuperación de contraseñas y verificación de permisos.
"""

from fastapi import HTTPException, status

from . import api, dependencies, errors, schemas, service
from .dependencies import (
    get_current_active_superuser,
    get_current_active_user,
    get_current_user,
    get_optional_current_user,
)
from .errors import (
    ACCOUNT_DISABLED_EXCEPTION,
    ACCOUNT_NOT_VERIFIED_EXCEPTION,
    CREDENTIALS_EXCEPTION,
    INACTIVE_USER_EXCEPTION,
    INCORRECT_CREDENTIALS_EXCEPTION,
    INSUFFICIENT_PRIVILEGES_EXCEPTION,
    INVALID_RESET_TOKEN_EXCEPTION,
    INVALID_TOKEN_EXCEPTION,
    INVALID_VERIFICATION_TOKEN_EXCEPTION,
    AuthenticationError,
    EmailAlreadyExistsError,
    ExpiredTokenError,
    InactiveUserError,
    InvalidCredentialsError,
    InvalidTokenError,
    UnverifiedAccountError,
    handle_auth_error,
)
# from .models import TokenBlacklist, User  # Commented out: app/auth/models.py does not exist
from .schemas import (
    ResetPasswordSchema,
    Token,
    TokenData,
    TokenRefresh,
)
from app.users.schemas import UserCreate, UserResponse
from .service import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    get_password_hash,
    register_user,
    reset_password,
    revoke_token,
    send_password_reset_email,
    send_verification_email,
    verify_email_token,
    verify_password,
    verify_refresh_token,
    verify_token,
)

__all__ = [
    # Módulos
    
    "schemas",
    "service",
    "errors",
    "api",
    "dependencies",
    # Modelos
    
    
    # Esquemas
    "Token",
    "UserCreate",
    "UserResponse",
    "TokenRefresh",
    "ResetPasswordSchema",
    "TokenData",
    # Servicios
    "authenticate_user",
    "create_access_token",
    "create_refresh_token",
    "verify_password",
    "get_password_hash",
    "register_user",
    "verify_token",
    "verify_refresh_token",
    "send_password_reset_email",
    "reset_password",
    "send_verification_email",
    "verify_email_token",
    "revoke_token",
    # Dependencias
    "get_current_user",
    "get_current_active_user",
    "get_current_active_superuser",
    "get_optional_current_user",
    # Excepciones
    "AuthenticationError",
    "EmailAlreadyExistsError",
    "InvalidCredentialsError",
    "InactiveUserError",
    "UnverifiedAccountError",
    "InvalidTokenError",
    "ExpiredTokenError",
    "handle_auth_error",
    # Constantes de excepciones
    "CREDENTIALS_EXCEPTION",
    "INACTIVE_USER_EXCEPTION",
    "INVALID_TOKEN_EXCEPTION",
    "INSUFFICIENT_PRIVILEGES_EXCEPTION",
    "INCORRECT_CREDENTIALS_EXCEPTION",
    "ACCOUNT_DISABLED_EXCEPTION",
    "ACCOUNT_NOT_VERIFIED_EXCEPTION",
    "INVALID_RESET_TOKEN_EXCEPTION",
    "INVALID_VERIFICATION_TOKEN_EXCEPTION",
]
