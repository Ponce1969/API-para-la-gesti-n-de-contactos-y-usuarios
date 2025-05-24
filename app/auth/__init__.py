"""
Módulo de autenticación y autorización.

Este módulo maneja la autenticación de usuarios, generación de tokens JWT,
recuperación de contraseñas y verificación de permisos.
"""
from fastapi import HTTPException, status

from . import models, schemas, service, errors, api, dependencies
from .models import User, TokenBlacklist
from .schemas import Token, UserCreate, UserResponse, TokenRefresh, ResetPassword, TokenData
from .service import (
    authenticate_user,
    create_access_token,
    create_refresh_token,
    verify_password,
    get_password_hash,
    register_user,
    verify_token,
    verify_refresh_token,
    send_password_reset_email,
    reset_password,
    send_verification_email,
    verify_email_token,
    revoke_token,
)
from .dependencies import (
    get_current_user,
    get_current_active_user,
    get_current_active_superuser,
    get_optional_current_user,
)
from .errors import (
    AuthenticationError,
    EmailAlreadyExistsError,
    InvalidCredentialsError,
    InactiveUserError,
    UnverifiedAccountError,
    InvalidTokenError,
    ExpiredTokenError,
    handle_auth_error,
    CREDENTIALS_EXCEPTION,
    INACTIVE_USER_EXCEPTION,
    INVALID_TOKEN_EXCEPTION,
    INSUFFICIENT_PRIVILEGES_EXCEPTION,
    INCORRECT_CREDENTIALS_EXCEPTION,
    ACCOUNT_DISABLED_EXCEPTION,
    ACCOUNT_NOT_VERIFIED_EXCEPTION,
    INVALID_RESET_TOKEN_EXCEPTION,
    INVALID_VERIFICATION_TOKEN_EXCEPTION,
)

__all__ = [
    # Módulos
    'models',
    'schemas',
    'service',
    'errors',
    'api',
    'dependencies',
    
    # Modelos
    'User',
    'TokenBlacklist',
    
    # Esquemas
    'Token',
    'UserCreate',
    'UserResponse',
    'TokenRefresh',
    'ResetPassword',
    'TokenData',
    
    # Servicios
    'authenticate_user',
    'create_access_token',
    'create_refresh_token',
    'verify_password',
    'get_password_hash',
    'register_user',
    'verify_token',
    'verify_refresh_token',
    'send_password_reset_email',
    'reset_password',
    'send_verification_email',
    'verify_email_token',
    'revoke_token',
    
    # Dependencias
    'get_current_user',
    'get_current_active_user',
    'get_current_active_superuser',
    'get_optional_current_user',
    
    # Excepciones
    'AuthenticationError',
    'EmailAlreadyExistsError',
    'InvalidCredentialsError',
    'InactiveUserError',
    'UnverifiedAccountError',
    'InvalidTokenError',
    'ExpiredTokenError',
    'handle_auth_error',
    
    # Constantes de excepciones
    'CREDENTIALS_EXCEPTION',
    'INACTIVE_USER_EXCEPTION',
    'INVALID_TOKEN_EXCEPTION',
    'INSUFFICIENT_PRIVILEGES_EXCEPTION',
    'INCORRECT_CREDENTIALS_EXCEPTION',
    'ACCOUNT_DISABLED_EXCEPTION',
    'ACCOUNT_NOT_VERIFIED_EXCEPTION',
    'INVALID_RESET_TOKEN_EXCEPTION',
    'INVALID_VERIFICATION_TOKEN_EXCEPTION',
]