"""
Módulo de excepciones personalizadas para el módulo de autenticación.

Este módulo define excepciones personalizadas para manejar errores
de autenticación y autorización de manera consistente en toda la aplicación.
"""
from fastapi import HTTPException, status

# Excepción para credenciales inválidas
CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="No se pudieron validar las credenciales",
    headers={"WWW-Authenticate": "Bearer"},
)

# Excepción para usuario inactivo
INACTIVE_USER_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="Usuario inactivo",
)

# Excepción para token inválido o expirado
INVALID_TOKEN_EXCEPTION = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Token inválido o expirado",
    headers={"WWW-Authenticate": "Bearer"},
)

# Excepción para permisos insuficientes
INSUFFICIENT_PRIVILEGES_EXCEPTION = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="No tiene los permisos necesarios para realizar esta acción",
)

# Excepción para credenciales incorrectas
INCORRECT_CREDENTIALS_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="Email o contraseña incorrectos",
)

# Excepción para cuenta deshabilitada
ACCOUNT_DISABLED_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="Cuenta deshabilitada. Por favor, contacte al administrador.",
)

# Excepción para cuenta no verificada
ACCOUNT_NOT_VERIFIED_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="Por favor, verifique su correo electrónico para activar su cuenta.",
)

# Excepción para token de restablecimiento inválido
INVALID_RESET_TOKEN_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="El enlace de restablecimiento no es válido o ha expirado.",
)

# Excepción para token de verificación inválido
INVALID_VERIFICATION_TOKEN_EXCEPTION = HTTPException(
    status_code=status.HTTP_400_BAD_REQUEST,
    detail="El enlace de verificación no es válido o ha expirado.",
)

class AuthenticationError(Exception):
    """Excepción base para errores de autenticación."""
    pass

class EmailAlreadyExistsError(AuthenticationError):
    """Excepción lanzada cuando se intenta registrar un email que ya existe."""
    pass

class InvalidCredentialsError(AuthenticationError):
    """Excepción lanzada cuando las credenciales son inválidas."""
    pass

class InactiveUserError(AuthenticationError):
    """Excepción lanzada cuando un usuario inactivo intenta autenticarse."""
    pass

class UnverifiedAccountError(AuthenticationError):
    """Excepción lanzada cuando un usuario no verificado intenta autenticarse."""
    pass

class InvalidTokenError(AuthenticationError):
    """Excepción lanzada cuando un token es inválido o ha expirado."""
    pass

class ExpiredTokenError(InvalidTokenError):
    """Excepción lanzada cuando un token ha expirado."""
    pass

def handle_auth_error(error: AuthenticationError) -> HTTPException:
    """
    Maneja una excepción de autenticación y devuelve la respuesta HTTP apropiada.
    
    Args:
        error: Excepción de autenticación.
        
    Returns:
        HTTPException: Respuesta HTTP con el código de estado y mensaje apropiados.
    """
    if isinstance(error, (InvalidCredentialsError, EmailAlreadyExistsError)):
        return INCORRECT_CREDENTIALS_EXCEPTION
    elif isinstance(error, InactiveUserError):
        return INACTIVE_USER_EXCEPTION
    elif isinstance(error, UnverifiedAccountError):
        return ACCOUNT_NOT_VERIFIED_EXCEPTION
    elif isinstance(error, (InvalidTokenError, ExpiredTokenError)):
        return INVALID_TOKEN_EXCEPTION
    else:
        # Error no manejado específicamente
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de autenticación inesperado",
        )