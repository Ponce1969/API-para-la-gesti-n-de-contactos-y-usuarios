"""
Módulo JWT para la autenticación.

Este módulo proporciona funciones para crear, verificar y manejar tokens JWT,
utilizando el patrón Result para un manejo funcional de errores.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

from jose import JWTError, jwt
from returns.result import Result, Success, Failure
import uuid

from app.auth import errors # Import the errors module
from app.auth.schemas import TokenData
from app.common.config import settings


def create_token(
    data: Dict[str, Any], 
    secret_key: str, 
    expires_delta: Optional[timedelta] = None,
    token_type: str = "access"
) -> Result[str, errors.InvalidTokenError]: # Use aliased errors
    """
    Crea un token JWT genérico.

    Args:
        data: Diccionario con los datos a incluir en el payload (ej. {"sub": "user_email"}).
        secret_key: Clave secreta para firmar el token.
        expires_delta: Tiempo de expiración. Si es None, se usa un valor predeterminado.
        token_type: Tipo de token ("access" o "refresh").

    Returns:
        Result[str, InvalidTokenError]: Un Result que contiene el token JWT si la operación
        es exitosa, o un InvalidTokenError si ocurre un error.
    """
    try:
        to_encode = data.copy()
        
        # Agregar tiempo de expiración
        if expires_delta:
            expire = datetime.now(timezone.utc) + expires_delta
        else:
            expire = datetime.now(timezone.utc) + timedelta(minutes=15)
        
        # Agregar claims estándar y personalizados
        to_encode.update({
            "exp": expire,
            "iat": datetime.now(timezone.utc),  # Issued At
            "type": token_type,
            "jti": str(uuid.uuid4())  # JWT ID único para prevenir reutilización
        })
        
        # Codificar el token
        encoded_jwt = jwt.encode(
            to_encode, 
            secret_key, 
            algorithm=settings.JWT_ALGORITHM
        )
        
        return Success(encoded_jwt)
    except Exception as e:
        return Failure(errors.InvalidTokenError(f"Error al crear el token: {str(e)}"))


def create_access_token(
    data: Dict[str, Any], 
    expires_delta: Optional[timedelta] = None
) -> Result[str, errors.InvalidTokenError]: # Use aliased errors
    """
    Crea un token de acceso JWT.

    Args:
        data: Diccionario con los datos a incluir en el payload (ej. {"sub": "user_email"}).
        expires_delta: Tiempo de expiración. Si es None, se usa el valor predeterminado.

    Returns:
        Result[str, InvalidTokenError]: Un Result que contiene el token JWT si la operación
        es exitosa, o un InvalidTokenError si ocurre un error.
    """
    if not expires_delta:
        expires_delta = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    
    return create_token(
        data=data,
        secret_key=settings.JWT_SECRET_KEY.get_secret_value(),
        expires_delta=expires_delta,
        token_type="access"
    )


def create_refresh_token(
    data: Dict[str, Any], 
    expires_delta: Optional[timedelta] = None
) -> Result[str, errors.InvalidTokenError]: # Use aliased errors
    """
    Crea un token de actualización JWT.

    Args:
        data: Diccionario con los datos a incluir en el payload (ej. {"sub": "user_email"}).
        expires_delta: Tiempo de expiración. Si es None, se usa el valor predeterminado.

    Returns:
        Result[str, InvalidTokenError]: Un Result que contiene el token JWT si la operación
        es exitosa, o un InvalidTokenError si ocurre un error.
    """
    if not expires_delta:
        expires_delta = timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    
    return create_token(
        data=data,
        secret_key=settings.JWT_REFRESH_SECRET_KEY.get_secret_value(),
        expires_delta=expires_delta,
        token_type="refresh"
    )


def create_password_reset_token(
    data: Dict[str, Any]
) -> Result[str, errors.InvalidTokenError]: # Use aliased errors
    """
    Crea un token específico para el restablecimiento de contraseña.

    Args:
        data: Datos a incluir en el token, típicamente {"sub": email}.

    Returns:
        Result[str, InvalidTokenError]: Un Result que contiene el token JWT si la operación
        es exitosa, o un InvalidTokenError si ocurre un error.
    """
    expires_delta = timedelta(hours=settings.RESET_PASSWORD_TOKEN_EXPIRE_HOURS)
    
    return create_token(
        data=data,
        secret_key=settings.JWT_SECRET_KEY.get_secret_value(),
        expires_delta=expires_delta,
        token_type="reset"
    )


def create_email_verification_token(
    data: Dict[str, Any]
) -> Result[str, errors.InvalidTokenError]: # Use aliased errors
    """
    Crea un token específico para la verificación de correo electrónico.

    Args:
        data: Datos a incluir en el token, típicamente {"sub": email}.

    Returns:
        Result[str, InvalidTokenError]: Un Result que contiene el token JWT si la operación
        es exitosa, o un InvalidTokenError si ocurre un error.
    """
    expires_delta = timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS)
    
    return create_token(
        data=data,
        secret_key=settings.JWT_SECRET_KEY.get_secret_value(),
        expires_delta=expires_delta,
        token_type="email_verification"
    )


def verify_token(
    token: str, 
    token_type: str = "access"
) -> Result[TokenData, errors.InvalidTokenError]: # Use aliased errors
    """
    Verifica y decodifica un token JWT.

    Args:
        token: El token JWT a verificar.
        token_type: El tipo de token esperado ("access", "refresh", "reset", "email_verification").

    Returns:
        Result[TokenData, InvalidTokenError]: Un Result que contiene un objeto TokenData con
        el subject del token si la verificación es exitosa, o un InvalidTokenError si
        el token es inválido o ha expirado.
    """
    # Seleccionar la clave secreta adecuada según el tipo de token
    if token_type == "access" or token_type == "reset" or token_type == "email_verification":
        secret_key = settings.JWT_SECRET_KEY.get_secret_value()
    elif token_type == "refresh":
        secret_key = settings.JWT_REFRESH_SECRET_KEY.get_secret_value()
    else:
        return Failure(errors.InvalidTokenError(f"Tipo de token no válido: {token_type}"))
    
    try:
        # Decodificar el token
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[settings.JWT_ALGORITHM],
            options={"verify_aud": False}  # No verificamos audiencia por ahora
        )
        
        # Verificar que el token contenga un subject
        sub_val = payload.get("sub")
        if sub_val is None:
            return Failure(errors.InvalidTokenError("Token no contiene un identificador de usuario (sub)"))
        
        # Verificar que el tipo de token coincida con el esperado
        token_payload_type = payload.get("type")
        if token_payload_type != token_type:
            return Failure(errors.InvalidTokenError(
                f"Tipo de token incorrecto. Esperado: {token_type}, Recibido: {token_payload_type}"
            ))
        
        # Crear y devolver el objeto TokenData
        token_data = TokenData(sub=str(sub_val)) # Ensure sub is str
        return Success(token_data)
    
    except jwt.ExpiredSignatureError:
        return Failure(errors.ExpiredTokenError("El token ha expirado"))
    except JWTError as e:
        return Failure(errors.InvalidTokenError(f"Token inválido: {str(e)}"))
    except Exception as e:
        return Failure(errors.InvalidTokenError(f"Error al verificar el token: {str(e)}"))


def verify_refresh_token(token: str) -> Result[TokenData, errors.InvalidTokenError]: # Use aliased errors
    """
    Verifica un token de actualización JWT.

    Args:
        token: El token de actualización JWT a verificar.

    Returns:
        Result[TokenData, InvalidTokenError]: Un Result que contiene un objeto TokenData con
        el subject del token si la verificación es exitosa, o un InvalidTokenError si
        el token es inválido o ha expirado.
    """
    return verify_token(token, token_type="refresh")


def decode_token_payload(
    token: str, 
    verify_signature: bool = True
) -> Result[Dict[str, Any], errors.InvalidTokenError]: # Use aliased errors
    """
    Decodifica el payload de un token JWT sin verificar el tipo de token.
    
    Útil para obtener información del token sin importar su tipo, 
    o para inspeccionar tokens potencialmente inválidos.

    Args:
        token: El token JWT a decodificar.
        verify_signature: Si es True, verifica la firma del token. 
                         Si es False, solo decodifica el payload sin verificar.

    Returns:
        Result[Dict[str, Any], InvalidTokenError]: Un Result que contiene el payload
        completo del token si la decodificación es exitosa, o un InvalidTokenError
        si el token no puede ser decodificado.
    """
    try:
        if verify_signature:
            # Intentamos primero con la clave de acceso
            try:
                payload = jwt.decode(
                    token,
                    settings.JWT_SECRET_KEY.get_secret_value(),
                    algorithms=[settings.JWT_ALGORITHM],
                    options={"verify_aud": False}
                )
                return Success(payload)
            except Exception:
                # Si falla, probamos con la clave de refresh
                try:
                    payload = jwt.decode(
                        token,
                        settings.JWT_REFRESH_SECRET_KEY.get_secret_value(),
                        algorithms=[settings.JWT_ALGORITHM],
                        options={"verify_aud": False}
                    )
                    return Success(payload)
                except Exception as e:
                    return Failure(errors.InvalidTokenError(f"Token inválido: {str(e)}"))
        else:
            # Solo decodificar sin verificar firma
            payload = jwt.decode(
                token,
                key=None, # Explicitly set key to None when verify_signature is False
                algorithms=None, # Explicitly set algorithms to None when verify_signature is False
                options={"verify_signature": False, "verify_aud": False}
            )
            return Success(payload)
    except Exception as e:
        return Failure(errors.InvalidTokenError(f"Error al decodificar el token: {str(e)}"))
