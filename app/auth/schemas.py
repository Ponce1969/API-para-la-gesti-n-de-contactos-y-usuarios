"""
Esquemas Pydantic para el módulo de autenticación.

Este módulo define los modelos de validación de datos para la API de autenticación,
manejo de tokens y reseteo de contraseñas.
"""
from typing import Optional

from pydantic import BaseModel, EmailStr, Field


class Token(BaseModel):
    """Esquema para la respuesta del token de acceso."""
    access_token: str = Field(..., description="Token de acceso JWT")
    token_type: str = Field(default="bearer", description="Tipo de token (siempre 'bearer')")
    # refresh_token: Optional[str] = Field(None, description="Token de refresco JWT, si aplica")


class TokenData(BaseModel):
    """Esquema para los datos contenidos dentro de un token JWT."""
    # Usaremos 'sub' (subject) para el identificador del usuario, que puede ser email o ID.
    sub: Optional[str] = Field(None, description="Identificador del sujeto del token (e.g., email o user_id)")
    # Otros campos que se quieran incluir en el token, como roles, scopes, etc.
    # scopes: List[str] = []


class TokenRefresh(BaseModel):
    """Esquema para la solicitud de refresco de token."""
    refresh_token: str = Field(..., description="Token de refresco JWT válido")


class PasswordResetRequest(BaseModel):
    """Esquema para solicitar un reseteo de contraseña."""
    email: EmailStr = Field(..., description="Email del usuario para el cual se solicita el reseteo")


class ResetPasswordSchema(BaseModel):
    """Esquema para realizar el reseteo de contraseña con un token."""
    token: str = Field(..., description="Token de reseteo de contraseña recibido por email")
    new_password: str = Field(..., min_length=8, description="Nueva contraseña para el usuario")


# Podríamos necesitar un schema para el login si no usamos OAuth2PasswordRequestForm directamente
# class UserLogin(BaseModel):
#     username: EmailStr # o str si se permite login con username
#     password: str
