"""
Esquemas Pydantic para el módulo de usuarios.

Este módulo define los modelos de validación de datos para la API de usuarios.
"""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.common.schemas import BaseResponse, PaginatedResponse


# Esquemas base
class UserBase(BaseModel):
    """Esquema base para usuario."""

    email: EmailStr = Field(..., description="Correo electrónico del usuario")
    full_name: Optional[str] = Field(None, description="Nombre completo del usuario")
    is_active: bool = Field(
        default=True, description="Indica si el usuario está activo"
    )
    is_superuser: bool = Field(
        default=False, description="Indica si el usuario es superusuario"
    )
    is_verified: bool = Field(
        default=False, description="Indica si el correo del usuario ha sido verificado"
    )


# Esquemas para creación y actualización
class UserCreate(UserBase):
    """Esquema para la creación de un usuario."""

    password: str = Field(
        ..., min_length=8, max_length=100, description="Contraseña del usuario"
    )

    @field_validator("password")
    def password_must_be_strong(cls, v: str) -> str:
        """Valida que la contraseña cumpla con los requisitos de seguridad."""
        if len(v) < 8:
            raise ValueError("La contraseña debe tener al menos 8 caracteres")
        if not any(char.isdigit() for char in v):
            raise ValueError("La contraseña debe contener al menos un número")
        if not any(char.isupper() for char in v):
            raise ValueError("La contraseña debe contener al menos una letra mayúscula")
        if not any(char.islower() for char in v):
            raise ValueError("La contraseña debe contener al menos una letra minúscula")
        if not any(char in "!@#$%^&*()_+-=[]{}|;:,.<>?" for char in v):
            raise ValueError(
                "La contraseña debe contener al menos un carácter especial"
            )
        return v


class UserUpdate(BaseModel):
    """Esquema para la actualización de un usuario."""

    email: Optional[EmailStr] = Field(None, description="Nuevo correo electrónico")
    full_name: Optional[str] = Field(None, description="Nuevo nombre completo")
    password: Optional[str] = Field(
        None, min_length=8, max_length=100, description="Nueva contraseña"
    )
    is_active: Optional[bool] = Field(
        None, description="Indica si el usuario está activo"
    )
    is_verified: Optional[bool] = Field(
        None, description="Indica si el correo ha sido verificado"
    )


# Esquema para la base de datos
class UserInDB(UserBase):
    """Esquema para representar un usuario en la base de datos."""

    id: int = Field(..., description="ID único del usuario")
    hashed_password: str = Field(..., description="Hash de la contraseña")
    created_at: datetime = Field(..., description="Fecha de creación del usuario")
    updated_at: datetime = Field(..., description="Fecha de última actualización")

    class Config:
        from_attributes = True
        json_schema_extra = {
            "example": {
                "id": 1,
                "email": "usuario@ejemplo.com",
                "full_name": "Nombre Apellido",
                "is_active": True,
                "is_superuser": False,
                "is_verified": True,
                "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        }


# Esquemas para respuesta
class UserResponse(BaseResponse):
    """Esquema para la respuesta de un usuario."""

    data: Optional[dict] = Field(
        None,
        example={
            "id": 1,
            "email": "usuario@ejemplo.com",
            "full_name": "Nombre Apellido",
            "is_active": True,
            "is_superuser": False,
            "is_verified": True,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
        },
    )


class UserListResponse(PaginatedResponse):
    """Esquema para la respuesta de una lista de usuarios."""

    data: List[dict] = Field(
        ...,
        example=[
            {
                "id": 1,
                "email": "usuario1@ejemplo.com",
                "full_name": "Usuario Uno",
                "is_active": True,
                "is_superuser": False,
                "is_verified": True,
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            },
            {
                "id": 2,
                "email": "usuario2@ejemplo.com",
                "full_name": "Usuario Dos",
                "is_active": True,
                "is_superuser": False,
                "is_verified": True,
                "created_at": "2023-01-02T00:00:00",
                "updated_at": "2023-01-02T00:00:00",
            },
        ],
    )


# Esquema para autenticación
class Token(BaseModel):
    """Esquema para la respuesta de autenticación."""

    access_token: str
    token_type: str = "bearer"
    user: dict


class TokenData(BaseModel):
    """Esquema para los datos del token."""

    email: Optional[str] = None


# --- Verification Token Schemas ---

class VerificationTokenBase(BaseModel):
    """Esquema base para un token de verificación."""
    token: str = Field(..., description="El valor del token único.")
    user_id: int = Field(..., description="ID del usuario al que pertenece el token.")
    token_type: str = Field(..., description="Tipo de token (ej: email_verification, password_reset).")
    expires_at: datetime = Field(..., description="Fecha y hora de expiración del token.")

class VerificationTokenCreateInternal(VerificationTokenBase):
    """
    Esquema para la creación interna de un token de verificación en la BD.
    Se espera que todos los campos sean provistos.
    """
    # Este esquema se usa cuando todos los datos del token (incluido el token en sí y expires_at)
    # ya están definidos, típicamente justo antes de guardarlo en la BD.
    pass

class VerificationTokenInDBBase(VerificationTokenBase):
    """Esquema base para un token de verificación leído desde la BD."""
    id: int = Field(..., description="ID único del token.")
    created_at: datetime = Field(..., description="Fecha y hora de creación del token.")
    is_used: bool = Field(..., description="Indica si el token ya ha sido utilizado.")

    class Config:
        from_attributes = True # Para Pydantic v2

class VerificationTokenInDB(VerificationTokenInDBBase):
    """Esquema completo para un token de verificación leído desde la BD."""
    # Hereda todos los campos y la configuración.
    pass

class VerificationTokenServiceCreate(BaseModel):
    """
    Esquema para solicitar la creación de un token de verificación desde un servicio.
    El token y la fecha de expiración serán generados por el servicio.
    """
    user_id: int = Field(..., description="ID del usuario para el cual generar el token.")
    token_type: str = Field(..., description="Tipo de token a generar (ej: email_verification, password_reset).")


# Esquema para cambio de contraseña
class PasswordResetRequest(BaseModel):
    """Esquema para solicitar restablecimiento de contraseña."""

    email: EmailStr = Field(..., description="Correo electrónico del usuario")


class PasswordReset(BaseModel):
    """Esquema para restablecer la contraseña."""

    token: str = Field(..., description="Token de restablecimiento")
    new_password: str = Field(
        ..., min_length=8, max_length=100, description="Nueva contraseña"
    )


# Esquema para verificación de correo
class EmailVerifyRequest(BaseModel):
    """Esquema para solicitar verificación de correo."""

    token: str = Field(..., description="Token de verificación")


# Esquema para la respuesta de autenticación
class AuthResponse(BaseResponse):
    """Esquema para la respuesta de autenticación."""

    data: Optional[dict] = Field(
        None,
        example={
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "bearer",
            "user": {
                "id": 1,
                "email": "usuario@ejemplo.com",
                "full_name": "Nombre Apellido",
                "is_active": True,
                "is_superuser": False,
                "is_verified": True,
            },
        },
    )


# Esquema para la respuesta de verificación de correo
class EmailVerifyResponse(BaseResponse):
    """Esquema para la respuesta de verificación de correo."""

    data: Optional[dict] = Field(
        None,
        example={
            "message": "Correo verificado exitosamente",
            "user": {"id": 1, "email": "usuario@ejemplo.com", "is_verified": True},
        },
    )


# Esquema para la respuesta de restablecimiento de contraseña
class PasswordResetResponse(BaseResponse):
    """Esquema para la respuesta de restablecimiento de contraseña."""

    data: Optional[dict] = Field(
        None, example={"message": "Contraseña actualizada exitosamente"}
    )
