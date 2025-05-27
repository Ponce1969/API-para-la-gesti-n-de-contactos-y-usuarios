"""
Esquemas Pydantic para el módulo de usuarios.

Este módulo define los modelos de validación de datos para la API de usuarios.
"""

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.common.schemas import BaseResponse, PaginatedResponse


# Esquemas base
class UserBase(BaseModel):
    """Esquema base para usuario."""

    email: EmailStr = Field(default=..., description="Correo electrónico del usuario")
    full_name: str | None = Field(
        default=None, description="Nombre completo del usuario"
    )
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

    email: EmailStr | None = Field(None, description="Nuevo correo electrónico")
    full_name: str | None = Field(None, description="Nuevo nombre completo")
    password: str | None = Field(
        None, min_length=8, max_length=100, description="Nueva contraseña"
    )
    is_active: bool | None = Field(None, description="Indica si el usuario está activo")
    is_verified: bool | None = Field(
        None, description="Indica si el correo ha sido verificado"
    )


# Esquema para la base de datos
class UserInDB(UserBase):
    """Esquema para representar un usuario en la base de datos."""

    id: int = Field(default=..., description="ID único del usuario")
    hashed_password: str = Field(default=..., description="Hash de la contraseña")
    first_name: str | None = Field(default=None, description="Nombre(s) del usuario") # Modelo User tiene first_name/last_name
    last_name: str | None = Field(default=None, description="Apellido(s) del usuario") # Modelo User tiene first_name/last_name
    created_at: datetime = Field(
        default=..., description="Fecha de creación del usuario"
    )
    updated_at: datetime = Field(
        default=..., description="Fecha de última actualización"
    )

    model_config = {
        "from_attributes": True,
        "json_schema_extra": {
            "example": {
                "id": 1,
                "email": "usuario@ejemplo.com",
                "first_name": "Nombre",
                "last_name": "Apellido",
                "is_active": True,
                "is_superuser": False,
                "is_verified": True,
                "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        }
    }


# Esquema para datos públicos del usuario (sin campos sensibles)
class UserPublic(BaseModel):
    id: int
    email: EmailStr
    full_name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    is_active: bool
    is_superuser: bool
    is_verified: bool
    created_at: datetime
    updated_at: datetime

    model_config = {
        "from_attributes": True, # Permite crear desde instancias de modelo SQLAlchemy
        "json_schema_extra": {
            "example": {
                "id": 1,
                "email": "usuario@ejemplo.com",
                "full_name": "Nombre Apellido", # Podría ser una propiedad del modelo User
                "first_name": "Nombre",
                "last_name": "Apellido",
                "is_active": True,
                "is_superuser": False,
                "is_verified": True,
                "created_at": "2023-01-01T00:00:00",
                "updated_at": "2023-01-01T00:00:00",
            }
        }
    }

    @field_validator("full_name", mode="before")
    @classmethod
    def assemble_full_name(cls, v, values):
        if isinstance(v, str):
            return v
        first_name = values.data.get("first_name")
        last_name = values.data.get("last_name")
        if first_name and last_name:
            return f"{first_name} {last_name}"
        return first_name or last_name or ""


# Esquemas para respuesta
class UserResponse(BaseResponse):
    """Esquema para la respuesta de un usuario."""
    data: UserPublic | None = None


class UserListResponse(PaginatedResponse[UserPublic]):
    """Esquema para la respuesta de una lista de usuarios."""
    # La clase base PaginatedResponse[T] ya define 'items: list[T]'
    # No es necesario redefinir 'data' aquí si 'items' es el campo deseado.
    # Si se quiere mantener 'data' como el nombre del campo, se debe sobrescribir.
    # Por consistencia con BaseResponse, mantendremos 'data'
    data: list[UserPublic] | None = Field(None, description="Lista de usuarios")
    # pagination: dict | None = Field(None, description="Información de paginación") # Ya en PaginatedResponse


# Esquema para autenticación
class Token(BaseModel):
    """Esquema para la respuesta de autenticación."""

    access_token: str
    token_type: str = "bearer"
    user: UserPublic # Usar el esquema público


class TokenData(BaseModel):
    """Esquema para los datos del token."""

    email: str | None = None


# --- Verification Token Schemas ---


class VerificationTokenBase(BaseModel):
    """Esquema base para un token de verificación."""

    token: str = Field(..., description="El valor del token único.")
    user_id: int = Field(..., description="ID del usuario al que pertenece el token.")
    token_type: str = Field(
        ..., description="Tipo de token (ej: email_verification, password_reset)."
    )
    expires_at: datetime = Field(
        ..., description="Fecha y hora de expiración del token."
    )


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

    model_config = {"from_attributes": True}


class VerificationTokenInDB(VerificationTokenInDBBase):
    """Esquema completo para un token de verificación leído desde la BD."""

    # Hereda todos los campos y la configuración.
    pass


class VerificationTokenServiceCreate(BaseModel):
    """
    Esquema para solicitar la creación de un token de verificación desde un servicio.
    El token y la fecha de expiración serán generados por el servicio.
    """

    user_id: int = Field(
        ..., description="ID del usuario para el cual generar el token."
    )
    token_type: str = Field(
        ...,
        description="Tipo de token a generar (ej: email_verification, password_reset).",
    )


# Esquema para cambio de contraseña
class PasswordResetRequest(BaseModel):
    """Esquema para solicitar restablecimiento de contraseña."""

    email: EmailStr = Field(default=..., description="Correo electrónico del usuario")


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
class AuthResponseData(BaseModel):
    token: Token
    user: UserPublic

class AuthResponse(BaseResponse):
    """Esquema para la respuesta de autenticación."""
    data: AuthResponseData | None = None


# Esquema para la respuesta de verificación de correo
class EmailVerifyResponseData(BaseModel):
    message: str
    user: UserPublic # O un subconjunto más pequeño si es preferible

class EmailVerifyResponse(BaseResponse):
    """Esquema para la respuesta de verificación de correo."""
    data: EmailVerifyResponseData | None = None


# Esquema para la respuesta de restablecimiento de contraseña
class PasswordResetResponseData(BaseModel):
    message: str

class PasswordResetResponse(BaseResponse):
    """Esquema para la respuesta de restablecimiento de contraseña."""
    data: PasswordResetResponseData | None = None
