"""Módulo de errores personalizados para la aplicación.

Este módulo define las clases de error personalizadas utilizadas en toda la aplicación,
proporcionando un manejo de errores consistente y tipado.
"""

from enum import Enum
from typing import Any

from fastapi import HTTPException, status
from pydantic import BaseModel, Field


class ErrorCode(str, Enum):
    """Códigos de error estandarizados para la aplicación.

    Los códigos de error siguen el formato: PREFIJO_DESCRIPCION
    """

    # Errores de autenticación y autorización (1000-1999)
    INVALID_CREDENTIALS = "AUTH_1000"
    INVALID_TOKEN = "AUTH_1001"
    EXPIRED_TOKEN = "AUTH_1002"
    INSUFFICIENT_PERMISSIONS = "AUTH_1003"
    ACCOUNT_DISABLED = "AUTH_1004"
    ACCOUNT_LOCKED = "AUTH_1005"

    # Errores de validación (2000-2999)
    VALIDATION_ERROR = "VALID_2000"
    INVALID_EMAIL = "VALID_2001"
    PASSWORD_TOO_WEAK = "VALID_2002"

    # Errores de recursos (3000-3999)
    RESOURCE_NOT_FOUND = "RES_3000"
    DUPLICATE_ENTRY = "RES_3001"

    # Errores de base de datos (4000-4999)
    DATABASE_ERROR = "DB_4000"
    INTEGRITY_ERROR = "DB_4001"

    # Errores del servidor (5000-5999)
    INTERNAL_SERVER_ERROR = "SRV_5000"
    SERVICE_UNAVAILABLE = "SRV_5001"

    # Errores de la API (6000-6999)
    BAD_REQUEST = "API_6000"
    RATE_LIMIT_EXCEEDED = "API_6001"


class ErrorDetail(BaseModel):
    """Detalle de error estandarizado para respuestas de la API."""

    code: str = Field(..., description="Código de error único")
    message: str = Field(..., description="Mensaje de error descriptivo")
    detail: str | dict[str, Any] | list[Any] | None = Field(
        None, description="Detalles adicionales del error"
    )


class AppError(Exception):
    """Clase base para todos los errores de la aplicación.

    Args:
        status_code: Código de estado HTTP
        code: Código de error personalizado
        message: Mensaje de error descriptivo
        detail: Detalles adicionales del error
        headers: Encabezados HTTP opcionales
    """

    def __init__(
        self,
        status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR,
        code: str | ErrorCode = ErrorCode.INTERNAL_SERVER_ERROR,
        message: str = "Ha ocurrido un error inesperado",
        detail: str | dict[str, Any] | list[Any] | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        self.status_code = status_code
        self.code = code.value if isinstance(code, ErrorCode) else code
        self.message = message
        self.detail = detail
        self.headers = headers
        super().__init__(self.message)

    def to_dict(self) -> dict[str, Any]:
        """Convierte el error a un diccionario para la respuesta de la API."""
        error_detail = ErrorDetail(
            code=self.code, message=self.message, detail=self.detail
        )
        return {"error": error_detail.model_dump(exclude_none=True)}


# Errores específicos
class ResourceNotFoundError(AppError):
    """Excepción lanzada cuando no se encuentra un recurso solicitado."""

    def __init__(
        self,
        resource_name: str = "recurso",
        resource_id: str | int | None = None,
        detail: str | dict[str, Any] | None = None,
    ) -> None:
        message = f"No se encontró el {resource_name}"
        if resource_id is not None:
            message += f" con ID {resource_id}"

        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=message,
            detail=detail or {"resource": resource_name, "id": resource_id},
        )


class UnauthorizedError(AppError):
    """Excepción lanzada cuando falla la autenticación."""

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(
            status_code=status.HTTP_401_UNAUTHORIZED,
            code=ErrorCode.INVALID_CREDENTIALS,
            message="No autorizado: credenciales inválidas o faltantes",
            detail=detail or "Se requiere autenticación para acceder a este recurso",
            headers={"WWW-Authenticate": "Bearer"},
        )


class ForbiddenError(AppError):
    """Excepción lanzada cuando el usuario no tiene permisos suficientes."""

    def __init__(self, detail: str | None = None) -> None:
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.INSUFFICIENT_PERMISSIONS,
            message="No tiene permisos para realizar esta acción",
            detail=detail,
        )


class ValidationError(AppError):
    """Excepción lanzada cuando falla la validación de datos."""

    def __init__(self, detail: str | dict[str, Any] | list[Any]) -> None:
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code=ErrorCode.VALIDATION_ERROR,
            message="Error de validación",
            detail=detail,
        )


class ConflictError(AppError):
    """Excepción lanzada cuando hay un conflicto con el estado actual del recurso."""

    def __init__(self, detail: str | dict[str, Any] | None = None) -> None:
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.DUPLICATE_ENTRY,
            message="Conflicto con el estado actual del recurso",
            detail=detail,
        )


class DatabaseError(AppError):
    """Excepción lanzada cuando ocurre un error en la base de datos."""

    def __init__(self, detail: str | dict[str, Any] | None = None) -> None:
        super().__init__(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            code=ErrorCode.DATABASE_ERROR,
            message="Error en la base de datos",
            detail=detail,
        )


class ServiceError(AppError):
    """Excepción lanzada cuando falla un servicio externo o interno."""

    def __init__(self, detail: str | dict[str, Any] | None = None) -> None:
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            code=ErrorCode.SERVICE_UNAVAILABLE,
            message="Error en el servicio",
            detail=detail,
        )


def handle_error(error: AppError) -> HTTPException:
    """Convierte un AppError en una HTTPException para FastAPI."""
    return HTTPException(
        status_code=error.status_code,
        detail=error.to_dict().get(
            "error"
        ),  # Usamos to_dict() para el formato estándar
        headers=error.headers,
    )
