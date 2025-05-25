"""
Esquemas base para respuestas de la API.

Este módulo define los esquemas base para las respuestas de la API,
incluyendo manejo de paginación y respuestas estándar.
"""

from typing import Any, Generic, TypeVar

from pydantic import BaseModel, Field
from pydantic.generics import GenericModel

# Tipo genérico para los datos de respuesta
T = TypeVar("T")


class BaseResponse(BaseModel):
    """
    Esquema base para todas las respuestas de la API.

    Atributos:
        success: Indica si la operación fue exitosa
        message: Mensaje descriptivo de la operación
        data: Datos de la respuesta (opcional)
        error: Detalles del error (opcional)
    """

    success: bool = Field(
        ..., default=True, description="Indica si la operación fue exitosa"
    )
    message: str | None = Field(
        ..., default=None, description="Mensaje descriptivo de la operación"
    )
    data: Any | None = Field(..., default=None, description="Datos de la respuesta")
    error: dict | None = Field(..., default=None, description="Detalles del error")

    class Config:
        json_schema_extra = {
            "example": {
                "success": True,
                "message": "Operación exitosa",
                "data": None,
                "error": None,
            }
        }


class PaginationParams(BaseModel):
    """
    Esquema para parámetros de paginación.

    Atributos:
        page: Número de página actual (empieza en 0)
        size: Tamaño de la página (elementos por página)
    """

    page: int = Field(default=0, ge=0, description="Número de página (empieza en 0)")
    size: int = Field(default=100, gt=0, le=1000, description="Tamaño de la página")

    class Config:
        json_schema_extra = {"example": {"page": 0, "size": 100}}


class PaginatedResponse(GenericModel, Generic[T]):
    """
    Esquema base para respuestas paginadas.

    Atributos:
        items: Lista de elementos en la página actual
        total: Número total de elementos
        page: Número de página actual
        size: Tamaño de la página
        pages: Número total de páginas
    """

    items: list[T] = Field(
        default=..., description="Lista de elementos en la página actual"
    )
    total: int = Field(default=..., description="Número total de elementos")
    page: int = Field(default=..., description="Número de página actual")
    size: int = Field(default=..., description="Tamaño de la página")
    pages: int = Field(default=..., description="Número total de páginas")

    class Config:
        json_schema_extra = {
            "example": {"items": [], "total": 0, "page": 1, "size": 10, "pages": 0}
        }


class ErrorResponse(BaseResponse):
    """
    Esquema para respuestas de error.

    Atributos:
        status_code: Código de estado HTTP
        error: Tipo de error
        details: Detalles adicionales del error
    """

    status_code: int = Field(default=..., description="Código de estado HTTP")
    error: str = Field(default=..., description="Tipo de error")
    details: dict | None = Field(
        default=None, description="Detalles adicionales del error"
    )

    class Config:
        json_schema_extra = {
            "example": {
                "success": False,
                "message": "Error en la operación",
                "status_code": 400,
                "error": "Bad Request",
                "details": {"field": "value"},
            }
        }


class SuccessResponse(BaseResponse):
    """
    Esquema para respuestas exitosas.

    Atributos:
        data: Datos de la respuesta
    """

    data: Any = Field(default=..., description="Datos de la respuesta")

    class Config:
        json_schema_extra = {
            "example": {"success": True, "message": "Operación exitosa", "data": {}}
        }


class MessageResponse(BaseResponse):
    """
    Esquema para respuestas con un mensaje simple.

    Atributos:
        message: Mensaje descriptivo
    """

    message: str = Field(default=..., description="Mensaje descriptivo")

    class Config:
        json_schema_extra = {
            "example": {"success": True, "message": "Operación exitosa"}
        }
