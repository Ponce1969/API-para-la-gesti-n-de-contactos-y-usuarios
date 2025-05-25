"""
Esquemas Pydantic para el módulo de contactos.

Este módulo define los esquemas de validación y serialización
para las operaciones relacionadas con contactos y grupos de contactos.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.common.schemas import BaseResponse, PaginatedResponse
from app.contacts.models import ContactStatus, ContactType


# Esquemas base
class ContactBase(BaseModel):
    """Esquema base para los contactos."""

    first_name: Optional[str] = Field(None, description="Nombre del contacto")
    last_name: Optional[str] = Field(None, description="Apellido del contacto")
    email: Optional[EmailStr] = Field(
        None, description="Correo electrónico del contacto"
    )
    phone: Optional[str] = Field(None, description="Número de teléfono del contacto")
    company: Optional[str] = Field(
        None, description="Empresa u organización del contacto"
    )
    position: Optional[str] = Field(
        None, description="Cargo o posición del contacto en la empresa"
    )
    contact_type: ContactType = Field(
        default=ContactType.OTHER,
        description="Tipo de contacto (personal, trabajo, familiar, etc.)",
    )
    status: ContactStatus = Field(
        default=ContactStatus.ACTIVE,
        description="Estado actual del contacto",
    )
    is_favorite: bool = Field(
        default=False, description="Indica si el contacto está marcado como favorito"
    )
    address: Optional[str] = Field(
        None, description="Dirección física completa del contacto"
    )
    notes: Optional[str] = Field(
        None, description="Notas adicionales sobre el contacto"
    )
    custom_fields: Optional[Dict[str, Any]] = Field(
        None, description="Campos personalizados adicionales en formato JSON"
    )

    @field_validator("phone")
    def validate_phone(cls, v):
        """Valida el formato del número de teléfono."""
        if v is not None:
            # Eliminar caracteres no numéricos para validación
            digits_only = "".join(filter(str.isdigit, v))
            # Verificar que hay suficientes dígitos para un número válido
            if len(digits_only) < 8:
                raise ValueError("El número de teléfono debe tener al menos 8 dígitos")
        return v


class ContactCreate(ContactBase):
    """Esquema para la creación de un contacto."""

    # Campos requeridos para la creación
    # Al menos un nombre o apellido debe estar presente
    @field_validator("first_name", "last_name")
    def validate_names(cls, v, values):
        """Valida que al menos uno de los campos de nombre esté presente."""
        if v is None:
            # Si estamos validando last_name, verificar si first_name está presente
            if "first_name" in values and values["first_name"] is None:
                # Si ambos son None, lanzar error
                raise ValueError("Al menos un nombre o apellido debe estar presente")
        return v


class ContactUpdate(ContactBase):
    """Esquema para la actualización de un contacto."""

    # Todos los campos son opcionales para la actualización
    pass


class ContactInDB(ContactBase):
    """Esquema para representar un contacto en la base de datos."""

    id: int = Field(..., description="ID único del contacto")
    owner_id: int = Field(
        ..., description="ID del usuario propietario de este contacto"
    )
    contact_user_id: Optional[int] = Field(
        None,
        description="ID del usuario de la plataforma si el contacto está registrado",
    )
    created_at: datetime = Field(
        ..., description="Fecha y hora de creación del contacto"
    )
    updated_at: datetime = Field(
        ..., description="Fecha y hora de la última actualización del contacto"
    )

    class Config:
        from_attributes = True


# Esquemas para grupos de contactos
class ContactGroupBase(BaseModel):
    """Esquema base para los grupos de contactos."""

    name: str = Field(..., description="Nombre del grupo de contactos")
    description: Optional[str] = Field(
        None, description="Descripción del grupo de contactos"
    )


class ContactGroupCreate(ContactGroupBase):
    """Esquema para la creación de un grupo de contactos."""

    # No se necesitan campos adicionales para la creación
    pass


class ContactGroupUpdate(BaseModel):
    """Esquema para la actualización de un grupo de contactos."""

    name: Optional[str] = Field(None, description="Nuevo nombre del grupo de contactos")
    description: Optional[str] = Field(
        None, description="Nueva descripción del grupo de contactos"
    )


class ContactGroupInDB(ContactGroupBase):
    """Esquema para representar un grupo de contactos en la base de datos."""

    id: int = Field(..., description="ID único del grupo de contactos")
    owner_id: int = Field(
        ..., description="ID del usuario propietario de este grupo de contactos"
    )
    created_at: datetime = Field(
        ..., description="Fecha y hora de creación del grupo de contactos"
    )
    updated_at: datetime = Field(
        ...,
        description="Fecha y hora de la última actualización del grupo de contactos",
    )
    contacts_count: Optional[int] = Field(
        None, description="Número de contactos en este grupo"
    )

    class Config:
        from_attributes = True


# Esquemas para respuestas de API
class ContactResponse(BaseResponse):
    """Esquema para la respuesta de un contacto."""

    data: Optional[dict] = Field(
        None,
        example={
            "id": 1,
            "first_name": "Juan",
            "last_name": "Pérez",
            "email": "juan@ejemplo.com",
            "phone": "+34 612345678",
            "company": "Empresa S.A.",
            "position": "Gerente",
            "contact_type": "work",
            "status": "active",
            "is_favorite": True,
            "address": "Calle Principal 123",
            "notes": "Cliente importante",
            "custom_fields": {"proyecto": "Alpha", "prioridad": "Alta"},
            "owner_id": 1,
            "contact_user_id": None,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
            "groups": [{"id": 1, "name": "Trabajo"}],
        },
    )


class ContactListResponse(PaginatedResponse):
    """Esquema para la respuesta de una lista de contactos."""

    data: List[dict] = Field(
        ...,
        example=[
            {
                "id": 1,
                "first_name": "Juan",
                "last_name": "Pérez",
                "email": "juan@ejemplo.com",
                "phone": "+34 612345678",
                "company": "Empresa S.A.",
                "contact_type": "work",
                "status": "active",
                "is_favorite": True,
            },
            {
                "id": 2,
                "first_name": "María",
                "last_name": "García",
                "email": "maria@ejemplo.com",
                "phone": "+34 698765432",
                "company": "Otra Empresa S.L.",
                "contact_type": "personal",
                "status": "active",
                "is_favorite": False,
            },
        ],
    )


class ContactGroupResponse(BaseResponse):
    """Esquema para la respuesta de un grupo de contactos."""

    data: Optional[dict] = Field(
        None,
        example={
            "id": 1,
            "name": "Trabajo",
            "description": "Contactos de trabajo",
            "owner_id": 1,
            "created_at": "2023-01-01T00:00:00",
            "updated_at": "2023-01-01T00:00:00",
            "contacts_count": 5,
        },
    )


class ContactGroupListResponse(PaginatedResponse):
    """Esquema para la respuesta de una lista de grupos de contactos."""

    data: List[dict] = Field(
        ...,
        example=[
            {
                "id": 1,
                "name": "Trabajo",
                "description": "Contactos de trabajo",
                "contacts_count": 5,
            },
            {
                "id": 2,
                "name": "Familia",
                "description": "Contactos familiares",
                "contacts_count": 10,
            },
        ],
    )


# Esquemas para operaciones con grupos
class AddContactToGroupResponse(BaseResponse):
    """Esquema para la respuesta de agregar un contacto a un grupo."""

    data: Optional[dict] = Field(
        None,
        example={
            "message": "Contacto agregado al grupo correctamente",
            "contact_id": 1,
            "group_id": 2,
        },
    )


class RemoveContactFromGroupResponse(BaseResponse):
    """Esquema para la respuesta de eliminar un contacto de un grupo."""

    data: Optional[dict] = Field(
        None,
        example={
            "message": "Contacto eliminado del grupo correctamente",
            "contact_id": 1,
            "group_id": 2,
        },
    )
