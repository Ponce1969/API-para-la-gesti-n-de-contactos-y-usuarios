"""
Esquemas Pydantic para el módulo de contactos.

Este módulo define los esquemas de validación y serialización
para las operaciones relacionadas con contactos y grupos de contactos.
"""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.common.schemas import BaseResponse, PaginatedResponse
from app.contacts.models import ContactStatus, ContactType


# Esquemas base
class ContactBase(BaseModel):
    """Esquema base para los contactos."""

    first_name: str | None = Field(default=None, description="Nombre del contacto")
    last_name: str | None = Field(default=None, description="Apellido del contacto")
    email: EmailStr | None = Field(
        default=None, description="Correo electrónico del contacto"
    )
    phone: str | None = Field(
        default=None, description="Número de teléfono del contacto"
    )
    company: str | None = Field(
        default=None, description="Empresa u organización del contacto"
    )
    position: str | None = Field(
        default=None, description="Cargo o posición del contacto en la empresa"
    )
    contact_type: ContactType = Field(
        default=ContactType.OTHER,
        description="Tipo de contacto (personal, trabajo, familiar, etc.)",
    )
    status: ContactStatus = Field(
        default=ContactStatus.ACTIVE, description="Estado actual del contacto"
    )
    is_favorite: bool = Field(
        default=False, description="Indica si el contacto está marcado como favorito"
    )
    address: str | None = Field(
        default=None, description="Dirección física completa del contacto"
    )
    notes: str | None = Field(
        default=None, description="Notas adicionales sobre el contacto"
    )
    custom_fields: dict[str, Any] | None = Field(
        default=None, description="Campos personalizados adicionales en formato JSON"
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
    @field_validator("first_name")
    def validate_first_name_or_last_name_present(cls, v, info):
        """Valida que al menos first_name o last_name esté presente."""
        if v is None and (info.data.get("last_name") is None and info.data.get("email") is None and info.data.get("phone") is None) :
            if not info.data.get("last_name"): # Check if last_name is also None or empty
                 raise ValueError("Se requiere al menos un nombre, apellido, email o teléfono.")
        return v

    @field_validator("last_name")
    def validate_last_name_or_first_name_present(cls, v, info):
        """Valida que al menos first_name o last_name esté presente."""
        if v is None and (info.data.get("first_name") is None and info.data.get("email") is None and info.data.get("phone") is None):
            if not info.data.get("first_name"): # Check if first_name is also None or empty
                 raise ValueError("Se requiere al menos un nombre, apellido, email o teléfono.")
        return v


class ContactUpdate(ContactBase):
    """Esquema para la actualización de un contacto."""

    # Todos los campos son opcionales para la actualización
    pass


class ContactInDB(ContactBase):
    """Esquema para representar un contacto en la base de datos."""

    id: int = Field(default=..., description="ID único del contacto")
    owner_id: int = Field(
        default=..., description="ID del usuario propietario de este contacto"
    )
    contact_user_id: int | None = Field(
        default=None,
        description="ID del usuario de la plataforma si el contacto está registrado",
    )
    created_at: datetime = Field(
        default=..., description="Fecha y hora de creación del contacto"
    )
    updated_at: datetime = Field(
        default=..., description="Fecha y hora de la última actualización del contacto"
    )

    model_config = {"from_attributes": True}


# Esquemas para grupos de contactos
class ContactGroupBase(BaseModel):
    """Esquema base para los grupos de contactos."""

    name: str = Field(default=..., description="Nombre del grupo de contactos")
    description: str | None = Field(
        default=None, description="Descripción del grupo de contactos"
    )


class ContactGroupCreate(ContactGroupBase):
    """Esquema para la creación de un grupo de contactos."""

    # No se necesitan campos adicionales para la creación
    pass


class ContactGroupUpdate(BaseModel):
    """Esquema para la actualización de un grupo de contactos."""

    name: str | None = Field(
        default=None, description="Nuevo nombre del grupo de contactos"
    )
    description: str | None = Field(
        default=None, description="Nueva descripción del grupo de contactos"
    )


class ContactGroupInDB(ContactGroupBase):
    """Esquema para representar un grupo de contactos en la base de datos."""

    id: int = Field(default=..., description="ID único del grupo de contactos")
    owner_id: int = Field(
        default=..., description="ID del usuario propietario de este grupo de contactos"
    )
    created_at: datetime = Field(
        default=..., description="Fecha y hora de creación del grupo de contactos"
    )
    updated_at: datetime = Field(
        default=...,
        description="Fecha y hora de la última actualización del grupo de contactos",
    )
    contacts_count: int | None = Field(
        default=None, description="Número de contactos en este grupo"
    )

    model_config = {"from_attributes": True}


# Schemas for public representation (excluding owner_id, sensitive fields if any)
class ContactPublic(ContactBase):
    id: int
    contact_user_id: int | None = None
    created_at: datetime
    updated_at: datetime
    groups: list[dict[str, Any]] = [] # Simplified group info for now

    model_config = {"from_attributes": True}


class ContactGroupPublic(ContactGroupBase):
    id: int
    created_at: datetime
    updated_at: datetime
    contacts_count: int | None = 0

    model_config = {"from_attributes": True}


# Esquemas para respuestas de API
class ContactResponse(BaseResponse):
    """Esquema para la respuesta de un contacto."""

    data: ContactPublic | None = Field(default=None)


class ContactListResponse(PaginatedResponse[ContactPublic]):
    """Esquema para la respuesta de una lista de contactos."""
    # Inherits 'items: list[ContactPublic]', 'total', 'page', 'size', 'pages'
    # If 'data' field is preferred:
    data: list[ContactPublic] | None = Field(default=None, description="Lista de contactos")


class ContactGroupResponse(BaseResponse):
    """Esquema para la respuesta de un grupo de contactos."""

    data: ContactGroupPublic | None = Field(default=None)


class ContactGroupListResponse(PaginatedResponse[ContactGroupPublic]):
    """Esquema para la respuesta de una lista de grupos de contactos."""
    data: list[ContactGroupPublic] | None = Field(default=None, description="Lista de grupos de contactos")


# Schemas for specific operation responses
class ContactGroupAssociationData(BaseModel):
    message: str
    contact_id: int
    group_id: int

class AddContactToGroupResponse(BaseResponse):
    """Esquema para la respuesta de agregar un contacto a un grupo."""
    data: ContactGroupAssociationData | None = None


class RemoveContactFromGroupResponse(BaseResponse):
    """Esquema para la respuesta de eliminar un contacto de un grupo."""
    data: ContactGroupAssociationData | None = None
