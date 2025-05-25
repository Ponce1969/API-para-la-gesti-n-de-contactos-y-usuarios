"""
Esquemas Pydantic para el módulo de roles y permisos.

Este módulo define los modelos de validación de datos para la API de roles y permisos.
"""
from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


# --- Permission Schemas ---
class PermissionBase(BaseModel):
    """Esquema base para un permiso."""
    name: str = Field(..., description="Nombre descriptivo del permiso")
    code: str = Field(..., description="Código único del permiso (ej: users_create)")
    description: Optional[str] = Field(None, description="Descripción detallada del permiso")


class PermissionResponse(PermissionBase):
    """Esquema para la respuesta de un permiso."""
    id: int = Field(..., description="ID único del permiso")
    created_at: datetime = Field(..., description="Fecha de creación del permiso")
    updated_at: datetime = Field(..., description="Fecha de última actualización del permiso")

    class Config:
        from_attributes = True


# --- Role Schemas ---
class RoleBase(BaseModel):
    """Esquema base para un rol."""
    name: str = Field(..., description="Nombre único del rol")
    description: Optional[str] = Field(None, description="Descripción del rol")


class RoleCreate(RoleBase):
    """Esquema para la creación de un rol."""
    pass


class RoleUpdate(BaseModel):
    """Esquema para la actualización de un rol."""
    name: Optional[str] = Field(None, description="Nuevo nombre del rol")
    description: Optional[str] = Field(None, description="Nueva descripción del rol")
    is_active: Optional[bool] = Field(None, description="Estado de activación del rol")


class RoleResponse(RoleBase):
    """Esquema para la respuesta de un rol."""
    id: int = Field(..., description="ID único del rol")
    is_active: bool = Field(..., description="Indica si el rol está activo")
    is_system: bool = Field(..., description="Indica si es un rol del sistema")
    created_at: datetime = Field(..., description="Fecha de creación del rol")
    updated_at: datetime = Field(..., description="Fecha de última actualización del rol")
    permissions: List[PermissionResponse] = Field([], description="Lista de permisos asociados al rol")

    class Config:
        from_attributes = True


# --- RolePermission Schemas (Asignación de permisos a roles) ---
class RolePermissionCreate(BaseModel):
    """Esquema para asignar un permiso a un rol."""
    permission_id: int = Field(..., description="ID del permiso a asignar")
    # role_id se tomará de la ruta


class RolePermissionResponse(BaseModel):
    """Esquema para la respuesta de una asignación de permiso a rol."""
    role_id: int = Field(..., description="ID del rol")
    permission_id: int = Field(..., description="ID del permiso asignado")
    assigned_at: Optional[datetime] = Field(None, description="Fecha de asignación del permiso al rol")
    # Podríamos anidar PermissionResponse aquí si es necesario en el futuro
    # permission: PermissionResponse

    class Config:
        from_attributes = True
