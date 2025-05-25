"""
Módulo de gestión de roles y permisos.

Este módulo maneja la lógica de negocio, modelos y rutas para la gestión
de roles y permisos en la aplicación, incluyendo la asignación de permisos a roles.
"""

from . import api, errors, models, schemas, service
from .models import Permission, Role, role_permissions, user_roles
# from .schemas import (
#     PermissionResponse,
#     RoleCreate,
#     RolePermissionCreate,
#     RolePermissionResponse,
#     RoleResponse,
#     RoleUpdate,
#     UserRoleCreate,
#     UserRoleResponse,
# )
# from .service import (
#     add_permission_to_role,
#     add_role_to_user,
#     create_role,
#     delete_role,
#     get_permission_by_id,
#     get_permissions,
#     get_role_by_id,
#     get_role_permissions,
#     get_roles,
#     get_user_permissions,
#     get_user_roles,
#     remove_permission_from_role,
#     remove_role_from_user,
#     update_role,
# )

__all__ = [
    "models",
    "schemas",
    "service",
    "errors",
    "api",
    "Role",
    "Permission",
    "RolePermission",
    "UserRole",
    "RoleCreate",
    "RoleUpdate",
    "RoleResponse",
    "PermissionResponse",
    "RolePermissionCreate",
    "RolePermissionResponse",
    "UserRoleCreate",
    "UserRoleResponse",
    "get_role_by_id",
    "get_roles",
    "create_role",
    "update_role",
    "delete_role",
    "get_permissions",
    "get_permission_by_id",
    "add_permission_to_role",
    "remove_permission_from_role",
    "get_role_permissions",
    "get_user_roles",
    "add_role_to_user",
    "remove_role_from_user",
    "get_user_permissions",
]
