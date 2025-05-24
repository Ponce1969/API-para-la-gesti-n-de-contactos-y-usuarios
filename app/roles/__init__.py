"""
Módulo de gestión de roles y permisos.

Este módulo maneja la lógica de negocio, modelos y rutas para la gestión
de roles y permisos en la aplicación, incluyendo la asignación de permisos a roles.
"""
from . import models, schemas, service, errors, api
from .models import Role, Permission, RolePermission, UserRole
from .schemas import (
    RoleCreate,
    RoleUpdate,
    RoleResponse,
    PermissionResponse,
    RolePermissionCreate,
    RolePermissionResponse,
    UserRoleCreate,
    UserRoleResponse,
)
from .service import (
    get_role_by_id,
    get_roles,
    create_role,
    update_role,
    delete_role,
    get_permissions,
    get_permission_by_id,
    add_permission_to_role,
    remove_permission_from_role,
    get_role_permissions,
    get_user_roles,
    add_role_to_user,
    remove_role_from_user,
    get_user_permissions,
)

__all__ = [
    'models',
    'schemas',
    'service',
    'errors',
    'api',
    'Role',
    'Permission',
    'RolePermission',
    'UserRole',
    'RoleCreate',
    'RoleUpdate',
    'RoleResponse',
    'PermissionResponse',
    'RolePermissionCreate',
    'RolePermissionResponse',
    'UserRoleCreate',
    'UserRoleResponse',
    'get_role_by_id',
    'get_roles',
    'create_role',
    'update_role',
    'delete_role',
    'get_permissions',
    'get_permission_by_id',
    'add_permission_to_role',
    'remove_permission_from_role',
    'get_role_permissions',
    'get_user_roles',
    'add_role_to_user',
    'remove_role_from_user',
    'get_user_permissions',
]