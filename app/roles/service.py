# app/roles/service.py
"""
Lógica de negocio para la gestión de roles y permisos.

Este módulo contiene funciones para interactuar con la base de datos
y realizar operaciones CRUD en los modelos Role y Permission, así como
manejar sus relaciones.
"""
from typing import List, Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload # For eager loading relationships

from app.common.errors import DatabaseError, ResourceNotFoundError
from app.common.result import Result, Success, Failure # Import Result types
from . import errors as role_errors # Import custom errors
from .models import Permission, Role #, role_permissions (tabla de asociación)
from .schemas import (
    # PermissionResponse, # Responses are usually built in handlers/API layer
    RoleCreate,
    # RoleResponse,
    RoleUpdate,
    # RolePermissionCreate,
    # RolePermissionResponse
)

async def create_role(db: AsyncSession, role_data: RoleCreate) -> Result[Role, role_errors.RoleAlreadyExistsError | DatabaseError]:
    """
    Crea un nuevo rol en la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.
        role_data: Datos del rol a crear.

    Returns:
        El objeto Role creado.

    Raises:
        IntegrityError: Si ya existe un rol con el mismo nombre (propagada para ser manejada por la capa de API como DatabaseError o más específicamente).
    """
    db_role = Role(name=role_data.name, description=role_data.description)
    db.add(db_role)
    try:
        # Check if role with the same name already exists
        existing_role_query = select(Role).where(Role.name == role_data.name)
        existing_role_result = await db.execute(existing_role_query)
        if existing_role_result.scalar_one_or_none() is not None:
            return Failure(role_errors.RoleAlreadyExistsError(role_name=role_data.name))

        await db.commit()
        await db.refresh(db_role)
        return Success(db_role)
    except IntegrityError: # Should be caught by the name check above, but as a safeguard
        await db.rollback()
        return Failure(role_errors.RoleAlreadyExistsError(role_name=role_data.name))
    except Exception as e:
        await db.rollback()
        return Failure(DatabaseError(detail=f"Error al crear rol: {e!s}"))


async def get_roles(db: AsyncSession, skip: int = 0, limit: int = 100) -> Result[List[Role], DatabaseError]:
    """
    Obtiene una lista de roles de la base de datos con paginación.

    Args:
        db: Sesión de base de datos asíncrona.
        skip: Número de roles a omitir.
        limit: Número máximo de roles a devolver.

    Returns:
        Una lista de objetos Role.
    """
    try:
        query = select(Role).offset(skip).limit(limit).order_by(Role.id)
        result = await db.execute(query)
        return Success(list(result.scalars().all()))
    except Exception as e:
        return Failure(DatabaseError(detail=f"Error al obtener roles: {e!s}"))

async def get_role_by_id(db: AsyncSession, role_id: int) -> Result[Role, role_errors.RoleNotFoundError | DatabaseError]:
    """
    Obtiene un rol por su ID de la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol a buscar.

    Returns:
        El objeto Role si se encuentra, de lo contrario None.
    """
    try:
        query = select(Role).where(Role.id == role_id)
        result = await db.execute(query)
        role = result.scalar_one_or_none()
        if role is None:
            return Failure(role_errors.RoleNotFoundError(role_id=role_id))
        return Success(role)
    except Exception as e:
        return Failure(DatabaseError(detail=f"Error al obtener rol por ID: {e!s}"))

async def update_role(db: AsyncSession, role_id: int, role_data: RoleUpdate) -> Result[Role, role_errors.RoleNotFoundError | role_errors.RoleAlreadyExistsError | DatabaseError]:
    """
    Actualiza un rol existente en la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol a actualizar.
        role_data: Datos para actualizar el rol.

    Returns:
        El objeto Role actualizado si se encuentra, de lo contrario None.
        
    Raises:
        IntegrityError: Si la actualización viola restricciones de la base de datos (ej. nombre duplicado).
    """
    role_result = await get_role_by_id(db, role_id)
    if role_result.is_failure():
        return role_result # RoleNotFoundError or DatabaseError

    db_role = role_result.unwrap()

    update_data = role_data.model_dump(exclude_unset=True)

    if "name" in update_data and update_data["name"] != db_role.name:
        # Check if new name already exists
        existing_role_query = select(Role).where(Role.name == update_data["name"], Role.id != role_id)
        existing_role_exec = await db.execute(existing_role_query)
        if existing_role_exec.scalar_one_or_none() is not None:
            return Failure(role_errors.RoleAlreadyExistsError(role_name=update_data["name"]))

    for key, value in update_data.items():
        setattr(db_role, key, value)
    
    try:
        await db.commit()
        await db.refresh(db_role)
        return Success(db_role)
    except IntegrityError: # Should be caught by name check, but as safeguard
        await db.rollback()
        return Failure(role_errors.RoleAlreadyExistsError(role_name=str(update_data.get("name", ""))))
    except Exception as e:
        await db.rollback()
        return Failure(DatabaseError(detail=f"Error al actualizar rol: {e!s}"))


async def delete_role(db: AsyncSession, role_id: int) -> Result[Role, role_errors.RoleNotFoundError | DatabaseError | role_errors.RoleDeleteError]:
    """
    Elimina un rol de la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol a eliminar.

    Returns:
        El objeto Role eliminado si se encuentra y elimina, de lo contrario None.
    """
    role_result = await get_role_by_id(db, role_id)
    if role_result.is_failure():
        return role_result # RoleNotFoundError or DatabaseError
    
    db_role = role_result.unwrap()
    
    # Additional business logic for deletion can be added here (e.g., check if role is in use)
    # For now, directly deleting.
    try:
        await db.delete(db_role)
        await db.commit()
        return Success(db_role) # Return the deleted role object for confirmation
    except IntegrityError: # For FK constraints if role is in use
        await db.rollback()
        return Failure(role_errors.RoleDeleteError(role_id=role_id, message="No se puede eliminar el rol porque está en uso."))
    except Exception as e:
        await db.rollback()
        return Failure(DatabaseError(detail=f"Error al eliminar rol: {e!s}"))

async def get_permissions(db: AsyncSession) -> Result[List[Permission], DatabaseError]:
    """
    Obtiene una lista de todos los permisos de la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.

    Returns:
        Una lista de objetos Permission.
    """
    try:
        query = select(Permission).order_by(Permission.id)
        result = await db.execute(query)
        return Success(list(result.scalars().all()))
    except Exception as e:
        return Failure(DatabaseError(detail=f"Error al obtener permisos: {e!s}"))

async def add_permission_to_role(db: AsyncSession, role_id: int, permission_id: int) -> Result[Role, role_errors.RoleNotFoundError | role_errors.PermissionNotFoundError | DatabaseError | role_errors.PermissionAssignmentError]:
    """
    Asigna un permiso a un rol existente.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol.
        permission_id: ID del permiso a asignar.

    Returns:
        El objeto Role actualizado con el permiso asignado, o un error.
    """
    role_result = await get_role_by_id(db, role_id) # Uses Result now
    if role_result.is_failure():
        return Failure(role_errors.RoleNotFoundError(role_id=role_id))
    db_role = role_result.unwrap()

    # PermissionRepository would be better here if it exists and returns Result
    db_permission = await db.get(Permission, permission_id)
    if not db_permission:
        return Failure(role_errors.PermissionNotFoundError(permission_id=permission_id))

    if db_permission not in db_role.permissions:
        db_role.permissions.append(db_permission)
        try:
            await db.commit()
            await db.refresh(db_role, attribute_names=['permissions'])
            return Success(db_role)
        except IntegrityError:
            await db.rollback()
            return Failure(role_errors.PermissionAssignmentError(f"No se pudo asignar el permiso {permission_id} al rol {role_id}"))
        except Exception as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error de base de datos al asignar permiso: {e!s}"))
    return Success(db_role) # Permiso ya asignado, considerado éxito


async def remove_permission_from_role(db: AsyncSession, role_id: int, permission_id: int) -> Result[Role, role_errors.RoleNotFoundError | role_errors.PermissionNotFoundError | DatabaseError | role_errors.PermissionAssignmentError]:
    """
    Elimina un permiso de un rol existente.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol.
        permission_id: ID del permiso a eliminar.

    Returns:
        El objeto Role actualizado sin el permiso, o un error.
    """
    role_result = await get_role_by_id(db, role_id) # Uses Result now
    if role_result.is_failure():
        return Failure(role_errors.RoleNotFoundError(role_id=role_id))
    db_role = role_result.unwrap()

    db_permission = await db.get(Permission, permission_id) # Similar to above, could use a repo method
    if not db_permission:
        return Failure(role_errors.PermissionNotFoundError(permission_id=permission_id))

    if db_permission in db_role.permissions:
        db_role.permissions.remove(db_permission)
        try:
            await db.commit()
            await db.refresh(db_role, attribute_names=['permissions'])
            return Success(db_role)
        except IntegrityError: # Should not typically happen on remove if FKs are set up
            await db.rollback()
            return Failure(role_errors.PermissionAssignmentError(f"No se pudo remover el permiso {permission_id} del rol {role_id}"))
        except Exception as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error de base de datos al remover permiso: {e!s}"))
    
    # Permiso no estaba asignado, se considera éxito o un error específico "PermissionNotAssignedError"
    return Success(db_role)


async def get_role_permissions(db: AsyncSession, role_id: int) -> Result[List[Permission], role_errors.RoleNotFoundError | DatabaseError]:
    """
    Obtiene los permisos asignados a un rol específico.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol.

    Returns:
        Una lista de objetos Permission asignados al rol, o un error.
    """
    role_result = await get_role_by_id(db, role_id) # Uses Result now
    if role_result.is_failure():
        return Failure(role_errors.RoleNotFoundError(role_id=role_id))
    
    db_role = role_result.unwrap()
    # Eager load permissions if not already loaded by get_role_by_id
    # (assuming get_role_by_id does not eager load permissions by default)
    # If get_role_by_id already loads them via options=[selectinload(Role.permissions)], then this is fine.
    # Otherwise, a separate query or refreshing with attribute_names=['permissions'] might be needed.
    # For simplicity, assuming 'db_role.permissions' is accessible and loaded.
    try:
        # Make sure permissions are loaded. If Role.permissions is a lazy load by default,
        # accessing it here might trigger a synchronous load if not handled carefully in async.
        # The `selectinload` option in `get_role_by_id` (if added there) or here is crucial.
        # If `get_role_by_id` does not load permissions:
        # refreshed_role = await db.refresh(db_role, attribute_names=['permissions']) # This is one way
        # return Success(list(refreshed_role.permissions))
        # Or query directly:
        # query = select(Permission).join(Role.permissions).where(Role.id == role_id)
        # permissions_result = await db.execute(query)
        # return Success(list(permissions_result.scalars().all()))
        
        # Assuming Role.permissions is already loaded (e.g. via selectinload in get_by_id or relationships)
        return Success(list(db_role.permissions))
    except Exception as e:
        return Failure(DatabaseError(detail=f"Error al obtener permisos del rol: {e!s}"))
