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

from app.common.errors import DatabaseError, ResourceNotFoundError
from .models import Permission, Role #, role_permissions (tabla de asociación)
from .schemas import (
    PermissionResponse, # Usado si el servicio construye directamente el response
    RoleCreate,
    RoleResponse, # Usado si el servicio construye directamente el response
    RoleUpdate,
    RolePermissionCreate, # Este schema es para input a la API
    RolePermissionResponse # Usado si el servicio construye directamente el response
)

async def create_role(db: AsyncSession, role_data: RoleCreate) -> Role:
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
        await db.commit()
        await db.refresh(db_role)
        return db_role
    except IntegrityError as e: # Captura específica para violación de unicidad u otras restricciones
        await db.rollback() # Es importante revertir la sesión en caso de error
        # La capa API puede capturar esto como DatabaseError o podríamos definir excepciones personalizadas.
        # Por ahora, la relanzamos para que la API la maneje.
        # Considerar: raise RoleAlreadyExistsError(f"Role '{role_data.name}' already exists.") from e
        raise

async def get_roles(db: AsyncSession, skip: int = 0, limit: int = 100) -> List['Role']:
    """
    Obtiene una lista de roles de la base de datos con paginación.

    Args:
        db: Sesión de base de datos asíncrona.
        skip: Número de roles a omitir.
        limit: Número máximo de roles a devolver.

    Returns:
        Una lista de objetos Role.
    """
    query = select(Role).offset(skip).limit(limit).order_by(Role.id)
    result = await db.execute(query)
    return list(result.scalars().all())

async def get_role_by_id(db: AsyncSession, role_id: int) -> Optional['Role']:
    """
    Obtiene un rol por su ID de la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol a buscar.

    Returns:
        El objeto Role si se encuentra, de lo contrario None.
    """
    query = select(Role).where(Role.id == role_id)
    result = await db.execute(query)
    return result.scalar_one_or_none()

async def update_role(db: AsyncSession, role_id: int, role_data: RoleUpdate) -> Optional['Role']:
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
    db_role = await get_role_by_id(db, role_id)
    if not db_role:
        return None

    # Actualizar los campos. Pydantic model_dump(exclude_unset=True) es útil aquí
    # para solo actualizar los campos que se proporcionan en la solicitud.
    update_data = role_data.model_dump(exclude_unset=True)
    for key, value in update_data.items():
        setattr(db_role, key, value)
    
    db.add(db_role) # SQLAlchemy rastrea cambios, pero add() es explícito.
    try:
        await db.commit()
        await db.refresh(db_role)
        return db_role
    except IntegrityError as e:
        await db.rollback()
        # Considerar: raise RoleNameConflictError o similar si es un error de unicidad de nombre.
        raise e


async def delete_role(db: AsyncSession, role_id: int) -> Optional['Role']:
    """
    Elimina un rol de la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol a eliminar.

    Returns:
        El objeto Role eliminado si se encuentra y elimina, de lo contrario None.
    """
    db_role = await get_role_by_id(db, role_id)
    if not db_role:
        return None
    
    await db.delete(db_role)
    try:
        await db.commit()
        # No se puede hacer refresh a un objeto eliminado, pero devolvemos el objeto tal como estaba antes de eliminarlo.
        # La API no espera contenido de vuelta (204 No Content), pero el servicio puede devolverlo para confirmación.
        return db_role 
    except IntegrityError as e: # Por si hay restricciones de FK que impiden la eliminación
        await db.rollback()
        # Considerar: raise RoleInUseError(f"Role '{db_role.name}' cannot be deleted as it is in use.") from e
        raise e

async def get_permissions(db: AsyncSession) -> List['Permission']:
    """
    Obtiene una lista de todos los permisos de la base de datos.

    Args:
        db: Sesión de base de datos asíncrona.

    Returns:
        Una lista de objetos Permission.
    """
    query = select(Permission).order_by(Permission.id)
    result = await db.execute(query)
    return list(result.scalars().all())

async def add_permission_to_role(db: AsyncSession, role_id: int, permission_id: int) -> Optional['Role']:
    """
    Asigna un permiso a un rol existente.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol.
        permission_id: ID del permiso a asignar.

    Returns:
        El objeto Role actualizado con el permiso asignado, o None si el rol o permiso no existen.
    """
    db_role = await db.get(models.Role, role_id, options=[selectinload(models.Role.permissions)])
    if not db_role:
        # Considerar: raise RoleNotFoundError(f"Role with id {role_id} not found")
        return None

    db_permission = await db.get(models.Permission, permission_id)
    if not db_permission:
        # Considerar: raise PermissionNotFoundError(f"Permission with id {permission_id} not found")
        return None

    # Verificar si el permiso ya está asignado al rol para idempotencia
    if db_permission not in db_role.permissions:
        db_role.permissions.append(db_permission)
        db.add(db_role)
        try:
            await db.commit()
            await db.refresh(db_role, attribute_names=['permissions']) # Asegurar que la relación se refresca
        except IntegrityError as e: # Podría ocurrir si hay constraints inesperados
            await db.rollback()
            # Considerar: raise PermissionAssignmentError(
            #    f"Could not assign permission {permission_id} to role {role_id}: {e}"
            # )
            raise e
    
    return db_role

async def remove_permission_from_role(db: AsyncSession, role_id: int, permission_id: int) -> Optional['Role']:
    """
    Elimina un permiso de un rol existente.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol.
        permission_id: ID del permiso a eliminar.

    Returns:
        El objeto Role actualizado sin el permiso, o None si el rol o permiso no existen o no estaban asociados.
    """
    db_role = await db.get(models.Role, role_id, options=[selectinload(models.Role.permissions)])
    if not db_role:
        # Considerar: raise RoleNotFoundError(f"Role with id {role_id} not found")
        return None

    db_permission = await db.get(models.Permission, permission_id)
    if not db_permission:
        # Considerar: raise PermissionNotFoundError(f"Permission with id {permission_id} not found")
        return None

    # Verificar si el permiso está realmente asignado al rol
    if db_permission in db_role.permissions:
        db_role.permissions.remove(db_permission)
        db.add(db_role)
        try:
            await db.commit()
            await db.refresh(db_role, attribute_names=['permissions']) # Asegurar que la relación se refresca
        except IntegrityError as e: # Menos probable aquí, pero por consistencia
            await db.rollback()
            # Considerar: raise PermissionRemovalError(
            #    f"Could not remove permission {permission_id} from role {role_id}: {e}"
            # )
            raise e
        return db_role # Devuelve el rol actualizado
    else:
        # El permiso no estaba asignado, se considera la operación exitosa (idempotencia) o se puede devolver None/error
        # Devolver el rol tal cual para indicar que el estado deseado (permiso no presente) se cumple.
        return db_role

async def get_role_permissions(db: AsyncSession, role_id: int) -> List['Permission']:
    """
    Obtiene los permisos asignados a un rol específico.

    Args:
        db: Sesión de base de datos asíncrona.
        role_id: ID del rol.

    Returns:
        Una lista de objetos Permission asignados al rol. Devuelve una lista vacía si el rol no existe.
    """
    # La API en get_role_permissions ya verifica si el rol existe primero.
    # Si llegamos aquí, el rol debería existir. No obstante, por seguridad:
    db_role = await db.get(models.Role, role_id, options=[selectinload(models.Role.permissions)])
    if not db_role:
        # Esto no debería ocurrir si la API valida la existencia del rol primero.
        # Considerar: raise RoleNotFoundError(f"Role with id {role_id} not found during permission retrieval")
        return [] # Devuelve lista vacía si el rol no se encuentra
    
    return list(db_role.permissions) # Devuelve la lista de permisos del rol[]
