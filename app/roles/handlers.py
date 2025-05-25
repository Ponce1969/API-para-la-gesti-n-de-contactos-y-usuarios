"""
Endpoints para la gestión de roles y permisos.

Este módulo define los endpoints de la API para la gestión de roles y permisos,
incluida la creación, actualización, eliminación y obtención de roles, así como
la asignación y eliminación de permisos.
"""

from typing import Dict, List, Optional, Any

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_active_superuser, get_current_active_user
from app.common.database import get_db
from app.common.errors import handle_error
from app.users.models import User
from app.roles.errors import (
    ROLE_NOT_FOUND_EXCEPTION,
    ROLE_ALREADY_EXISTS_EXCEPTION,
    SYSTEM_ROLE_MODIFICATION_EXCEPTION,
    PERMISSION_NOT_FOUND_EXCEPTION,
    handle_role_error
)
from app.roles.models import Role, Permission
from app.roles.repository import RoleRepository, PermissionRepository
from app.roles.schemas import (
    RoleCreate,
    RoleUpdate,
    RoleResponse,
    PermissionResponse,
    RolePermissionCreate
)

# Crear el router
router = APIRouter(prefix="/roles", tags=["roles"])


@router.get("/", response_model=List[RoleResponse])
async def get_roles(
    skip: int = Query(0, ge=0, description="Número de registros a omitir para paginación"),
    limit: int = Query(100, ge=1, le=100, description="Límite de registros a retornar"),
    include_inactive: bool = Query(False, description="Incluir roles inactivos"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user)
) -> List[Role]:
    """
    Obtiene la lista de roles con paginación.

    Args:
        skip: Número de registros a omitir (para paginación).
        limit: Límite de registros a retornar.
        include_inactive: Si es True, incluye roles inactivos.
        db: Sesión de base de datos.
        _: Usuario actual (para verificar autenticación).

    Returns:
        List[Role]: Lista de roles.

    Raises:
        HTTPException: Si ocurre un error al obtener los roles.
    """
    try:
        result = await RoleRepository.get_all(db, skip, limit, include_inactive)
        if result.is_failure():
            error = result.failure()
            raise handle_error(error)
        
        return result.unwrap()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener roles: {str(e)}"
        )


@router.get("/{role_id}", response_model=RoleResponse)
async def get_role(
    role_id: int = Path(..., ge=1, description="ID del rol a obtener"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user)
) -> Role:
    """
    Obtiene un rol por su ID.

    Args:
        role_id: ID del rol a obtener.
        db: Sesión de base de datos.
        _: Usuario actual (para verificar autenticación).

    Returns:
        Role: El rol encontrado.

    Raises:
        HTTPException: Si el rol no existe o hay un error al obtenerlo.
    """
    try:
        result = await RoleRepository.get_by_id(db, role_id)
        if result.is_failure():
            error = result.failure()
            raise handle_role_error(error)
        
        return result.unwrap()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener rol: {str(e)}"
        )


@router.post("/", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_superuser)
) -> Role:
    """
    Crea un nuevo rol.

    Args:
        role_data: Datos del rol a crear.
        db: Sesión de base de datos.
        _: Usuario administrador actual (solo administradores pueden crear roles).

    Returns:
        Role: El rol creado.

    Raises:
        HTTPException: Si ya existe un rol con el mismo nombre o hay un error al crearlo.
    """
    try:
        result = await RoleRepository.create(
            db, 
            name=role_data.name, 
            description=role_data.description
        )
        if result.is_failure():
            error = result.failure()
            raise handle_role_error(error)
        
        await db.commit()
        return result.unwrap()
    except HTTPException:
        raise
    except IntegrityError as e:
        await db.rollback()
        if "unique constraint" in str(e).lower() and "name" in str(e).lower():
            raise ROLE_ALREADY_EXISTS_EXCEPTION
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error de integridad al crear rol: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear rol: {str(e)}"
        )


@router.put("/{role_id}", response_model=RoleResponse)
async def update_role(
    role_id: int = Path(..., ge=1, description="ID del rol a actualizar"),
    role_data: RoleUpdate = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_superuser)
) -> Role:
    """
    Actualiza un rol existente.

    Args:
        role_id: ID del rol a actualizar.
        role_data: Datos para actualizar el rol.
        db: Sesión de base de datos.
        _: Usuario administrador actual (solo administradores pueden actualizar roles).

    Returns:
        Role: El rol actualizado.

    Raises:
        HTTPException: Si el rol no existe, se intenta modificar un rol del sistema,
                      ya existe otro rol con el nuevo nombre, o hay un error al actualizarlo.
    """
    if role_data is None:
        role_data = RoleUpdate()
    
    try:
        result = await RoleRepository.update(
            db,
            role_id=role_id,
            name=role_data.name,
            description=role_data.description,
            is_active=role_data.is_active
        )
        if result.is_failure():
            error = result.failure()
            raise handle_role_error(error)
        
        await db.commit()
        return result.unwrap()
    except HTTPException:
        raise
    except IntegrityError as e:
        await db.rollback()
        if "unique constraint" in str(e).lower() and "name" in str(e).lower():
            raise ROLE_ALREADY_EXISTS_EXCEPTION
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error de integridad al actualizar rol: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar rol: {str(e)}"
        )


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_id: int = Path(..., ge=1, description="ID del rol a eliminar"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_superuser)
) -> None:
    """
    Elimina un rol existente.

    Args:
        role_id: ID del rol a eliminar.
        db: Sesión de base de datos.
        _: Usuario administrador actual (solo administradores pueden eliminar roles).

    Raises:
        HTTPException: Si el rol no existe, es un rol del sistema,
                      tiene usuarios asignados, o hay un error al eliminarlo.
    """
    try:
        result = await RoleRepository.delete(db, role_id)
        if result.is_failure():
            error = result.failure()
            raise handle_role_error(error)
        
        await db.commit()
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar rol: {str(e)}"
        )


@router.get("/permissions/", response_model=List[PermissionResponse])
async def get_permissions(
    skip: int = Query(0, ge=0, description="Número de registros a omitir para paginación"),
    limit: int = Query(100, ge=1, le=100, description="Límite de registros a retornar"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user)
) -> List[Permission]:
    """
    Obtiene la lista de permisos con paginación.

    Args:
        skip: Número de registros a omitir (para paginación).
        limit: Límite de registros a retornar.
        db: Sesión de base de datos.
        _: Usuario actual (para verificar autenticación).

    Returns:
        List[Permission]: Lista de permisos.

    Raises:
        HTTPException: Si ocurre un error al obtener los permisos.
    """
    try:
        result = await PermissionRepository.get_all(db, skip, limit)
        if result.is_failure():
            error = result.failure()
            raise handle_error(error)
        
        return result.unwrap()
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener permisos: {str(e)}"
        )


@router.get("/{role_id}/permissions/", response_model=List[PermissionResponse])
async def get_role_permissions(
    role_id: int = Path(..., ge=1, description="ID del rol"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user)
) -> List[Permission]:
    """
    Obtiene los permisos asignados a un rol.

    Args:
        role_id: ID del rol.
        db: Sesión de base de datos.
        _: Usuario actual (para verificar autenticación).

    Returns:
        List[Permission]: Lista de permisos asignados al rol.

    Raises:
        HTTPException: Si el rol no existe o hay un error al obtener los permisos.
    """
    try:
        result = await RoleRepository.get_permissions_by_role_id(db, role_id)
        if result.is_failure():
            error = result.failure()
            raise handle_role_error(error)
        
        return result.unwrap()
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener permisos del rol: {str(e)}"
        )


@router.post("/{role_id}/permissions/", status_code=status.HTTP_200_OK)
async def add_permission_to_role(
    permission_data: RolePermissionCreate,
    role_id: int = Path(..., ge=1, description="ID del rol"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser)
) -> Dict[str, Any]:
    """
    Asigna un permiso a un rol.

    Args:
        permission_data: Datos del permiso a asignar.
        role_id: ID del rol.
        db: Sesión de base de datos.
        current_user: Usuario administrador actual (solo administradores pueden asignar permisos).

    Returns:
        Dict[str, Any]: Información sobre la asignación realizada.

    Raises:
        HTTPException: Si el rol o el permiso no existen, o hay un error al asignar el permiso.
    """
    try:
        result = await RoleRepository.assign_permission(
            db,
            role_id=role_id,
            permission_id=permission_data.permission_id,
            assigned_by=current_user.id
        )
        if result.is_failure():
            error = result.failure()
            raise handle_role_error(error)
        
        await db.commit()
        return result.unwrap()
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al asignar permiso al rol: {str(e)}"
        )


@router.delete("/{role_id}/permissions/{permission_id}", status_code=status.HTTP_204_NO_CONTENT)
async def remove_permission_from_role(
    role_id: int = Path(..., ge=1, description="ID del rol"),
    permission_id: int = Path(..., ge=1, description="ID del permiso"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_superuser)
) -> None:
    """
    Elimina un permiso de un rol.

    Args:
        role_id: ID del rol.
        permission_id: ID del permiso a eliminar.
        db: Sesión de base de datos.
        _: Usuario administrador actual (solo administradores pueden eliminar permisos).

    Raises:
        HTTPException: Si el rol o el permiso no existen, o hay un error al eliminar el permiso.
    """
    try:
        result = await RoleRepository.remove_permission(db, role_id, permission_id)
        if result.is_failure():
            error = result.failure()
            raise handle_role_error(error)
        
        await db.commit()
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar permiso del rol: {str(e)}"
        )
