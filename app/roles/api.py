"""
Módulo de rutas de la API para la gestión de roles y permisos.

Este módulo define los endpoints para la gestión de roles, permisos
y la asignación de permisos a roles.
"""
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.dependencies import get_current_active_user, get_current_active_superuser
from app.common.database import get_db
from app.common.errors import ResourceNotFoundError, DatabaseError
from sqlalchemy.ext.asyncio import AsyncSession

from . import schemas, service
from .models import Role, Permission, RolePermission
from .schemas import (
    RoleCreate, 
    RoleUpdate, 
    RoleResponse, 
    PermissionResponse,
    RolePermissionCreate,
    RolePermissionResponse
)

router = APIRouter()

# Rutas para roles
@router.post(
    "/",
    response_model=RoleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un nuevo rol",
    description="Crea un nuevo rol en el sistema (requiere permisos de superusuario).",
)
async def create_role(
    role_data: RoleCreate,
    current_user: schemas.User = Depends(get_current_active_superuser),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """
    Crea un nuevo rol.
    
    Args:
        role_data: Datos del rol a crear.
        current_user: Usuario autenticado (debe ser superusuario).
        db: Sesión de base de datos.
        
    Returns:
        El rol creado con su ID asignado.
    """
    try:
        return await service.create_role(db, role_data)
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el rol.",
        )

@router.get(
    "/",
    response_model=List[RoleResponse],
    summary="Listar roles",
    description="Obtiene una lista de todos los roles del sistema.",
)
async def list_roles(
    skip: int = 0,
    limit: int = 100,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> List[RoleResponse]:
    """
    Obtiene una lista de roles con paginación.
    
    Args:
        skip: Número de registros a omitir (para paginación).
        limit: Número máximo de registros a devolver.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Lista de roles.
    """
    return await service.get_roles(db, skip=skip, limit=limit)

@router.get(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Obtener un rol",
    description="Obtiene los detalles de un rol específico por su ID.",
)
async def get_role(
    role_id: int,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """
    Obtiene un rol por su ID.
    
    Args:
        role_id: ID del rol a obtener.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Los detalles del rol solicitado.
        
    Raises:
        HTTPException: Si el rol no se encuentra.
    """
    try:
        role = await service.get_role_by_id(db, role_id)
        return role
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

@router.put(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Actualizar un rol",
    description="Actualiza los datos de un rol existente (requiere permisos de superusuario).",
)
async def update_role(
    role_id: int,
    role_data: RoleUpdate,
    current_user: schemas.User = Depends(get_current_active_superuser),
    db: AsyncSession = Depends(get_db),
) -> RoleResponse:
    """
    Actualiza un rol existente.
    
    Args:
        role_id: ID del rol a actualizar.
        role_data: Datos actualizados del rol.
        current_user: Usuario autenticado (debe ser superusuario).
        db: Sesión de base de datos.
        
    Returns:
        El rol actualizado.
        
    Raises:
        HTTPException: Si el rol no se encuentra o hay un error en la actualización.
    """
    try:
        return await service.update_role(db, role_id, role_data)
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar el rol.",
        )

@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un rol",
    description="Elimina un rol del sistema (requiere permisos de superusuario).",
)
async def delete_role(
    role_id: int,
    current_user: schemas.User = Depends(get_current_active_superuser),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Elimina un rol.
    
    Args:
        role_id: ID del rol a eliminar.
        current_user: Usuario autenticado (debe ser superusuario).
        db: Sesión de base de datos.
        
    Raises:
        HTTPException: Si el rol no se encuentra o hay un error al eliminarlo.
    """
    try:
        await service.delete_role(db, role_id)
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el rol.",
        )

# Rutas para permisos
@router.get(
    "/permissions/",
    response_model=List[PermissionResponse],
    summary="Listar permisos",
    description="Obtiene una lista de todos los permisos del sistema.",
)
async def list_permissions(
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> List[PermissionResponse]:
    """
    Obtiene una lista de permisos.
    
    Args:
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Lista de permisos.
    """
    return await service.get_permissions(db)

# Rutas para asignación de permisos a roles
@router.post(
    "/{role_id}/permissions/",
    response_model=RolePermissionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Asignar permiso a rol",
    description="Asigna un permiso a un rol (requiere permisos de superusuario).",
)
async def add_permission_to_role(
    role_id: int,
    permission_data: RolePermissionCreate,
    current_user: schemas.User = Depends(get_current_active_superuser),
    db: AsyncSession = Depends(get_db),
) -> RolePermissionResponse:
    """
    Asigna un permiso a un rol.
    
    Args:
        role_id: ID del rol al que se asignará el permiso.
        permission_data: Datos del permiso a asignar.
        current_user: Usuario autenticado (debe ser superusuario).
        db: Sesión de base de datos.
        
    Returns:
        La asignación de permiso creada.
        
    Raises:
        HTTPException: Si el rol o el permiso no existen, o si ya están asignados.
    """
    try:
        return await service.add_permission_to_role(
            db, role_id, permission_data.permission_id
        )
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        if "duplicate key" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El permiso ya está asignado a este rol.",
            )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al asignar el permiso al rol.",
        )

@router.delete(
    "/{role_id}/permissions/{permission_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar permiso de rol",
    description="Elimina un permiso de un rol (requiere permisos de superusuario).",
)
async def remove_permission_from_role(
    role_id: int,
    permission_id: int,
    current_user: schemas.User = Depends(get_current_active_superuser),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Elimina un permiso de un rol.
    
    Args:
        role_id: ID del rol del que se eliminará el permiso.
        permission_id: ID del permiso a eliminar.
        current_user: Usuario autenticado (debe ser superusuario).
        db: Sesión de base de datos.
        
    Raises:
        HTTPException: Si el rol, el permiso o la asignación no existen.
    """
    try:
        await service.remove_permission_from_role(
            db, role_id, permission_id
        )
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el permiso del rol.",
        )

@router.get(
    "/{role_id}/permissions/",
    response_model=List[PermissionResponse],
    summary="Obtener permisos de un rol",
    description="Obtiene la lista de permisos asignados a un rol específico.",
)
async def get_role_permissions(
    role_id: int,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> List[PermissionResponse]:
    """
    Obtiene los permisos asignados a un rol.
    
    Args:
        role_id: ID del rol del que se obtendrán los permisos.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Lista de permisos asignados al rol.
        
    Raises:
        HTTPException: Si el rol no existe.
    """
    try:
        return await service.get_role_permissions(db, role_id)
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
