"""
Módulo de rutas de la API para la gestión de roles y permisos.

Este módulo define los endpoints para la gestión de roles, permisos
y la asignación de permisos a roles.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_active_superuser, get_current_active_user
from app.common.database import get_db
from app.common.errors import DatabaseError, ResourceNotFoundError
from app.users import schemas as user_schemas # Importar esquemas de usuario

from . import schemas, service
from .models import Permission, Role
from .schemas import (
    PermissionResponse,
    RoleCreate,
    RolePermissionCreate,
    RolePermissionResponse,
    RoleResponse,
    RoleUpdate,
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
    current_user: user_schemas.UserResponse = Depends(get_current_active_superuser),
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
        db_role = await service.create_role(db, role_data)
        # Asumiendo que create_role no devuelve None y si falla lanza excepción.
        return RoleResponse.model_validate(db_role)
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el rol.",
        )
    except Exception as e: # Captura general para errores inesperados del servicio
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al crear el rol: {e}",
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
    current_user: user_schemas.UserResponse = Depends(get_current_active_user),
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
    try:
        db_roles = await service.get_roles(db, skip=skip, limit=limit)
        return [RoleResponse.model_validate(role) for role in db_roles]
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al listar roles.",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al listar roles: {e}",
        )


@router.get(
    "/{role_id}",
    response_model=RoleResponse,
    summary="Obtener un rol",
    description="Obtiene los detalles de un rol específico por su ID.",
)
async def get_role(
    role_id: int,
    current_user: user_schemas.UserResponse = Depends(get_current_active_user),
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
        db_role = await service.get_role_by_id(db, role_id=role_id)
        if db_role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Rol no encontrado"
            )
        return RoleResponse.model_validate(db_role)
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except ResourceNotFoundError as e: # Si el servicio lanza esto explícitamente
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al obtener el rol.",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al obtener el rol: {e}",
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
    current_user: user_schemas.UserResponse = Depends(get_current_active_superuser),
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
        updated_db_role = await service.update_role(
            db, role_id=role_id, role_data=role_data
        )
        if updated_db_role is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Rol no encontrado para actualizar"
            )
        return RoleResponse.model_validate(updated_db_role)
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except ResourceNotFoundError as e: # Si el servicio lanza esto explícitamente
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar el rol.",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al actualizar el rol: {e}",
        )


@router.delete(
    "/{role_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un rol",
    description="Elimina un rol del sistema (requiere permisos de superusuario).",
)
async def delete_role(
    role_id: int,
    current_user: user_schemas.UserResponse = Depends(get_current_active_superuser),
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
        deleted_role = await service.delete_role(db, role_id=role_id)
        if deleted_role is None:
             # Si el servicio devuelve None cuando no encuentra el rol para eliminar
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rol no encontrado para eliminar")
        # No hay contenido de respuesta para una eliminación exitosa (204)
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except ResourceNotFoundError as e: # Si el servicio lanza esto explícitamente
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el rol.",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al eliminar el rol: {e}",
        )


# Rutas para permisos
@router.get(
    "/permissions/",
    response_model=List[PermissionResponse],
    summary="Listar permisos",
    description="Obtiene una lista de todos los permisos del sistema.",
)
async def list_permissions(
    current_user: user_schemas.UserResponse = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> List[PermissionResponse]:
    """
    Obtiene una lista de todos los permisos del sistema.

    Args:
        current_user: Usuario autenticado.
        db: Sesión de base de datos.

    Returns:
        Lista de permisos.
    """
    try:
        db_permissions = await service.get_permissions(db)
        return [PermissionResponse.model_validate(perm) for perm in db_permissions]
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al listar permisos.",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al listar permisos: {e}",
        )


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
    current_user: user_schemas.UserResponse = Depends(get_current_active_superuser),
    db: AsyncSession = Depends(get_db),
) -> RolePermissionResponse:
    """
    Asigna un permiso a un rol.

    Args:
        role_id: ID del rol al que se asignará el permiso.
        permission_data: Datos del permiso a asignar (contiene permission_id).
        current_user: Usuario autenticado (debe ser superusuario).
        db: Sesión de base de datos.

    Returns:
        La asignación de permiso creada.

    Raises:
        HTTPException: Si el rol o el permiso no existen, o si ya están asignados.
    """
    try:
        updated_role_or_none = await service.add_permission_to_role(
            db, role_id=role_id, permission_id=permission_data.permission_id
        )
        if updated_role_or_none is None:
            # Esto podría significar que el rol o permiso no se encontró, o la asignación falló.
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rol o Permiso no encontrado, o fallo al asignar.")
        
        # El servicio devuelve el Role actualizado (updated_role_or_none).
        # Necesitamos role_id (de updated_role_or_none.id) y permission_id (de permission_data.permission_id).
        # assigned_at no está en nuestra tabla de asociación, por lo que será None por defecto en RolePermissionResponse.
        return RolePermissionResponse(
            role_id=updated_role_or_none.id,
            permission_id=permission_data.permission_id,
            assigned_at=None # Explicitly pass None to satisfy MyPy
        )

    except NotImplementedError: # Si el servicio subyacente aún no está implementado (ya no debería ser el caso)
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función de servicio no implementada")
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DatabaseError as e: 
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Error de base de datos al asignar permiso al rol: {e}",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al asignar permiso: {e}",
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
    current_user: user_schemas.UserResponse = Depends(get_current_active_superuser),
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
        updated_role = await service.remove_permission_from_role(
            db, role_id=role_id, permission_id=permission_id
        )
        if updated_role is None:
            # Si el servicio devuelve None cuando no encuentra la entidad para eliminar/actualizar
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rol, Permiso o asignación no encontrada para eliminar")
        # No hay contenido de respuesta para una eliminación exitosa (204)
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except ResourceNotFoundError as e: # Si el servicio lanza esto explícitamente
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar permiso del rol.",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al eliminar permiso: {e}",
        )


@router.get(
    "/{role_id}/permissions/",
    response_model=List[PermissionResponse],
    summary="Obtener permisos de un rol",
    description="Obtiene la lista de permisos asignados a un rol específico.",
)
async def get_role_permissions(
    role_id: int,
    current_user: user_schemas.UserResponse = Depends(get_current_active_user),
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
        # Primero, verificar si el rol existe
        db_role_check = await service.get_role_by_id(db, role_id=role_id)
        if db_role_check is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail=f"Rol con id {role_id} no encontrado"
            )
        
        # Luego, obtener los permisos para ese rol
        db_permissions = await service.get_role_permissions(db, role_id=role_id)
        return [PermissionResponse.model_validate(p) for p in db_permissions]
    except NotImplementedError: # Específico para stubs
        raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED, detail="Función no implementada")
    except ResourceNotFoundError as e: # Si get_role_by_id lanza esto
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al obtener los permisos del rol.",
        )
    except Exception as e: # Captura general
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado al obtener permisos del rol: {e}",
        )
