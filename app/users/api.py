"""
Módulo de rutas de la API para la gestión de usuarios.

Este módulo define los endpoints para operaciones CRUD de usuarios,
incluyendo creación, lectura, actualización y desactivación de cuentas.
"""
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status

from app.common.database import get_db
from app.common.errors import ResourceNotFoundError, DatabaseError
from sqlalchemy.ext.asyncio import AsyncSession

from . import schemas, service
from .models import User
from .errors import UserNotFoundError, EmailAlreadyExistsError

router = APIRouter()

@router.post(
    "/",
    response_model=schemas.UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un nuevo usuario",
    description="Crea un nuevo usuario en el sistema con los datos proporcionados.",
)
async def create_user(
    user_data: schemas.UserCreate,
    db: AsyncSession = Depends(get_db),
) -> schemas.UserResponse:
    """
    Crea un nuevo usuario en el sistema.
    
    Args:
        user_data: Datos del usuario a crear.
        db: Sesión de base de datos.
        
    Returns:
        El usuario creado con su ID asignado.
        
    Raises:
        HTTPException: Si el email ya está registrado o hay un error en la base de datos.
    """
    try:
        created_user = await service.create_user(db, user_data)
        return created_user
    except EmailAlreadyExistsError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el usuario en la base de datos.",
        )

@router.get(
    "/{user_id}",
    response_model=schemas.UserResponse,
    summary="Obtener un usuario por ID",
    description="Obtiene los detalles de un usuario específico por su ID.",
)
async def get_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
) -> schemas.UserResponse:
    """
    Obtiene un usuario por su ID.
    
    Args:
        user_id: ID del usuario a obtener.
        db: Sesión de base de datos.
        
    Returns:
        Los detalles del usuario solicitado.
        
    Raises:
        HTTPException: Si el usuario no se encuentra.
    """
    try:
        user = await service.get_user_by_id(db, user_id)
        return user
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

@router.get(
    "/",
    response_model=List[schemas.UserResponse],
    summary="Listar usuarios",
    description="Obtiene una lista paginada de todos los usuarios registrados.",
)
async def list_users(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
) -> List[schemas.UserResponse]:
    """
    Obtiene una lista de usuarios con paginación.
    
    Args:
        skip: Número de registros a omitir (para paginación).
        limit: Número máximo de registros a devolver.
        db: Sesión de base de datos.
        
    Returns:
        Lista de usuarios.
    """
    users = await service.get_users(db, skip=skip, limit=limit)
    return users

@router.put(
    "/{user_id}",
    response_model=schemas.UserResponse,
    summary="Actualizar un usuario",
    description="Actualiza los datos de un usuario existente.",
)
async def update_user(
    user_id: int,
    user_data: schemas.UserUpdate,
    db: AsyncSession = Depends(get_db),
) -> schemas.UserResponse:
    """
    Actualiza los datos de un usuario.
    
    Args:
        user_id: ID del usuario a actualizar.
        user_data: Datos actualizados del usuario.
        db: Sesión de base de datos.
        
    Returns:
        El usuario actualizado.
        
    Raises:
        HTTPException: Si el usuario no se encuentra o hay un error en la actualización.
    """
    try:
        updated_user = await service.update_user(db, user_id, user_data)
        return updated_user
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar el usuario en la base de datos.",
        )

@router.delete(
    "/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un usuario",
    description="Elimina un usuario del sistema (borrado lógico).",
)
async def delete_user(
    user_id: int,
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Elimina un usuario (borrado lógico).
    
    Args:
        user_id: ID del usuario a eliminar.
        db: Sesión de base de datos.
        
    Raises:
        HTTPException: Si el usuario no se encuentra o hay un error al eliminarlo.
    """
    try:
        await service.delete_user(db, user_id)
    except UserNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el usuario de la base de datos.",
        )
