"""
Endpoints para la gestión de usuarios.

Este módulo define los endpoints de la API para la gestión de usuarios,
incluida la creación, actualización, eliminación y obtención de usuarios.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query, Path, BackgroundTasks
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_active_superuser, get_current_active_user
from app.common.database import get_db
from app.common.errors import handle_error
from app.users.models import User
from app.users.errors import UserNotFoundError, UserAlreadyExistsError
from app.users import service as user_service
from app.users.schemas import (
    UserCreate, 
    UserUpdate, 
    UserInDB, 
    UserResponse, 
    UserListResponse
)

# Crear el router
router = APIRouter(prefix="/users", tags=["users"])


@router.get("/", response_model=UserListResponse)
async def get_users(
    skip: int = Query(0, ge=0, description="Número de registros a omitir para paginación"),
    limit: int = Query(100, ge=1, le=100, description="Límite de registros a retornar"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user)
) -> UserListResponse:
    """
    Obtiene la lista de usuarios con paginación.

    Args:
        skip: Número de registros a omitir (para paginación).
        limit: Límite de registros a retornar.
        db: Sesión de base de datos.
        _: Usuario actual (para verificar autenticación).

    Returns:
        UserListResponse: Respuesta con lista paginada de usuarios.

    Raises:
        HTTPException: Si ocurre un error al obtener los usuarios.
    """
    try:
        result = await user_service.get_users(db, skip=skip, limit=limit)
        if result.is_failure():
            error = result.failure()
            raise handle_error(error)
        
        users_in_db = result.unwrap()
        total = len(users_in_db)  # En una implementación real debería ser una consulta COUNT
        
        # Convertir los objetos User a diccionarios para la respuesta
        user_data: list[dict[str, Any]] = []
        for user_model in users_in_db:
            user_dict: dict[str, Any] = {
                "id": user_model.id,
                "email": user_model.email,
                "full_name": user_model.first_name + " " + user_model.last_name if user_model.first_name and user_model.last_name else None,
                "is_active": user_model.is_active,
                "is_superuser": user_model.is_superuser,
                "is_verified": user_model.is_verified,
                "created_at": user_model.created_at,
                "updated_at": user_model.updated_at
            }
            user_data.append(user_dict)
        
        # Ensure pagination is a dict[str, Any]
        pagination_data: dict[str, Any] = {
            "total": total,
            "page": skip // limit + 1,
            "size": limit,
            "pages": (total + limit - 1) // limit  # Redondeo hacia arriba
        }

        return UserListResponse(
            success=True,
            message="Usuarios obtenidos exitosamente",
            data=user_data,
            pagination=pagination_data
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener usuarios: {str(e)}"
        )


@router.get("/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int = Path(..., ge=1, description="ID del usuario a obtener"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_active_user)
) -> UserResponse:
    """
    Obtiene un usuario por su ID.

    Args:
        user_id: ID del usuario a obtener.
        db: Sesión de base de datos.
        _: Usuario actual (para verificar autenticación).

    Returns:
        UserResponse: Respuesta con los datos del usuario.

    Raises:
        HTTPException: Si el usuario no existe o hay un error al obtenerlo.
    """
    try:
        result = await user_service.get_user_by_id(db, user_id)
        if result.is_failure():
            error = result.failure()
            if isinstance(error, UserNotFoundError):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Usuario con ID {user_id} no encontrado"
                )
            raise handle_error(error)
        
        user_model = result.unwrap()
        
        # Convertir el objeto User a diccionario para la respuesta
        user_data_dict: dict[str, Any] = {
            "id": user_model.id,
            "email": user_model.email,
            "full_name": user_model.first_name + " " + user_model.last_name if user_model.first_name and user_model.last_name else None,
            "is_active": user_model.is_active,
            "is_superuser": user_model.is_superuser,
            "is_verified": user_model.is_verified,
            "created_at": user_model.created_at,
            "updated_at": user_model.updated_at
        }
        
        return UserResponse(
            success=True,
            message="Usuario obtenido exitosamente",
            data=user_data_dict
        )
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener usuario: {str(e)}"
        )


@router.post("/", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser)
) -> UserResponse:
    """
    Crea un nuevo usuario.

    Args:
        user_data: Datos del usuario a crear.
        background_tasks: Tareas en segundo plano para enviar email de verificación.
        db: Sesión de base de datos.
        current_user: Usuario administrador actual (solo administradores pueden crear usuarios).

    Returns:
        UserResponse: Respuesta con los datos del usuario creado.

    Raises:
        HTTPException: Si ya existe un usuario con el mismo email o hay un error al crearlo.
    """
    try:
        # Adaptar UserCreate a la estructura esperada por la aplicación
        # La aplicación espera first_name y last_name separados, pero UserCreate tiene full_name
        # first_name: Optional[str] = None
        # last_name: Optional[str] = None
        # if user_data.full_name:
        #     name_parts = user_data.full_name.split(" ", 1)
        #     first_name = name_parts[0]
        #     last_name = name_parts[1] if len(name_parts) > 1 else ""
        
        # Crear el usuario
        # user_to_create = UserCreate(
        #     email=user_data.email,
        #     password=user_data.password,
        #     is_active=user_data.is_active,
        #     is_superuser=user_data.is_superuser,
        #     is_verified=user_data.is_verified,
        #     full_name=user_data.full_name
        # )
        # The user_data already is of type UserCreate, direct pass to service
        
        result = await user_service.create_user(db, user_data) # Pass user_data directly
        if result.is_failure():
            error = result.failure()
            if isinstance(error, UserAlreadyExistsError):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Ya existe un usuario con el email {user_data.email}"
                )
            raise handle_error(error)
        
        created_user_model = result.unwrap()
        
        # Si el usuario no está verificado, enviar email de verificación
        if not created_user_model.is_verified:
            # Aquí podríamos agregar la tarea en segundo plano para enviar el email
            # background_tasks.add_task(send_verification_email, db, created_user_model.email)
            pass
        
        # Convertir el objeto User a diccionario para la respuesta
        user_data_dict: dict[str, Any] = {
            "id": created_user_model.id,
            "email": created_user_model.email,
            "full_name": created_user_model.first_name + " " + created_user_model.last_name if created_user_model.first_name and created_user_model.last_name else None,
            "is_active": created_user_model.is_active,
            "is_superuser": created_user_model.is_superuser,
            "is_verified": created_user_model.is_verified,
            "created_at": created_user_model.created_at,
            "updated_at": created_user_model.updated_at
        }
        
        return UserResponse(
            success=True,
            message="Usuario creado exitosamente",
            data=user_data_dict
        )
    except HTTPException:
        raise
    except IntegrityError as e:
        await db.rollback()
        if "unique constraint" in str(e).lower() and "email" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ya existe un usuario con el email {user_data.email}"
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error de integridad al crear usuario: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al crear usuario: {str(e)}"
        )


@router.put("/{user_id}", response_model=UserResponse)
async def update_user(
    user_data: UserUpdate,
    user_id: int = Path(..., ge=1, description="ID del usuario a actualizar"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser)
) -> UserResponse:
    """
    Actualiza un usuario existente.

    Args:
        user_data: Datos para actualizar el usuario.
        user_id: ID del usuario a actualizar.
        db: Sesión de base de datos.
        current_user: Usuario administrador actual (solo administradores pueden actualizar usuarios).

    Returns:
        UserResponse: Respuesta con los datos del usuario actualizado.

    Raises:
        HTTPException: Si el usuario no existe, el email ya está en uso, o hay un error al actualizarlo.
    """
    try:
        # Adaptar UserUpdate a la estructura esperada por la aplicación (si es necesario)
        # En este caso, UserUpdate ya tiene la estructura correcta para el servicio
        # first_name: Optional[str] = None
        # last_name: Optional[str] = None
        # if user_data.full_name is not None:
        #     name_parts = user_data.full_name.split(" ", 1)
        #     first_name = name_parts[0]
        #     last_name = name_parts[1] if len(name_parts) > 1 else ""
        
        # Preparar UserUpdate para el servicio - user_data ya es del tipo correcto
        # update_payload = UserUpdate(
        #     email=user_data.email,
        #     password=user_data.password,
        #     is_active=user_data.is_active,
        #     is_verified=user_data.is_verified,
        #     full_name=user_data.full_name
        # )
        
        result = await user_service.update_user(db, user_id, user_data) # Pass user_data directly
        if result.is_failure():
            error = result.failure()
            if isinstance(error, UserNotFoundError):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Usuario con ID {user_id} no encontrado"
                )
            elif isinstance(error, UserAlreadyExistsError):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Ya existe un usuario con el email {user_data.email}"
                )
            raise handle_error(error)
        
        updated_user_model = result.unwrap()
        
        # Convertir el objeto User a diccionario para la respuesta
        user_data_dict: dict[str, Any] = {
            "id": updated_user_model.id,
            "email": updated_user_model.email,
            "full_name": updated_user_model.first_name + " " + updated_user_model.last_name if updated_user_model.first_name and updated_user_model.last_name else None,
            "is_active": updated_user_model.is_active,
            "is_superuser": updated_user_model.is_superuser,
            "is_verified": updated_user_model.is_verified,
            "created_at": updated_user_model.created_at,
            "updated_at": updated_user_model.updated_at
        }
        
        return UserResponse(
            success=True,
            message="Usuario actualizado exitosamente",
            data=user_data_dict
        )
    except HTTPException:
        raise
    except IntegrityError as e:
        await db.rollback()
        if "unique constraint" in str(e).lower() and "email" in str(e).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ya existe un usuario con el email {user_data.email if user_data.email else ''}"
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error de integridad al actualizar usuario: {str(e)}"
        )
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al actualizar usuario: {str(e)}"
        )


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    user_id: int = Path(..., ge=1, description="ID del usuario a eliminar"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_active_superuser)
) -> None:
    """
    Elimina un usuario existente.

    Args:
        user_id: ID del usuario a eliminar.
        db: Sesión de base de datos.
        current_user: Usuario administrador actual (solo administradores pueden eliminar usuarios).

    Raises:
        HTTPException: Si el usuario no existe o hay un error al eliminarlo.
    """
    try:
        # Validar que no se esté intentando eliminar al propio usuario
        if user_id == current_user.id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No puede eliminar su propio usuario"
            )
        
        result = await user_service.delete_user(db, user_id)
        if result.is_failure():
            error = result.failure()
            if isinstance(error, UserNotFoundError):
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"Usuario con ID {user_id} no encontrado"
                )
            raise handle_error(error)
        
        await db.commit()
    except HTTPException:
        raise
    except Exception as e:
        await db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al eliminar usuario: {str(e)}"
        )


@router.get("/me/", response_model=UserResponse)
async def read_user_me(
    current_user: User = Depends(get_current_active_user)
) -> UserResponse:
    """
    Obtiene los datos del usuario autenticado.

    Args:
        current_user: Usuario actualmente autenticado.

    Returns:
        UserResponse: Respuesta con los datos del usuario autenticado.
    """
    try:
        # Convertir el objeto User a diccionario para la respuesta
        user_data_dict: dict[str, Any] = {
            "id": current_user.id,
            "email": current_user.email,
            "full_name": current_user.first_name + " " + current_user.last_name if current_user.first_name and current_user.last_name else None,
            "is_active": current_user.is_active,
            "is_superuser": current_user.is_superuser,
            "is_verified": current_user.is_verified,
            "created_at": current_user.created_at,
            "updated_at": current_user.updated_at
        }
        
        return UserResponse(
            success=True,
            message="Datos del usuario autenticado obtenidos exitosamente",
            data=user_data_dict
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al obtener datos del usuario autenticado: {str(e)}"
        )
