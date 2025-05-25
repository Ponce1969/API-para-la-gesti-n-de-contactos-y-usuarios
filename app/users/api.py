"""
Módulo de rutas de la API para la gestión de usuarios.

Este módulo define los endpoints para operaciones CRUD de usuarios,
incluyendo creación, lectura, actualización y desactivación de cuentas.
"""

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.database import get_db
from app.common.errors import DatabaseError, ResourceNotFoundError

from . import schemas
from .service import UserService
from .repository import UserRepository
from .errors import UserAlreadyExistsError, UserNotFoundError, VerificationTokenNotFoundError, TokenInvalidError
# from .models import User # Models are typically handled by service/repository layers

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
    Crea un nuevo usuario en el sistema y gestiona la creación de un token de verificación.

    Args:
        user_data: Datos del usuario a crear.
        db: Sesión de base de datos.

    Returns:
        El usuario creado con su ID asignado.

    Raises:
        HTTPException: Si el email ya está registrado o hay un error.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)
    
    result = await user_service.register_new_user(user_data)
    
    if result.is_failure():
        error = result.error()
        if isinstance(error, UserAlreadyExistsError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=str(error),
            )
        elif isinstance(error, DatabaseError):
            # Log error internally for more details if needed
            # logger.error(f"Database error during user registration: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error en la base de datos al procesar el registro.",
            )
        else:
            # Log error internally for more details if needed
            # logger.error(f"Unexpected error during user registration: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error inesperado al procesar el registro.",
            )
    
    created_user_in_db = result.value
    return schemas.UserResponse.model_validate(created_user_in_db)


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
        HTTPException: Si el usuario no se encuentra o hay un error de base de datos.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)

    result = await user_service.get_user_by_id(user_id)

    if result.is_failure():
        error = result.error()
        if isinstance(error, UserNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(error),
            )
        elif isinstance(error, DatabaseError):
            # logger.error(f"Database error al obtener usuario {user_id}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error en la base de datos al obtener el usuario.",
            )
        else:
            # logger.error(f"Error inesperado al obtener usuario {user_id}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error inesperado al obtener el usuario.",
            )

    user_in_db = result.value
    return schemas.UserResponse.model_validate(user_in_db)


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

    Raises:
        HTTPException: Si hay un error de base de datos.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)

    result = await user_service.get_users_list(skip=skip, limit=limit)

    if result.is_failure():
        error = result.error() # Debería ser DatabaseError
        # logger.error(f"Database error al listar usuarios: {error}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error en la base de datos al listar usuarios.",
        )

    users_in_db_list = result.value
    return [schemas.UserResponse.model_validate(user) for user in users_in_db_list]


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
        HTTPException: Si el usuario no se encuentra, el email ya existe, o hay un error de base de datos.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)

    result = await user_service.update_existing_user(user_id=user_id, user_update_data=user_data)

    if result.is_failure():
        error = result.error()
        if isinstance(error, UserNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(error),
            )
        elif isinstance(error, UserAlreadyExistsError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT, # Email conflict
                detail=str(error),
            )
        elif isinstance(error, DatabaseError):
            # logger.error(f"Database error al actualizar usuario {user_id}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error en la base de datos al actualizar el usuario.",
            )
        else:
            # logger.error(f"Error inesperado al actualizar usuario {user_id}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error inesperado al actualizar el usuario.",
            )

    updated_user_in_db = result.value
    return schemas.UserResponse.model_validate(updated_user_in_db)


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
    Elimina un usuario (borrado lógico o físico según la implementación del repositorio).

    Args:
        user_id: ID del usuario a eliminar.
        db: Sesión de base de datos.

    Raises:
        HTTPException: Si el usuario no se encuentra o hay un error al eliminarlo.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)

    result = await user_service.delete_user_by_id(user_id=user_id)

    if result.is_failure():
        error = result.error()
        if isinstance(error, UserNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=str(error),
            )
        elif isinstance(error, DatabaseError):
            # logger.error(f"Database error al eliminar usuario {user_id}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error en la base de datos al eliminar el usuario.",
            )
        else:
            # logger.error(f"Error inesperado al eliminar usuario {user_id}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error inesperado al eliminar el usuario.",
            )
    
    # Si llegamos aquí, la operación fue exitosa y no se devuelve contenido.
    return


@router.get(
    "/verify-email/",
    response_model=schemas.UserResponse,
    summary="Verificar dirección de correo electrónico",
    description="Verifica la dirección de correo electrónico de un usuario utilizando un token. "
                "El token se espera como un parámetro de consulta (?token=valor_del_token).",
    tags=["auth", "users"], # Añadir tags para agrupar en la documentación de la API
)
async def verify_email_with_token(
    token: str, # FastAPI obtendrá esto de los parámetros de consulta
    db: AsyncSession = Depends(get_db),
) -> schemas.UserResponse:
    """
    Verifica el correo electrónico de un usuario usando un token.

    Args:
        token: El token de verificación.
        db: Sesión de base de datos.

    Returns:
        Los detalles del usuario actualizado si el token es válido y la verificación es exitosa.

    Raises:
        HTTPException: Si el token es inválido, no se encuentra, o hay un error de base de datos.
    """
    user_repo = UserRepository(db)
    user_service = UserService(user_repo)

    # El tipo de token esperado para la verificación de email
    expected_token_type = "email_verification"

    result = await user_service.use_verification_token(
        token_value=token,
        expected_token_type=expected_token_type
    )

    if result.is_failure():
        error = result.error()
        if isinstance(error, VerificationTokenNotFoundError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Token de verificación no encontrado o ya utilizado.", # Mensaje genérico por seguridad
            )
        elif isinstance(error, TokenInvalidError):
            # Podríamos loguear error.reason internamente para más detalles
            # logger.warning(f"Intento de uso de token inválido: {token}. Razón: {error.reason}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Token inválido o expirado.", # Mensaje genérico por seguridad
            )
        elif isinstance(error, UserNotFoundError):
            # Este caso es menos probable si el token es válido y está correctamente vinculado.
            # logger.error(f"Usuario no encontrado para un token supuestamente válido: {token}")
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario asociado al token no encontrado.",
            )
        elif isinstance(error, DatabaseError):
            # logger.error(f"Error de base de datos al verificar token {token}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error interno del servidor al procesar el token.",
            )
        else: # Captura genérica para otros AppError
            # logger.error(f"Error inesperado al verificar token {token}: {error}", exc_info=True)
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error inesperado al procesar la verificación.",
            )
    
    updated_user_in_db = result.value
    return schemas.UserResponse.model_validate(updated_user_in_db)

