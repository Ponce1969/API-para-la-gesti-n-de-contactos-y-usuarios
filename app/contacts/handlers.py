"""
Controladores para endpoints de la API de gestión de contactos.

Este módulo define los manejadores para las operaciones HTTP
relacionadas con contactos y grupos de contactos.
"""

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth.dependencies import get_current_active_user
from app.common.database import get_db
from app.common.result import is_failure
from app.common.schemas import PaginationParams
from app.contacts.errors import (
    ContactAlreadyExistsError,
    ContactAlreadyInGroupError,
    ContactGroupAlreadyExistsError,
    ContactGroupNotFoundError,
    ContactGroupValidationError,
    ContactNotFoundError,
    ContactNotInGroupError,
    ContactValidationError,
    UnauthorizedContactAccessError,
    UnauthorizedGroupAccessError,
)
from app.contacts.schemas import (
    ContactCreate,
    ContactGroupCreate,
    ContactGroupListResponse,
    ContactGroupResponse,
    ContactGroupUpdate,
    ContactListResponse,
    ContactResponse,
    ContactUpdate,
)
from app.contacts.service import ContactGroupService, ContactService
from app.users.models import User

# Crear el router
router = APIRouter()


# Rutas para contactos
@router.post(
    "/",
    response_model=ContactResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un nuevo contacto",
    description="Crea un nuevo contacto para el usuario autenticado.",
)
async def create_contact(
    contact_data: ContactCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactResponse:
    """
    Crea un nuevo contacto para el usuario autenticado.

    Args:
        contact_data: Datos del contacto a crear.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        El contacto creado.

    Raises:
        HTTPException: Si ocurre un error al crear el contacto.
    """
    result = await ContactService.create_contact(db, current_user.id, contact_data)

    if is_failure(result):
        error = result.failure()
        if isinstance(error, ContactAlreadyExistsError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ya existe un contacto con el email {error.email}",
            )
        elif isinstance(error, ContactValidationError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error de validación: {error.errors}",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al crear el contacto",
            )

    return ContactResponse.model_validate(result.unwrap())


@router.get(
    "/",
    response_model=ContactListResponse,
    summary="Listar contactos",
    description="Obtiene una lista paginada de contactos del usuario autenticado.",
)
async def list_contacts(
    pagination: PaginationParams = Depends(),
    search: str | None = Query(None, description="Término de búsqueda"),
    group_id: int | None = Query(
        None, description="ID del grupo para filtrar contactos"
    ),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactListResponse:
    """
    Obtiene una lista paginada de contactos del usuario autenticado.

    Args:
        pagination: Parámetros de paginación.
        search: Término de búsqueda opcional.
        group_id: ID del grupo para filtrar contactos (opcional).
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        Lista paginada de contactos.

    Raises:
        HTTPException: Si ocurre un error al listar los contactos.
    """
    result = await ContactService.list_contacts(
        db,
        current_user.id,
        skip=pagination.skip,
        limit=pagination.limit,
        search=search,
        group_id=group_id,
    )

    if is_failure(result):
        error = result.failure()
        if isinstance(error, (ContactGroupNotFoundError, UnauthorizedGroupAccessError)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Grupo no encontrado o no tienes permisos para acceder a él",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al listar los contactos",
            )

    contacts = result.unwrap()

    return ContactListResponse(
        items=[ContactResponse.model_validate(contact) for contact in contacts],
        total=len(contacts),
        page=pagination.page,
        size=pagination.limit,
    )


@router.get(
    "/{contact_id}",
    response_model=ContactResponse,
    summary="Obtener un contacto",
    description="Obtiene los detalles de un contacto específico por su ID.",
)
async def get_contact(
    contact_id: int = Path(..., description="ID del contacto a obtener"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactResponse:
    """
    Obtiene los detalles de un contacto específico por su ID.

    Args:
        contact_id: ID del contacto a obtener.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        El contacto solicitado.

    Raises:
        HTTPException: Si el contacto no existe o no pertenece al usuario.
    """
    result = await ContactService.get_contact_by_id(db, contact_id, current_user.id)

    if is_failure(result):
        error = result.failure()
        if isinstance(error, (ContactNotFoundError, UnauthorizedContactAccessError)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contacto no encontrado o no tienes permisos para acceder a él",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al obtener el contacto",
            )

    return ContactResponse.model_validate(result.unwrap())


@router.put(
    "/{contact_id}",
    response_model=ContactResponse,
    summary="Actualizar un contacto",
    description="Actualiza los detalles de un contacto existente.",
)
async def update_contact(
    contact_data: ContactUpdate,
    contact_id: int = Path(..., description="ID del contacto a actualizar"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactResponse:
    """
    Actualiza los detalles de un contacto existente.

    Args:
        contact_data: Datos actualizados del contacto.
        contact_id: ID del contacto a actualizar.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        El contacto actualizado.

    Raises:
        HTTPException: Si el contacto no existe, no pertenece al usuario o hay conflictos.
    """
    result = await ContactService.update_contact(
        db, contact_id, current_user.id, contact_data
    )

    if is_failure(result):
        error = result.failure()
        if isinstance(error, (ContactNotFoundError, UnauthorizedContactAccessError)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contacto no encontrado o no tienes permisos para acceder a él",
            )
        elif isinstance(error, ContactAlreadyExistsError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ya existe un contacto con el email {error.email}",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al actualizar el contacto",
            )

    return ContactResponse.model_validate(result.unwrap())


@router.delete(
    "/{contact_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un contacto",
    description="Elimina un contacto existente.",
)
async def delete_contact(
    contact_id: int = Path(..., description="ID del contacto a eliminar"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Elimina un contacto existente.

    Args:
        contact_id: ID del contacto a eliminar.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        None

    Raises:
        HTTPException: Si el contacto no existe o no pertenece al usuario.
    """
    result = await ContactService.delete_contact(db, contact_id, current_user.id)

    if is_failure(result):
        error = result.failure()
        if isinstance(error, (ContactNotFoundError, UnauthorizedContactAccessError)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contacto no encontrado o no tienes permisos para acceder a él",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al eliminar el contacto",
            )


# Rutas para grupos de contactos
@router.post(
    "/groups/",
    response_model=ContactGroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un nuevo grupo de contactos",
    description="Crea un nuevo grupo de contactos para el usuario autenticado.",
)
async def create_contact_group(
    group_data: ContactGroupCreate,
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactGroupResponse:
    """
    Crea un nuevo grupo de contactos para el usuario autenticado.

    Args:
        group_data: Datos del grupo a crear.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        El grupo de contactos creado.

    Raises:
        HTTPException: Si ocurre un error al crear el grupo.
    """
    result = await ContactGroupService.create_group(db, current_user.id, group_data)

    if is_failure(result):
        error = result.failure()
        if isinstance(error, ContactGroupAlreadyExistsError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ya existe un grupo con el nombre {error.name}",
            )
        elif isinstance(error, ContactGroupValidationError):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Error de validación: {error.errors}",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al crear el grupo de contactos",
            )

    return ContactGroupResponse.model_validate(result.unwrap())


@router.get(
    "/groups/",
    response_model=ContactGroupListResponse,
    summary="Listar grupos de contactos",
    description="Obtiene una lista paginada de grupos de contactos del usuario autenticado.",
)
async def list_contact_groups(
    pagination: PaginationParams = Depends(),
    search: str | None = Query(None, description="Término de búsqueda"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactGroupListResponse:
    """
    Obtiene una lista paginada de grupos de contactos del usuario autenticado.

    Args:
        pagination: Parámetros de paginación.
        search: Término de búsqueda opcional.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        Lista paginada de grupos de contactos.

    Raises:
        HTTPException: Si ocurre un error al listar los grupos.
    """
    result = await ContactGroupService.list_groups(
        db, current_user.id, skip=pagination.skip, limit=pagination.limit, search=search
    )

    if result.is_failure():
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al listar los grupos de contactos",
        )

    groups = result.unwrap()

    return ContactGroupListResponse(
        items=[ContactGroupResponse.model_validate(group) for group in groups],
        total=len(groups),
        page=pagination.page,
        size=pagination.limit,
    )


@router.get(
    "/groups/{group_id}",
    response_model=ContactGroupResponse,
    summary="Obtener un grupo de contactos",
    description="Obtiene los detalles de un grupo de contactos específico por su ID.",
)
async def get_contact_group(
    group_id: int = Path(..., description="ID del grupo a obtener"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactGroupResponse:
    """
    Obtiene los detalles de un grupo de contactos específico por su ID.

    Args:
        group_id: ID del grupo a obtener.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        El grupo de contactos solicitado.

    Raises:
        HTTPException: Si el grupo no existe o no pertenece al usuario.
    """
    result = await ContactGroupService.get_group_by_id(db, group_id, current_user.id)

    if is_failure(result):
        error = result.failure()
        if isinstance(error, (ContactGroupNotFoundError, UnauthorizedGroupAccessError)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Grupo no encontrado o no tienes permisos para acceder a él",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al obtener el grupo de contactos",
            )

    return ContactGroupResponse.model_validate(result.unwrap())


@router.put(
    "/groups/{group_id}",
    response_model=ContactGroupResponse,
    summary="Actualizar un grupo de contactos",
    description="Actualiza los detalles de un grupo de contactos existente.",
)
async def update_contact_group(
    group_data: ContactGroupUpdate,
    group_id: int = Path(..., description="ID del grupo a actualizar"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactGroupResponse:
    """
    Actualiza los detalles de un grupo de contactos existente.

    Args:
        group_data: Datos actualizados del grupo.
        group_id: ID del grupo a actualizar.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        El grupo de contactos actualizado.

    Raises:
        HTTPException: Si el grupo no existe, no pertenece al usuario o hay conflictos.
    """
    result = await ContactGroupService.update_group(
        db, group_id, current_user.id, group_data
    )

    if is_failure(result):
        error = result.failure()
        if isinstance(error, (ContactGroupNotFoundError, UnauthorizedGroupAccessError)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Grupo no encontrado o no tienes permisos para acceder a él",
            )
        elif isinstance(error, ContactGroupAlreadyExistsError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Ya existe un grupo con el nombre {error.name}",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al actualizar el grupo de contactos",
            )

    return ContactGroupResponse.model_validate(result.unwrap())


@router.delete(
    "/groups/{group_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un grupo de contactos",
    description="Elimina un grupo de contactos existente.",
)
async def delete_contact_group(
    group_id: int = Path(..., description="ID del grupo a eliminar"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Elimina un grupo de contactos existente.

    Args:
        group_id: ID del grupo a eliminar.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        None

    Raises:
        HTTPException: Si el grupo no existe o no pertenece al usuario.
    """
    result = await ContactGroupService.delete_group(db, group_id, current_user.id)

    if is_failure(result):
        error = result.failure()
        if isinstance(error, (ContactGroupNotFoundError, UnauthorizedGroupAccessError)):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Grupo no encontrado o no tienes permisos para acceder a él",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al eliminar el grupo de contactos",
            )


# Rutas para asociaciones entre contactos y grupos
@router.post(
    "/groups/{group_id}/contacts/{contact_id}",
    status_code=status.HTTP_200_OK,
    summary="Añadir contacto a grupo",
    description="Añade un contacto existente a un grupo de contactos.",
)
async def add_contact_to_group(
    group_id: int = Path(..., description="ID del grupo al que añadir el contacto"),
    contact_id: int = Path(..., description="ID del contacto a añadir"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """
    Añade un contacto existente a un grupo de contactos.

    Args:
        group_id: ID del grupo al que añadir el contacto.
        contact_id: ID del contacto a añadir.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        Mensaje de confirmación.

    Raises:
        HTTPException: Si el contacto o grupo no existen, no pertenecen al usuario,
                      o el contacto ya está en el grupo.
    """
    result = await ContactGroupService.add_contact_to_group(
        db, contact_id, group_id, current_user.id
    )

    if is_failure(result):
        error = result.failure()
        if isinstance(
            error,
            (
                ContactNotFoundError,
                ContactGroupNotFoundError,
                UnauthorizedContactAccessError,
                UnauthorizedGroupAccessError,
            ),
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contacto o grupo no encontrado, o no tienes permisos para acceder a ellos",
            )
        elif isinstance(error, ContactAlreadyInGroupError):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El contacto ya está en el grupo",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al añadir el contacto al grupo",
            )

    return {"message": "Contacto añadido al grupo correctamente"}


@router.delete(
    "/groups/{group_id}/contacts/{contact_id}",
    status_code=status.HTTP_200_OK,
    summary="Eliminar contacto de grupo",
    description="Elimina un contacto de un grupo de contactos.",
)
async def remove_contact_from_group(
    group_id: int = Path(..., description="ID del grupo del que eliminar el contacto"),
    contact_id: int = Path(..., description="ID del contacto a eliminar"),
    current_user: User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict[str, str]:
    """
    Elimina un contacto de un grupo de contactos.

    Args:
        group_id: ID del grupo del que eliminar el contacto.
        contact_id: ID del contacto a eliminar.
        current_user: Usuario autenticado actual.
        db: Sesión de base de datos.

    Returns:
        Mensaje de confirmación.

    Raises:
        HTTPException: Si el contacto o grupo no existen, no pertenecen al usuario,
                      o el contacto no está en el grupo.
    """
    result = await ContactGroupService.remove_contact_from_group(
        db, contact_id, group_id, current_user.id
    )

    if is_failure(result):
        error = result.failure()
        if isinstance(
            error,
            (
                ContactNotFoundError,
                ContactGroupNotFoundError,
                UnauthorizedContactAccessError,
                UnauthorizedGroupAccessError,
            ),
        ):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Contacto o grupo no encontrado, o no tienes permisos para acceder a ellos",
            )
        elif isinstance(error, ContactNotInGroupError):
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="El contacto no está en el grupo",
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Error al eliminar el contacto del grupo",
            )

    return {"message": "Contacto eliminado del grupo correctamente"}
