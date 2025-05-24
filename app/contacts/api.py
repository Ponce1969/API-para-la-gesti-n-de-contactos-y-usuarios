"""
Módulo de rutas de la API para la gestión de contactos.

Este módulo define los endpoints para operaciones CRUD de contactos,
incluyendo la gestión de grupos de contactos.
"""
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status, Query

from app.auth.dependencies import get_current_active_user
from app.common.database import get_db
from app.common.errors import ResourceNotFoundError, DatabaseError
from sqlalchemy.ext.asyncio import AsyncSession

from . import schemas, service
from .models import Contact, ContactGroup
from .schemas import ContactCreate, ContactUpdate, ContactResponse, ContactGroupCreate, ContactGroupResponse

router = APIRouter()

# Rutas para contactos
@router.post(
    "/",
    response_model=ContactResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un nuevo contacto",
    description="Crea un nuevo contacto asociado al usuario actual.",
)
async def create_contact(
    contact_data: ContactCreate,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactResponse:
    """
    Crea un nuevo contacto para el usuario actual.
    
    Args:
        contact_data: Datos del contacto a crear.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        El contacto creado con su ID asignado.
    """
    try:
        return await service.create_contact(db, contact_data, owner_id=current_user.id)
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el contacto.",
        )

@router.get(
    "/",
    response_model=List[ContactResponse],
    summary="Listar contactos",
    description="Obtiene una lista paginada de los contactos del usuario actual.",
)
async def list_contacts(
    skip: int = 0,
    limit: int = 100,
    group_id: Optional[int] = None,
    search: Optional[str] = None,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> List[ContactResponse]:
    """
    Obtiene una lista de contactos del usuario actual con opciones de filtrado.
    
    Args:
        skip: Número de registros a omitir (para paginación).
        limit: Número máximo de registros a devolver.
        group_id: Filtrar por ID de grupo (opcional).
        search: Término de búsqueda para filtrar contactos (opcional).
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Lista de contactos que coinciden con los criterios.
    """
    return await service.get_contacts(
        db, 
        owner_id=current_user.id, 
        group_id=group_id,
        search=search,
        skip=skip, 
        limit=limit
    )

@router.get(
    "/{contact_id}",
    response_model=ContactResponse,
    summary="Obtener un contacto",
    description="Obtiene los detalles de un contacto específico por su ID.",
)
async def get_contact(
    contact_id: int,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactResponse:
    """
    Obtiene un contacto por su ID.
    
    Args:
        contact_id: ID del contacto a obtener.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Los detalles del contacto solicitado.
        
    Raises:
        HTTPException: Si el contacto no se encuentra o no pertenece al usuario.
    """
    try:
        contact = await service.get_contact_by_id(db, contact_id, current_user.id)
        return contact
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )

@router.put(
    "/{contact_id}",
    response_model=ContactResponse,
    summary="Actualizar un contacto",
    description="Actualiza los datos de un contacto existente.",
)
async def update_contact(
    contact_id: int,
    contact_data: ContactUpdate,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactResponse:
    """
    Actualiza un contacto existente.
    
    Args:
        contact_id: ID del contacto a actualizar.
        contact_data: Datos actualizados del contacto.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        El contacto actualizado.
        
    Raises:
        HTTPException: Si el contacto no se encuentra o no pertenece al usuario.
    """
    try:
        return await service.update_contact(
            db, contact_id, contact_data, current_user.id
        )
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al actualizar el contacto.",
        )

@router.delete(
    "/{contact_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Eliminar un contacto",
    description="Elimina un contacto del sistema.",
)
async def delete_contact(
    contact_id: int,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> None:
    """
    Elimina un contacto.
    
    Args:
        contact_id: ID del contacto a eliminar.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Raises:
        HTTPException: Si el contacto no se encuentra o no pertenece al usuario.
    """
    try:
        await service.delete_contact(db, contact_id, current_user.id)
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el contacto.",
        )

# Rutas para grupos de contactos
@router.post(
    "/groups/",
    response_model=ContactGroupResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Crear un nuevo grupo",
    description="Crea un nuevo grupo de contactos para el usuario actual.",
)
async def create_contact_group(
    group_data: ContactGroupCreate,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> ContactGroupResponse:
    """
    Crea un nuevo grupo de contactos.
    
    Args:
        group_data: Datos del grupo a crear.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        El grupo creado con su ID asignado.
    """
    try:
        return await service.create_contact_group(
            db, group_data, owner_id=current_user.id
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el grupo de contactos.",
        )

@router.get(
    "/groups/",
    response_model=List[ContactGroupResponse],
    summary="Listar grupos",
    description="Obtiene una lista de los grupos de contactos del usuario actual.",
)
async def list_contact_groups(
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> List[ContactGroupResponse]:
    """
    Obtiene los grupos de contactos del usuario actual.
    
    Args:
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Lista de grupos de contactos del usuario.
    """
    return await service.get_contact_groups(db, owner_id=current_user.id)

@router.post(
    "/{contact_id}/groups/{group_id}",
    status_code=status.HTTP_200_OK,
    summary="Agregar contacto a grupo",
    description="Agrega un contacto a un grupo específico.",
)
async def add_contact_to_group(
    contact_id: int,
    group_id: int,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Agrega un contacto a un grupo.
    
    Args:
        contact_id: ID del contacto a agregar.
        group_id: ID del grupo al que se agregará el contacto.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Mensaje de confirmación.
        
    Raises:
        HTTPException: Si el contacto o el grupo no existen o no pertenecen al usuario.
    """
    try:
        await service.add_contact_to_group(
            db, contact_id, group_id, current_user.id
        )
        return {"message": "Contacto agregado al grupo correctamente"}
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al agregar el contacto al grupo.",
        )

@router.delete(
    "/{contact_id}/groups/{group_id}",
    status_code=status.HTTP_200_OK,
    summary="Eliminar contacto de grupo",
    description="Elimina un contacto de un grupo específico.",
)
async def remove_contact_from_group(
    contact_id: int,
    group_id: int,
    current_user: schemas.User = Depends(get_current_active_user),
    db: AsyncSession = Depends(get_db),
) -> dict:
    """
    Elimina un contacto de un grupo.
    
    Args:
        contact_id: ID del contacto a eliminar.
        group_id: ID del grupo del que se eliminará el contacto.
        current_user: Usuario autenticado.
        db: Sesión de base de datos.
        
    Returns:
        Mensaje de confirmación.
        
    Raises:
        HTTPException: Si el contacto o el grupo no existen o no pertenecen al usuario.
    """
    try:
        await service.remove_contact_from_group(
            db, contact_id, group_id, current_user.id
        )
        return {"message": "Contacto eliminado del grupo correctamente"}
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except DatabaseError as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al eliminar el contacto del grupo.",
        )
