import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Union

from returns.result import Failure, Result, Success
from sqlalchemy.ext.asyncio import AsyncSession

from app.contacts.errors import (
    ContactAlreadyExistsError,
    ContactAlreadyInGroupError,
    ContactGroupAlreadyExistsError,
    ContactGroupNotFoundError,
    ContactGroupValidationError,
    ContactNotFoundError,
    ContactNotInGroupError,
    ContactValidationError,
    DatabaseError,
    UnauthorizedContactAccessError,
    UnauthorizedGroupAccessError,
)
from app.contacts.models import Contact, ContactGroup
from app.contacts.repository import ContactGroupRepository, ContactRepository
from app.contacts.schemas import (
    ContactCreate,
    ContactGroupCreate,
    ContactGroupUpdate,
    ContactUpdate,
)

logger = logging.getLogger(__name__)


class ContactService:
    """
    Servicio para operaciones de negocio relacionadas con contactos.
    Implementa la lógica de negocio utilizando el repositorio para acceder a los datos.
    """

    @staticmethod
    async def get_contact_by_id(
        db: AsyncSession, contact_id: int, owner_id: Optional[int] = None
    ) -> Result[
        Contact, ContactNotFoundError | UnauthorizedContactAccessError | DatabaseError
    ]:
        """
        Obtiene un contacto por su ID.

        Args:
            db: Sesión de base de datos asíncrona.
            contact_id: ID del contacto a obtener.
            owner_id: ID del propietario del contacto (opcional).

        Returns:
            Result con el contacto si se encuentra, o un error apropiado si no.
        """
        return await ContactRepository.get_by_id(db, contact_id, owner_id)

    @staticmethod
    async def get_contact_by_email(
        db: AsyncSession, email: str, owner_id: int
    ) -> Result[Contact, ContactNotFoundError | DatabaseError]:
        """
        Obtiene un contacto por su email y propietario.

        Args:
            db: Sesión de base de datos asíncrona.
            email: Email del contacto a buscar.
            owner_id: ID del propietario del contacto.

        Returns:
            Result con el contacto si se encuentra, o un error apropiado si no.
        """
        return await ContactRepository.get_by_email(db, email, owner_id)

    @staticmethod
    async def list_contacts(
        db: AsyncSession,
        owner_id: int,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        group_id: Optional[int] = None,
    ) -> Result[
        List[Contact],
        DatabaseError | ContactGroupNotFoundError | UnauthorizedGroupAccessError,
    ]:
        """
        Obtiene una lista paginada de contactos con filtros opcionales.

        Args:
            db: Sesión de base de datos asíncrona.
            owner_id: ID del propietario de los contactos.
            skip: Número de registros a omitir (para paginación).
            limit: Límite de registros a devolver.
            search: Término de búsqueda para filtrar.
            group_id: ID del grupo para filtrar contactos (opcional).

        Returns:
            Result con la lista de contactos si la consulta es exitosa, o un error de base de datos.
        """
        # Si se especifica un grupo, verificar que existe y pertenece al usuario
        if group_id is not None:
            group_result = await ContactGroupRepository.get_by_id(
                db, group_id, owner_id
            )
            if group_result.is_failure():
                return group_result

        return await ContactRepository.list_contacts(
            db=db,
            owner_id=owner_id,
            skip=skip,
            limit=limit,
            group_id=group_id,
            search=search,
            contact_type=None,
            status=None,
            is_favorite=None
        )

    @staticmethod
    async def create_contact(
        db: AsyncSession, owner_id: int, contact_data: ContactCreate
    ) -> Result[
        Contact, ContactAlreadyExistsError | ContactValidationError | DatabaseError
    ]:
        """
        Crea un nuevo contacto.

        Args:
            db: Sesión de base de datos asíncrona.
            owner_id: ID del propietario del contacto.
            contact_data: Datos del contacto a crear.

        Returns:
            Result con el contacto creado si la operación es exitosa, o un error apropiado si no.
        """
        return await ContactRepository.create(
            db,
            owner_id=owner_id,
            first_name=contact_data.first_name,
            last_name=contact_data.last_name,
            email=contact_data.email,
            phone=contact_data.phone,
            company=contact_data.company,
            position=contact_data.position,
            contact_type=contact_data.contact_type.value if contact_data.contact_type else None,
            status=contact_data.status.value if contact_data.status else None,
            is_favorite=contact_data.is_favorite,
            address=contact_data.address,
            notes=contact_data.notes,
            custom_fields=contact_data.custom_fields,
        )

    @staticmethod
    async def update_contact(
        db: AsyncSession, contact_id: int, owner_id: int, contact_data: ContactUpdate
    ) -> Result[
        Contact,
        ContactNotFoundError
        | UnauthorizedContactAccessError
        | ContactAlreadyExistsError
        | DatabaseError,
    ]:
        """
        Actualiza un contacto existente.

        Args:
            db: Sesión de base de datos asíncrona.
            contact_id: ID del contacto a actualizar.
            owner_id: ID del propietario del contacto.
            contact_data: Datos actualizados del contacto.

        Returns:
            Result con el contacto actualizado si la operación es exitosa, o un error apropiado si no.
        """
        # Convertir el modelo Pydantic a un diccionario excluyendo valores None
        update_data = contact_data.dict(exclude_unset=True)

        # Eliminar campos None para no sobrescribir valores existentes con None
        update_data = {k: v for k, v in update_data.items() if v is not None}

        # Convertir enums a strings para la base de datos
        if 'contact_type' in update_data and update_data['contact_type'] is not None:
            update_data['contact_type'] = update_data['contact_type'].value
        
        if 'status' in update_data and update_data['status'] is not None:
            update_data['status'] = update_data['status'].value

        return await ContactRepository.update(db, contact_id, owner_id, **update_data)

    @staticmethod
    async def delete_contact(
        db: AsyncSession, contact_id: int, owner_id: int
    ) -> Result[
        None, ContactNotFoundError | UnauthorizedContactAccessError | DatabaseError
    ]:
        """
        Elimina un contacto existente.

        Args:
            db: Sesión de base de datos asíncrona.
            contact_id: ID del contacto a eliminar.
            owner_id: ID del propietario del contacto.

        Returns:
            Result con None si la eliminación es exitosa, o un error apropiado si no.
        """
        return await ContactRepository.delete(db, contact_id, owner_id)


class ContactGroupService:
    """
    Servicio para operaciones de negocio relacionadas con grupos de contactos.
    Implementa la lógica de negocio utilizando el repositorio para acceder a los datos.
    """

    @staticmethod
    async def get_group_by_id(
        db: AsyncSession, group_id: int, owner_id: Optional[int] = None
    ) -> Result[
        ContactGroup,
        ContactGroupNotFoundError | UnauthorizedGroupAccessError | DatabaseError,
    ]:
        """
        Obtiene un grupo de contactos por su ID.

        Args:
            db: Sesión de base de datos asíncrona.
            group_id: ID del grupo a obtener.
            owner_id: ID del propietario del grupo (opcional).

        Returns:
            Result con el grupo si se encuentra, o un error apropiado si no.
        """
        return await ContactGroupRepository.get_by_id(db, group_id, owner_id)

    @staticmethod
    async def get_group_by_name(
        db: AsyncSession, name: str, owner_id: int
    ) -> Result[ContactGroup, ContactGroupNotFoundError | DatabaseError]:
        """
        Obtiene un grupo de contactos por su nombre y propietario.

        Args:
            db: Sesión de base de datos asíncrona.
            name: Nombre del grupo a buscar.
            owner_id: ID del propietario del grupo.

        Returns:
            Result con el grupo si se encuentra, o un error apropiado si no.
        """
        return await ContactGroupRepository.get_by_name(db, name, owner_id)

    @staticmethod
    async def list_groups(
        db: AsyncSession,
        owner_id: int,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
    ) -> Result[List[ContactGroup], DatabaseError]:
        """
        Obtiene una lista paginada de grupos de contactos con filtros opcionales.

        Args:
            db: Sesión de base de datos asíncrona.
            owner_id: ID del propietario de los grupos.
            skip: Número de registros a omitir (para paginación).
            limit: Límite de registros a devolver.
            search: Término de búsqueda para filtrar por nombre o descripción.

        Returns:
            Result con la lista de grupos si la consulta es exitosa, o un error de base de datos.
        """
        return await ContactGroupRepository.list_groups(
            db, owner_id, skip, limit, search
        )

    @staticmethod
    async def create_group(
        db: AsyncSession, owner_id: int, group_data: ContactGroupCreate
    ) -> Result[
        ContactGroup,
        ContactGroupAlreadyExistsError | ContactGroupValidationError | DatabaseError,
    ]:
        """
        Crea un nuevo grupo de contactos.

        Args:
            db: Sesión de base de datos asíncrona.
            owner_id: ID del propietario del grupo.
            group_data: Datos del grupo a crear.

        Returns:
            Result con el grupo creado si la operación es exitosa, o un error apropiado si no.
        """
        return await ContactGroupRepository.create(
            db,
            owner_id=owner_id,
            name=group_data.name,
            description=group_data.description,
        )

    @staticmethod
    async def update_group(
        db: AsyncSession, group_id: int, owner_id: int, group_data: ContactGroupUpdate
    ) -> Result[
        ContactGroup,
        ContactGroupNotFoundError
        | UnauthorizedGroupAccessError
        | ContactGroupAlreadyExistsError
        | DatabaseError,
    ]:
        """
        Actualiza un grupo de contactos existente.

        Args:
            db: Sesión de base de datos asíncrona.
            group_id: ID del grupo a actualizar.
            owner_id: ID del propietario del grupo.
            group_data: Datos actualizados del grupo.

        Returns:
            Result con el grupo actualizado si la operación es exitosa, o un error apropiado si no.
        """
        # Convertir el modelo Pydantic a un diccionario excluyendo valores None
        update_data = group_data.dict(exclude_unset=True)

        # Eliminar campos None para no sobrescribir valores existentes con None
        update_data = {k: v for k, v in update_data.items() if v is not None}

        return await ContactGroupRepository.update(
            db, group_id, owner_id, **update_data
        )

    @staticmethod
    async def delete_group(
        db: AsyncSession, group_id: int, owner_id: int
    ) -> Result[
        None, ContactGroupNotFoundError | UnauthorizedGroupAccessError | DatabaseError
    ]:
        """
        Elimina un grupo de contactos existente.

        Args:
            db: Sesión de base de datos asíncrona.
            group_id: ID del grupo a eliminar.
            owner_id: ID del propietario del grupo.

        Returns:
            Result con None si la eliminación es exitosa, o un error apropiado si no.
        """
        return await ContactGroupRepository.delete(db, group_id, owner_id)

    @staticmethod
    async def add_contact_to_group(
        db: AsyncSession,
        contact_id: int,
        group_id: int,
        owner_id: int,
        notes: Optional[str] = None,
    ) -> Result[
        None,
        ContactNotFoundError
        | ContactGroupNotFoundError
        | UnauthorizedContactAccessError
        | UnauthorizedGroupAccessError
        | ContactAlreadyInGroupError
        | DatabaseError,
    ]:
        """
        Añade un contacto a un grupo de contactos.

        Args:
            db: Sesión de base de datos asíncrona.
            contact_id: ID del contacto a añadir.
            group_id: ID del grupo al que añadir el contacto.
            owner_id: ID del propietario tanto del contacto como del grupo.
            notes: Notas adicionales sobre la pertenencia del contacto al grupo.

        Returns:
            Result con None si la operación es exitosa, o un error apropiado si no.
        """
        return await ContactGroupRepository.add_contact_to_group(
            db, contact_id, group_id, owner_id, notes
        )

    @staticmethod
    async def remove_contact_from_group(
        db: AsyncSession, contact_id: int, group_id: int, owner_id: int
    ) -> Result[
        None,
        ContactNotFoundError
        | ContactGroupNotFoundError
        | UnauthorizedContactAccessError
        | UnauthorizedGroupAccessError
        | ContactNotInGroupError
        | DatabaseError,
    ]:
        """
        Elimina un contacto de un grupo de contactos.

        Args:
            db: Sesión de base de datos asíncrona.
            contact_id: ID del contacto a eliminar del grupo.
            group_id: ID del grupo del que eliminar el contacto.
            owner_id: ID del propietario tanto del contacto como del grupo.

        Returns:
            Result con None si la operación es exitosa, o un error apropiado si no.
        """
        return await ContactGroupRepository.remove_contact_from_group(
            db, contact_id, group_id, owner_id
        )
