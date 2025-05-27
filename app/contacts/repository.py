"""
Repositorio para el módulo de contactos.

Este módulo implementa la capa de acceso a datos para contactos y grupos de contactos,
utilizando SQLAlchemy con soporte asíncrono y el patrón Result para manejo funcional de errores.
"""

import logging
from datetime import datetime, timezone # Ensure timezone is imported
from typing import Any, Dict, List, Optional, Tuple, Union, cast

from returns.result import Failure, Result, Success
from sqlalchemy import and_, delete, func, insert, not_, or_, select, text, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import joinedload, selectinload

from app.common.errors import DatabaseError
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
from app.contacts.models import Contact, ContactGroup, contact_group_members

logger = logging.getLogger(__name__)


class ContactRepository:
    """Repositorio para operaciones CRUD de contactos."""

    @staticmethod
    async def get_by_id(
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
                Si se proporciona, se verifica que el contacto pertenezca a este usuario.

        Returns:
            Result con el contacto si se encuentra, o un error apropiado si no.
        """
        try:
            # Consulta base para obtener el contacto por ID
            query = (
                select(Contact)
                .where(Contact.id == contact_id)
                .options(selectinload(Contact.groups))
            )

            # Si se proporciona owner_id, agregar filtro para verificar propiedad
            if owner_id is not None:
                query = query.where(Contact.owner_id == owner_id)

            result = await db.execute(query)
            contact = result.scalars().first()

            # Si no se encuentra el contacto, devolver error
            if contact is None:
                if owner_id is not None:
                    # Verificar si el contacto existe pero no pertenece al usuario
                    verify_query = select(Contact).where(Contact.id == contact_id)
                    verify_result = await db.execute(verify_query)
                    verify_contact = verify_result.scalar_one_or_none()

                    if verify_contact is not None:
                        # El contacto existe pero no pertenece al usuario especificado
                        return Failure(UnauthorizedContactAccessError(contact_id))

                # El contacto no existe
                return Failure(ContactNotFoundError(contact_id))

            return Success(contact)
        except SQLAlchemyError as e:
            logger.error(f"Error al obtener contacto con ID {contact_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def get_by_email(
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
        try:
            query = (
                select(Contact)
                .where(Contact.email == email)
                .where(Contact.owner_id == owner_id)
            )
            result = await db.execute(query)
            contact = result.scalar_one_or_none()

            if contact is None:
                return Failure(
                    ContactNotFoundError(
                        0, f"No se encontró un contacto con email {email}"
                    )
                )

            return Success(contact)
        except SQLAlchemyError as e:
            logger.error(f"Error al obtener contacto con email {email}: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def create(
        db: AsyncSession,
        owner_id: int,
        first_name: Optional[str] = None,
        last_name: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        company: Optional[str] = None,
        position: Optional[str] = None,
        contact_type: Optional[str] = None,
        status: Optional[str] = None,
        is_favorite: bool = False,
        address: Optional[str] = None,
        notes: Optional[str] = None,
        custom_fields: Optional[Dict[str, Any]] = None,
        contact_user_id: Optional[int] = None,
    ) -> Result[
        Contact, ContactAlreadyExistsError | ContactValidationError | DatabaseError
    ]:
        """
        Crea un nuevo contacto.

        Args:
            db: Sesión de base de datos asíncrona.
            owner_id: ID del usuario propietario del contacto.
            first_name: Nombre del contacto.
            last_name: Apellido del contacto.
            email: Correo electrónico del contacto.
            phone: Número de teléfono del contacto.
            company: Empresa u organización del contacto.
            position: Cargo o posición del contacto en la empresa.
            contact_type: Tipo de contacto (personal, trabajo, familiar, etc.).
            status: Estado del contacto (activo, inactivo, pendiente, bloqueado).
            is_favorite: Indica si el contacto está marcado como favorito.
            address: Dirección física completa del contacto.
            notes: Notas adicionales sobre el contacto.
            custom_fields: Campos personalizados adicionales en formato JSON.
            contact_user_id: ID del usuario de la plataforma si el contacto está registrado.

        Returns:
            Result con el contacto creado si la operación es exitosa, o un error apropiado si no.
        """
        logger = logging.getLogger(__name__)
        try:
            # Validar campos requeridos
            validation_errors = {}
            if not first_name and not last_name and not email and not phone:
                validation_errors["contact"] = "Se requiere al menos un campo identificativo (nombre, apellido, email o teléfono)"
            
            if validation_errors:
                return Failure(ContactValidationError(validation_errors))

            # Verificar si ya existe un contacto con el mismo email para este usuario
            if email:
                existing_result = await ContactRepository.get_by_email(db, email, owner_id)
                if existing_result.is_success():
                    return Failure(ContactAlreadyExistsError(email, owner_id))

            # Crear nuevo contacto
            now = datetime.now(datetime.timezone.utc)
            new_contact = Contact(
                owner_id=owner_id,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone=phone,
                company=company,
                position=position,
                contact_type=contact_type,
                status=status,
                is_favorite=is_favorite,
                address=address,
                notes=notes,
                custom_fields=custom_fields,
                contact_user_id=contact_user_id,
                created_at=now,
                updated_at=now,
            )

            db.add(new_contact)
            await db.flush()
            await db.refresh(new_contact)
            await db.commit()

            return Success(new_contact)
        except IntegrityError as e:
            await db.rollback()
            logger.error(f"Error de integridad al crear contacto: {str(e)}")
            return Failure(ContactAlreadyExistsError(email or "", owner_id))
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al crear contacto: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def update(
        db: AsyncSession, contact_id: int, owner_id: int, **kwargs
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
            owner_id: ID del usuario propietario del contacto.
            **kwargs: Campos a actualizar y sus nuevos valores.

        Returns:
            Result con el contacto actualizado si la operación es exitosa, o un error apropiado si no.
        """
        logger = logging.getLogger(__name__)
        try:
            # Verificar si el contacto existe y pertenece al usuario
            contact_result = await ContactRepository.get_by_id(db, contact_id, owner_id)
            if contact_result.is_failure():
                return contact_result

            contact = contact_result.unwrap()

            # Si se intenta actualizar el email, verificar que no exista otro con ese email
            if "email" in kwargs and kwargs["email"] != contact.email and kwargs["email"] is not None:
                existing_result = await ContactRepository.get_by_email(
                    db, kwargs["email"], owner_id
                )
                if existing_result.is_success():
                    return Failure(
                        ContactAlreadyExistsError(kwargs["email"], owner_id)
                    )

            # Actualizar campos
            for key, value in kwargs.items():
                if hasattr(contact, key):
                    setattr(contact, key, value)

            contact.updated_at = datetime.now(datetime.timezone.utc)
            await db.commit()
            await db.refresh(contact)

            return Success(contact)
        except IntegrityError as e:
            await db.rollback()
            logger.error(f"Error de integridad al actualizar contacto {contact_id}: {str(e)}")
            return Failure(
                ContactAlreadyExistsError(
                    kwargs.get("email", ""), owner_id, message=str(e)
                )
            )
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al actualizar contacto {contact_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def delete(
        db: AsyncSession, contact_id: int, owner_id: int
    ) -> Result[None, ContactNotFoundError | UnauthorizedContactAccessError | DatabaseError]:
        """
        Elimina un contacto existente.

        Args:
            db: Sesión de base de datos asíncrona.
            contact_id: ID del contacto a eliminar.
            owner_id: ID del usuario propietario del contacto.

        Returns:
            Result con None si la eliminación es exitosa, o un error apropiado si no.
        """
        logger = logging.getLogger(__name__)
        try:
            # Verificar si el contacto existe y pertenece al usuario
            contact_result = await ContactRepository.get_by_id(db, contact_id, owner_id)
            if contact_result.is_failure():
                return contact_result

            contact = contact_result.unwrap()

            # Eliminar el contacto
            await db.delete(contact)
            await db.flush()
            await db.commit()

            return Success(None)
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al eliminar contacto {contact_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))


class ContactGroupRepository:
    """Repositorio para operaciones CRUD de grupos de contactos."""

    @staticmethod
    async def get_by_id(
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
                Si se proporciona, se verifica que el grupo pertenezca a este usuario.

        Returns:
            Result con el grupo si se encuentra, o un error apropiado si no.
        """
        logger = logging.getLogger(__name__)
        try:
            query = select(ContactGroup).where(ContactGroup.id == group_id)

            # Si se proporciona owner_id, verificar que el contacto pertenezca a este usuario
            if owner_id is not None:
                query = query.where(ContactGroup.owner_id == owner_id)

            result = await db.execute(query)
            group = result.scalar_one_or_none()

            if group is None:
                if owner_id is not None:
                    # Verificar si el grupo existe pero pertenece a otro usuario
                    query_check = select(ContactGroup).where(
                        ContactGroup.id == group_id
                    )
                    result_check = await db.execute(query_check)
                    exists = result_check.scalar_one_or_none() is not None

                    if exists:
                        return Failure(UnauthorizedGroupAccessError(group_id))

                return Failure(ContactGroupNotFoundError(group_id))

            return Success(group)
        except SQLAlchemyError as e:
            logger.error(f"Error al obtener grupo con ID {group_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def get_by_name(
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
        logger = logging.getLogger(__name__)
        try:
            query = select(ContactGroup).where(
                ContactGroup.name == name, ContactGroup.owner_id == owner_id
            )
            result = await db.execute(query)
            group = result.scalar_one_or_none()

            if group is None:
                return Failure(
                    ContactGroupNotFoundError(
                        0, f"No se encontró un grupo con nombre {name}"
                    )
                )

            return Success(group)
        except SQLAlchemyError as e:
            logger.error(f"Error al obtener grupo con nombre {name}: {str(e)}")
            return Failure(DatabaseError(str(e)))

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
        logger = logging.getLogger(__name__)
        try:
            # Consulta base
            query = select(ContactGroup).where(ContactGroup.owner_id == owner_id)

            # Aplicar filtro de búsqueda si se proporciona
            if search:
                query = query.where(
                    or_(
                        ContactGroup.name.ilike(f"%{search}%"),
                        ContactGroup.description.ilike(f"%{search}%"),
                    )
                )

            # Aplicar paginación
            query = query.offset(skip).limit(limit)

            # Cargar los contactos de cada grupo
            query = query.options(selectinload(ContactGroup.contacts))

            # Ejecutar consulta
            result = await db.execute(query)
            groups = result.scalars().all()

            return Success(list(groups))
        except SQLAlchemyError as e:
            logger.error(f"Error al listar grupos: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def create(
        db: AsyncSession,
        owner_id: int,
        name: str,
        description: Optional[str] = None,
    ) -> Result[
        ContactGroup,
        ContactGroupAlreadyExistsError | ContactGroupValidationError | DatabaseError,
    ]:
        """
        Crea un nuevo grupo de contactos.

        Args:
            db: Sesión de base de datos asíncrona.
            owner_id: ID del usuario propietario del grupo.
            name: Nombre del grupo de contactos.
            description: Descripción opcional del grupo.

        Returns:
            Result con el grupo creado si la operación es exitosa, o un error apropiado si no.
        """
        logger = logging.getLogger(__name__)
        try:
            # Validar nombre requerido
            if not name:
                return Failure(
                    ContactGroupValidationError(
                        {"name": "El nombre del grupo es requerido"}
                    )
                )

            # Verificar si ya existe un grupo con el mismo nombre para este usuario
            existing_result = await ContactGroupRepository.get_by_name(
                db, name, owner_id
            )
            if existing_result.is_success():
                return Failure(ContactGroupAlreadyExistsError(name, owner_id))

            # Crear nuevo grupo
            now = datetime.now(datetime.timezone.utc)
            new_group = ContactGroup(
                owner_id=owner_id,
                name=name,
                description=description,
                created_at=now,
                updated_at=now,
            )

            db.add(new_group)
            await db.flush()
            await db.refresh(new_group)
            await db.commit()

            return Success(new_group)
        except IntegrityError as e:
            await db.rollback()
            logger.error(f"Error de integridad al crear grupo: {str(e)}")
            return Failure(ContactGroupAlreadyExistsError(name, owner_id))
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al crear grupo: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def update(
        db: AsyncSession, group_id: int, owner_id: int, **kwargs
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
            owner_id: ID del usuario propietario del grupo.
            **kwargs: Campos a actualizar y sus nuevos valores.

        Returns:
            Result con el grupo actualizado si la operación es exitosa, o un error apropiado si no.
        """
        logger = logging.getLogger(__name__)
        try:
            # Verificar si el grupo existe y pertenece al usuario
            group_result = await ContactGroupRepository.get_by_id(
                db, group_id, owner_id
            )
            if group_result.is_failure():
                return group_result

            group = group_result.unwrap()

            # Si se intenta actualizar el nombre, verificar que no exista otro con ese nombre
            if "name" in kwargs and kwargs["name"] != group.name:
                existing_result = await ContactGroupRepository.get_by_name(
                    db, kwargs["name"], owner_id
                )
                if existing_result.is_success():
                    return Failure(
                        ContactGroupAlreadyExistsError(kwargs["name"], owner_id)
                    )

            # Actualizar campos
            for key, value in kwargs.items():
                if hasattr(group, key):
                    setattr(group, key, value)

            group.updated_at = datetime.now(datetime.timezone.utc)
            await db.commit()
            await db.refresh(group)

            return Success(group)
        except IntegrityError as e:
            await db.rollback()
            logger.error(
                f"Error de integridad al actualizar grupo {group_id}: {str(e)}"
            )
            return Failure(
                ContactGroupAlreadyExistsError(
                    kwargs.get("name", ""), owner_id, message=str(e)
                )
            )
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al actualizar grupo {group_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def delete(
        db: AsyncSession, group_id: int, owner_id: int
    ) -> Result[
        None, ContactGroupNotFoundError | UnauthorizedGroupAccessError | DatabaseError
    ]:
        """
        Elimina un grupo de contactos existente.

        Args:
            db: Sesión de base de datos asíncrona.
            group_id: ID del grupo a eliminar.
            owner_id: ID del usuario propietario del grupo.

        Returns:
            Result con None si la eliminación es exitosa, o un error apropiado si no.
        """
        logger = logging.getLogger(__name__)
        try:
            # Verificar si el grupo existe y pertenece al usuario
            group_result = await ContactGroupRepository.get_by_id(
                db, group_id, owner_id
            )
            if group_result.is_failure():
                return group_result

            group = group_result.unwrap()

            # Eliminar el grupo
            await db.delete(group)
            await db.flush()

            return Success(None)
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al eliminar grupo {group_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))

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
        logger = logging.getLogger(__name__)
        try:
            # Verificar si el contacto existe y pertenece al usuario
            contact_result = await ContactRepository.get_by_id(db, contact_id, owner_id)
            if contact_result.is_failure():
                return contact_result

            # Verificar si el grupo existe y pertenece al usuario
            group_result = await ContactGroupRepository.get_by_id(
                db, group_id, owner_id
            )
            if group_result.is_failure():
                return group_result

            # Verificar si el contacto ya está en el grupo
            query = select(contact_group_members).where(
                contact_group_members.c.contact_id == contact_id,
                contact_group_members.c.group_id == group_id,
            )
            result = await db.execute(query)
            if result.first() is not None:
                return Failure(ContactAlreadyInGroupError(contact_id, group_id))

            # Añadir contacto al grupo
            insert_stmt = insert(contact_group_members).values(
                contact_id=contact_id,
                group_id=group_id,
                notes=notes,
                added_at=datetime.now(datetime.timezone.utc),
            )
            await db.execute(insert_stmt)
            await db.commit()

            return Success(None)
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(
                f"Error al añadir contacto {contact_id} al grupo {group_id}: {str(e)}"
            )
            return Failure(DatabaseError(str(e)))

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
        logger = logging.getLogger(__name__)
        try:
            # Verificar si el contacto existe y pertenece al usuario
            contact_result = await ContactRepository.get_by_id(db, contact_id, owner_id)
            if contact_result.is_failure():
                return contact_result

            # Verificar si el grupo existe y pertenece al usuario
            group_result = await ContactGroupRepository.get_by_id(
                db, group_id, owner_id
            )
            if group_result.is_failure():
                return group_result

            # Verificar si el contacto está en el grupo
            query = select(contact_group_members).where(
                contact_group_members.c.contact_id == contact_id,
                contact_group_members.c.group_id == group_id,
            )
            result = await db.execute(query)
            if result.first() is None:
                return Failure(ContactNotInGroupError(contact_id, group_id))

            # Eliminar contacto del grupo
            delete_stmt = delete(contact_group_members).where(
                contact_group_members.c.contact_id == contact_id,
                contact_group_members.c.group_id == group_id,
            )
            await db.execute(delete_stmt)
            await db.commit()

            return Success(None)
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(
                f"Error al eliminar contacto {contact_id} del grupo {group_id}: {str(e)}"
            )
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def list_contacts(
        db: AsyncSession,
        owner_id: int,
        skip: int = 0,
        limit: int = 100,
        group_id: Optional[int] = None,
        search: Optional[str] = None,
        contact_type: Optional[str] = None,
        status: Optional[str] = None,
        is_favorite: Optional[bool] = None,
    ) -> Result[
        List[Contact],
        ContactGroupNotFoundError | UnauthorizedGroupAccessError | DatabaseError,
    ]:
        """
        Obtiene una lista paginada de contactos con filtros opcionales.

        Args:
            db: Sesión de base de datos asíncrona.
            owner_id: ID del propietario de los contactos.
            skip: Número de registros a omitir (para paginación).
            limit: Límite de registros a devolver.
            group_id: ID del grupo para filtrar contactos.
            search: Término de búsqueda para filtrar por nombre, email, teléfono, etc.
            contact_type: Tipo de contacto para filtrar.
            status: Estado del contacto para filtrar.
            is_favorite: Filtrar por contactos favoritos.

        Returns:
            Result con la lista de contactos si la consulta es exitosa, o un error de base de datos.
        """
        logger = logging.getLogger(__name__)
        try:
            # Si se especifica un grupo, verificar que exista y pertenezca al usuario
            if group_id is not None:
                group_result = await ContactGroupRepository.get_by_id(
                    db, group_id, owner_id
                )
                if group_result.is_failure():
                    return group_result

            # Construir la consulta base
            if group_id is not None:
                # Obtener contactos de un grupo específico
                query = (
                    select(Contact)
                    .join(
                        contact_group_members,
                        Contact.id == contact_group_members.c.contact_id,
                    )
                    .where(
                        contact_group_members.c.group_id == group_id,
                        Contact.owner_id == owner_id,
                    )
                )
            else:
                # Obtener todos los contactos del usuario
                query = select(Contact).where(Contact.owner_id == owner_id)

            # Aplicar filtros opcionales
            if search:
                search_filter = or_(
                    Contact.first_name.ilike(f"%{search}%"),
                    Contact.last_name.ilike(f"%{search}%"),
                    Contact.email.ilike(f"%{search}%"),
                    Contact.phone.ilike(f"%{search}%"),
                    Contact.company.ilike(f"%{search}%"),
                )
                query = query.where(search_filter)

            if contact_type:
                query = query.where(Contact.contact_type == contact_type)

            if status:
                query = query.where(Contact.status == status)

            if is_favorite is not None:
                query = query.where(Contact.is_favorite == is_favorite)

            # Aplicar paginación
            query = query.offset(skip).limit(limit)

            # Ejecutar consulta
            result = await db.execute(query)
            contacts = result.scalars().all()

            return Success(list(contacts))
        except SQLAlchemyError as e:
            logger.error(f"Error al listar contactos: {str(e)}")
            return Failure(DatabaseError(str(e)))
