"""
Repositorio para el módulo de contactos.

Este módulo implementa la capa de acceso a datos para contactos y grupos de contactos,
utilizando SQLAlchemy con soporte asíncrono y el patrón Result para manejo funcional de errores.
"""

import logging
from datetime import datetime
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
    ) -> Result[List[Contact], DatabaseError]:
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
        try:
            # Construir consulta base
            query = select(Contact).where(Contact.owner_id == owner_id)

            # Aplicar filtros si se proporcionan
            if group_id is not None:
                # Unir con la tabla de miembros de grupo para filtrar por grupo
                query = query.join(
                    contact_group_members,
                    Contact.id == contact_group_members.c.contact_id,
                ).where(contact_group_members.c.group_id == group_id)

            if search is not None:
                # Filtro de búsqueda en múltiples campos
                search_filter = or_(
                    Contact.first_name.ilike(f"%{search}%"),
                    Contact.last_name.ilike(f"%{search}%"),
                    Contact.email.ilike(f"%{search}%"),
                    Contact.phone.ilike(f"%{search}%"),
                    Contact.company.ilike(f"%{search}%"),
                    Contact.position.ilike(f"%{search}%"),
                    Contact.address.ilike(f"%{search}%"),
                    Contact.notes.ilike(f"%{search}%"),
                )
                query = query.where(search_filter)

            if contact_type is not None:
                query = query.where(Contact.contact_type == contact_type)

            if status is not None:
                query = query.where(Contact.status == status)

            if is_favorite is not None:
                query = query.where(Contact.is_favorite == is_favorite)

            # Aplicar paginación
            query = query.offset(skip).limit(limit)

            # Cargar los grupos de contactos con cada contacto
            query = query.options(selectinload(Contact.groups))

            # Ejecutar consulta
            result = await db.execute(query)
            contacts = result.scalars().all()

            return Success(list(contacts))
        except SQLAlchemyError as e:
            logger.error(f"Error al listar contactos: {str(e)}")
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
        try:
            # Validar que haya al menos un nombre o apellido
            if first_name is None and last_name is None:
                return Failure(
                    ContactValidationError(
                        {"name": "Al menos un nombre o apellido debe estar presente"}
                    )
                )

            # Si se proporciona un email, verificar que no exista otro contacto con el mismo email para este usuario
            if email is not None:
                existing_contact_result = await ContactRepository.get_by_email(
                    db, email, owner_id
                )
                if existing_contact_result.is_success():
                    return Failure(ContactAlreadyExistsError(email))

            # Crear el nuevo contacto
            new_contact = Contact(
                owner_id=owner_id,
                first_name=first_name,
                last_name=last_name,
                email=email,
                phone=phone,
                company=company,
                position=position,
                contact_type=contact_type if contact_type is not None else "other",
                status=status if status is not None else "active",
                is_favorite=is_favorite,
                address=address,
                notes=notes,
                custom_fields=custom_fields,
                contact_user_id=contact_user_id,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow(),
            )

            db.add(new_contact)
            await db.flush()  # Para obtener el ID generado

            return Success(new_contact)
        except IntegrityError as e:
            await db.rollback()
            logger.error(f"Error de integridad al crear contacto: {str(e)}")
            if "unique constraint" in str(e).lower() and "email" in str(e).lower():
                return Failure(ContactAlreadyExistsError(email or ""))
            return Failure(DatabaseError(str(e)))

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
        try:
            # Verificar que el contacto existe y pertenece al usuario
            contact_result = await ContactRepository.get_by_id(db, contact_id, owner_id)
            if contact_result.is_failure():
                return contact_result

            contact = contact_result.unwrap()

            # Si se está actualizando el email, verificar que no exista otro contacto con ese email
            if (
                "email" in kwargs
                and kwargs["email"] is not None
                and kwargs["email"] != contact.email
            ):
                existing_contact_result = await ContactRepository.get_by_email(
                    db, kwargs["email"], owner_id
                )
                if existing_contact_result.is_success():
                    return Failure(ContactAlreadyExistsError(kwargs["email"]))

            # Actualizar campos
            for key, value in kwargs.items():
                if hasattr(contact, key) and key not in [
                    "id",
                    "owner_id",
                    "created_at",
                ]:
                    setattr(contact, key, value)

            # Actualizar fecha de modificación
            contact.updated_at = datetime.utcnow()

            await db.flush()

            return Success(contact)
        except IntegrityError as e:
            await db.rollback()
            logger.error(
                f"Error de integridad al actualizar contacto {contact_id}: {str(e)}"
            )
            if "unique constraint" in str(e).lower() and "email" in str(e).lower():
                return Failure(ContactAlreadyExistsError(kwargs.get("email", "") or ""))
            return Failure(DatabaseError(str(e)))

        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al actualizar contacto {contact_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))

    @staticmethod
    async def delete(
        db: AsyncSession,
        contact_id: int,
        owner_id: int,
    ) -> Result[
        None, ContactNotFoundError | UnauthorizedContactAccessError | DatabaseError
    ]:
        """
        Elimina un contacto existente.

        Args:
            db: Sesión de base de datos asíncrona.
            contact_id: ID del contacto a eliminar.
            owner_id: ID del usuario propietario del contacto.

        Returns:
            Result con None si la eliminación es exitosa, o un error apropiado si no.
        """
        try:
            # Verificar que el contacto existe y pertenece al usuario
            contact_result = await ContactRepository.get_by_id(db, contact_id, owner_id)
            if contact_result.is_failure():
                return contact_result

            contact = contact_result.unwrap()

            # Eliminar el contacto
            await db.delete(contact)
            await db.flush()

            return Success(None)
        except SQLAlchemyError as e:
            await db.rollback()
            logger.error(f"Error al eliminar contacto {contact_id}: {str(e)}")
            return Failure(DatabaseError(str(e)))
