"""
Repositorio para operaciones de base de datos relacionadas con usuarios.

Este módulo proporciona funciones para interactuar con la tabla de usuarios
en la base de datos, siguiendo el patrón de repositorio.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, TYPE_CHECKING
from uuid import UUID

from sqlalchemy import delete, or_, select, update
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.errors import DatabaseError, ResourceNotFoundError # ValidationError ya no se usará aquí para duplicados
from app.users.errors import UserAlreadyExistsError, UserNotFoundError, VerificationTokenNotFoundError # Nuevo error específico
from app.common.result import Result, Success, Failure # Para el patrón Result
if TYPE_CHECKING:
    from app.users.models import User, VerificationToken
from app.users.schemas import UserInDB, VerificationTokenCreateInternal, VerificationTokenInDB # UserCreate y UserUpdate ya no se usan como parámetros directos aquí
from pydantic import EmailStr # Importar explícitamente

logger = logging.getLogger(__name__)


class UserRepository:
    """Repositorio para operaciones de base de datos de usuarios."""

    def __init__(self, db: AsyncSession):
        """Inicializa el repositorio con una sesión de base de datos."""
        self.db = db

    async def create(
        self,
        email: EmailStr,
        hashed_password: str,
        full_name: Optional[str] = None,
        is_active: bool = True,
        is_superuser: bool = False,
        is_verified: bool = False,
    ) -> Result[UserInDB, UserAlreadyExistsError | DatabaseError]:
        """
        Crea un nuevo usuario en la base de datos.

        Args:
            email: Correo electrónico del usuario.
            hashed_password: Contraseña hasheada del usuario.
            full_name: Nombre completo del usuario (opcional).
            is_active: Estado de actividad del usuario.
            is_superuser: Si el usuario es superusuario.
            is_verified: Si el correo del usuario ha sido verificado.

        Returns:
            Result con el usuario creado (UserInDB) o un error.

        Raises:
            # Este método ahora devuelve Result y no lanza excepciones directamente.
            # Las excepciones de SQLAlchemy se capturan y se convierten en Failure(AppError).
            None
        """
        from app.users.models import User # Local import
        try:
            # Verificar si ya existe un usuario con el mismo correo
            # (Esta lógica de get_by_email también será refactorizada luego)
            existing_user_stmt = select(User).where(User.email == email)
            existing_user_result = await self.db.execute(existing_user_stmt)
            if existing_user_result.scalar_one_or_none():
                return Failure(UserAlreadyExistsError(email=email))

            db_user = User(
                email=email,
                hashed_password=hashed_password,
                full_name=full_name, # NOTA: El modelo User tiene first_name, last_name.
                                     # El servicio deberá manejar la conversión de full_name
                                     # a first_name/last_name si es necesario antes de llamar aquí,
                                     # o este repositorio debería aceptar first_name/last_name.
                is_active=is_active,
                is_superuser=is_superuser,
                is_verified=is_verified,
            )

            self.db.add(db_user)
            await self.db.commit()
            await self.db.refresh(db_user)

            return Success(UserInDB.model_validate(db_user))

        except IntegrityError as e:
            await self.db.rollback()
            logger.error(f"Error de integridad al crear usuario {email}: {e.detail}", exc_info=True)
            return Failure(DatabaseError(detail=f"Conflicto de datos al crear usuario: {email}"))
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error de base de datos al crear usuario {email}: {str(e)}", exc_info=True)
            return Failure(DatabaseError(detail=f"Error de base de datos al crear usuario: {email}"))

    async def get_by_id(self, user_id: int) -> Result[UserInDB, UserNotFoundError | DatabaseError]:
        """
        Obtiene un usuario por su ID.

        Args:
            user_id: ID del usuario a buscar.

        Returns:
            Result con el usuario encontrado (UserInDB) o un error UserNotFoundError/DatabaseError.
        """
        from app.users.models import User # Local import
        try:
            result = await self.db.execute(select(User).where(User.id == user_id))
            user_model = result.scalar_one_or_none()

            if not user_model:
                return Failure(UserNotFoundError(user_id=user_id))

            return Success(UserInDB.model_validate(user_model))

        except SQLAlchemyError as e:
            logger.error(f"Error de base de datos al obtener usuario por ID {user_id}: {str(e)}", exc_info=True)
            return Failure(DatabaseError(detail=f"Error de base de datos al obtener usuario por ID: {user_id}"))

    async def get_by_email(self, email: EmailStr) -> Result[UserInDB, UserNotFoundError | DatabaseError]:
        """
        Obtiene un usuario por su correo electrónico.

        Args:
            email: Correo electrónico del usuario a buscar.

        Returns:
            Result con el usuario encontrado (UserInDB) o un error UserNotFoundError/DatabaseError.
        """
        from app.users.models import User # Local import
        try:
            result = await self.db.execute(select(User).where(User.email == email))
            user_model = result.scalar_one_or_none()

            if not user_model:
                return Failure(UserNotFoundError(email=email))

            return Success(UserInDB.model_validate(user_model))

        except SQLAlchemyError as e:
            logger.error(f"Error de base de datos al obtener usuario por email {email}: {str(e)}", exc_info=True)
            return Failure(DatabaseError(detail=f"Error de base de datos al obtener usuario por email: {email}"))

    async def update(
        self,
        user_id: int,
        email: Optional[EmailStr] = None,
        full_name: Optional[str] = None, # O first_name/last_name según el modelo
        hashed_password: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_superuser: Optional[bool] = None, # Si se permite actualizar
        is_verified: Optional[bool] = None,
    ) -> Result[UserInDB, UserNotFoundError | UserAlreadyExistsError | DatabaseError]:
        """
        Actualiza un usuario existente.
        Espera que la contraseña (si se proporciona) ya esté hasheada.

        Args:
            user_id: ID del usuario a actualizar.
            email: Nuevo correo electrónico (opcional).
            full_name: Nuevo nombre completo (opcional).
            hashed_password: Nueva contraseña hasheada (opcional).
            is_active: Nuevo estado de actividad (opcional).
            is_superuser: Nuevo estado de superusuario (opcional).
            is_verified: Nuevo estado de verificación (opcional).

        Returns:
            Result con el usuario actualizado (UserInDB) o un error.
        """
        from app.users.models import User # Local import
        try:
            # Obtener el usuario existente (modelo SQLAlchemy)
            user_model_to_update = await self.db.get(User, user_id)
            if not user_model_to_update:
                 return Failure(UserNotFoundError(user_id=user_id))

            update_values: Dict[str, Any] = {}
            if email is not None and email != user_model_to_update.email:
                # Verificar si el nuevo email ya está en uso por OTRO usuario
                existing_email_stmt = select(User).where(User.email == email, User.id != user_id)
                existing_email_result = await self.db.execute(existing_email_stmt)
                if existing_email_result.scalar_one_or_none():
                    return Failure(UserAlreadyExistsError(email=email))
                update_values["email"] = email
            
            if full_name is not None and hasattr(User, "full_name") and full_name != getattr(user_model_to_update, "full_name", None):
                 update_values["full_name"] = full_name

            if hashed_password is not None:
                update_values["hashed_password"] = hashed_password
            if is_active is not None and is_active != user_model_to_update.is_active:
                update_values["is_active"] = is_active
            if is_superuser is not None and is_superuser != user_model_to_update.is_superuser:
                update_values["is_superuser"] = is_superuser
            if is_verified is not None and is_verified != user_model_to_update.is_verified:
                update_values["is_verified"] = is_verified

            if not update_values: # No hay nada que actualizar
                return Success(UserInDB.model_validate(user_model_to_update))

            update_values["updated_at"] = datetime.utcnow() # Actualizar manualmente

            stmt = (
                update(User)
                .where(User.id == user_id)
                .values(**update_values)
                .returning(User)
            )
            result = await self.db.execute(stmt)
            await self.db.commit()
            
            updated_user_model = result.scalar_one() # scalar_one() porque returning(User) y esperamos que exista
            return Success(UserInDB.model_validate(updated_user_model))

        except IntegrityError as e:
            await self.db.rollback()
            logger.error(f"Error de integridad al actualizar usuario {user_id}: {e.detail}", exc_info=True)
            return Failure(DatabaseError(detail=f"Conflicto de datos al actualizar usuario {user_id}"))
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error de base de datos al actualizar usuario {user_id}: {str(e)}", exc_info=True)
            return Failure(DatabaseError(detail=f"Error de base de datos al actualizar usuario {user_id}"))

    async def delete(self, user_id: int) -> Result[bool, UserNotFoundError | DatabaseError]:
        """
        Elimina un usuario por su ID.

        Args:
            user_id: ID del usuario a eliminar.

        Returns:
            Result con True si se eliminó correctamente, o un error UserNotFoundError/DatabaseError.
        """
        from app.users.models import User # Local import
        try:
            # Verificar primero si el usuario existe para devolver un error claro si no.
            user_to_delete = await self.db.get(User, user_id)
            if not user_to_delete:
                return Failure(UserNotFoundError(user_id=user_id))

            # Si existe, proceder a eliminar
            stmt = delete(User).where(User.id == user_id)
            result = await self.db.execute(stmt)
            await self.db.commit()

            if result.rowcount == 0:
                # Esto es inesperado si la comprobación anterior tuvo éxito.
                # Podría indicar una condición de carrera o que el usuario fue eliminado
                # entre la comprobación y la operación de eliminación.
                logger.warning(
                    f"Intento de eliminar usuario {user_id} resultó en 0 filas afectadas "
                    "después de una comprobación de existencia exitosa."
                )
                # Consideramos esto como si el usuario ya no estuviera allí.
                return Failure(UserNotFoundError(user_id=user_id)) # O un error diferente si se prefiere
            
            return Success(True) # Eliminación exitosa

        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error de base de datos al eliminar usuario {user_id}: {str(e)}", exc_info=True)
            return Failure(DatabaseError(detail=f"Error de base de datos al eliminar el usuario {user_id}"))

    async def list_users(
        self,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_verified: Optional[bool] = None,
    ) -> Result[List[UserInDB], DatabaseError]:
        """
        Lista usuarios con paginación y filtros opcionales.

        Args:
            skip: Número de registros a omitir (para paginación).
            limit: Número máximo de registros a devolver.
            search: Texto para buscar en nombre o correo.
            is_active: Filtrar por estado activo/inactivo.
            is_verified: Filtrar por estado de verificación.

        Returns:
            Result con una lista de usuarios (List[UserInDB]) o un DatabaseError.
        """
        from app.users.models import User # Local import
        try:
            query = select(User)

            # Aplicar filtros
            if search:
                search_term = f"%{search}%"
                query = query.where(
                    or_(
                        User.email.ilike(search_term), 
                        User.first_name.ilike(search_term), 
                        User.last_name.ilike(search_term)
                    )
                )

            if is_active is not None:
                query = query.where(User.is_active == is_active)

            if is_verified is not None:
                query = query.where(User.is_verified == is_verified)

            # Aplicar paginación
            query = query.offset(skip).limit(limit).order_by(User.id)

            # Ejecutar consulta
            result_proxy = await self.db.execute(query)
            user_models = result_proxy.scalars().all()
            
            return Success([UserInDB.model_validate(user) for user in user_models])

        except SQLAlchemyError as e:
            logger.error(f"Error de base de datos al listar usuarios: {str(e)}", exc_info=True)
            return Failure(DatabaseError(detail="Error de base de datos al listar usuarios"))

    async def count(
        self,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_verified: Optional[bool] = None,
    ) -> Result[int, DatabaseError]:
        """
        Cuenta el número total de usuarios que coinciden con los filtros.

        Args:
            search: Texto para buscar en nombre o correo.
            is_active: Filtrar por estado activo/inactivo.
            is_verified: Filtrar por estado de verificación.

        Returns:
            Result con el número total de usuarios (int) o un DatabaseError.
        """
        try:
            from sqlalchemy import func

            query = select(func.count(User.id))

            # Aplicar filtros (deben coincidir con los de list_users)
            if search:
                # search_term = f"%{search.lower()}%" # No es necesario el lower() aquí si se usa en la columna
                query = query.where(
                    or_(
                        User.email.ilike(f"%{search}%"), # ilike ya es case-insensitive para PostgreSQL
                        func.lower(User.first_name + " " + User.last_name).contains(search.lower())
                    )
                )

            if is_active is not None:
                query = query.where(User.is_active == is_active)

            if is_verified is not None:
                query = query.where(User.is_verified == is_verified)

            # Ejecutar consulta
            result = await self.db.execute(query)
            count_value = result.scalar_one()
            return Success(count_value)

        except SQLAlchemyError as e:
            logger.error(f"Error de base de datos al contar usuarios: {str(e)}", exc_info=True)
            return Failure(DatabaseError(detail="Error de base de datos al contar usuarios"))

    async def update_last_login(
        self, user_id: int
    ) -> Result[None, UserNotFoundError | DatabaseError]:
        """
        Actualiza la fecha del último inicio de sesión de un usuario.

        Args:
            user_id: ID del usuario.

        Returns:
            Result con None si la actualización fue exitosa, o un error UserNotFoundError/DatabaseError.
        """
        try:
            stmt = (
                update(User)
                .where(User.id == user_id)
                .values(last_login_at=datetime.utcnow())  # Corregido: last_login_at
            )
            result = await self.db.execute(stmt)
            
            if result.rowcount == 0:
                # Si rowcount es 0, el usuario con user_id no fue encontrado para actualizar.
                logger.warning(f"Intento de actualizar last_login_at para usuario inexistente o sin cambios: {user_id}")
                return Failure(UserNotFoundError(user_id=user_id))

            await self.db.commit()
            return Success(None)

        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(
                f"Error de base de datos al actualizar último inicio de sesión para usuario {user_id}: {str(e)}",
                exc_info=True
            )
            return Failure(DatabaseError(detail=f"Error de BD al actualizar último login para usuario {user_id}"))

    async def update_password(
        self, user_id: int, hashed_password: str
    ) -> Result[None, UserNotFoundError | DatabaseError]:
        """
        Actualiza la contraseña de un usuario.

        Args:
            user_id: ID del usuario.
            hashed_password: Nueva contraseña ya hasheada.

        Returns:
            Result con None si la actualización fue exitosa, o un error UserNotFoundError/DatabaseError.
        """
        try:
            stmt = (
                update(User)
                .where(User.id == user_id)
                .values(
                    hashed_password=hashed_password,
                    updated_at=datetime.utcnow()  # Actualizar timestamp
                )
            )
            result = await self.db.execute(stmt)

            if result.rowcount == 0:
                logger.warning(f"Intento de actualizar contraseña para usuario inexistente: {user_id}")
                return Failure(UserNotFoundError(user_id=user_id))

            await self.db.commit()
            return Success(None)

        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(
                f"Error de base de datos al actualizar contraseña para usuario {user_id}: {str(e)}",
                exc_info=True
            )
            return Failure(DatabaseError(detail=f"Error de BD al actualizar contraseña para usuario {user_id}"))

    async def create_verification_token(
        self, token_data: VerificationTokenCreateInternal
    ) -> Result[VerificationTokenInDB, DatabaseError]:
        """
        Crea un nuevo token de verificación en la base de datos.
        """
        from app.users.models import VerificationToken # Local import
        try:
            new_token = VerificationToken(
                token=token_data.token,
                user_id=token_data.user_id,
                token_type=token_data.token_type,
                expires_at=token_data.expires_at,
                is_used=False, # Por defecto al crear
            )
            self.db.add(new_token)
            await self.db.flush() # Para obtener el ID y otros campos generados por la BD
            await self.db.refresh(new_token)
            
            # Convertir a esquema Pydantic para el retorno
            token_in_db = VerificationTokenInDB.from_attributes(new_token) # Usar from_attributes para Pydantic v2
            return Success(token_in_db)
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(
                f"Error de base de datos al crear token de verificación para usuario {token_data.user_id}: {str(e)}",
                exc_info=True
            )
            return Failure(DatabaseError(detail=f"Error de BD al crear token para usuario {token_data.user_id}"))
        except Exception as e: # Captura general por si from_attributes falla u otra cosa
            await self.db.rollback()
            logger.error(
                f"Error inesperado al crear token de verificación para usuario {token_data.user_id}: {str(e)}",
                exc_info=True
            )
            return Failure(DatabaseError(detail=f"Error inesperado al crear token para usuario {token_data.user_id}"))

    async def get_verification_token_by_value(
        self, token_value: str
    ) -> Result[VerificationTokenInDB, VerificationTokenNotFoundError | DatabaseError]:
        """
        Obtiene un token de verificación por su valor (string).
        """
        from app.users.models import VerificationToken # Local import
        try:
            stmt = select(VerificationToken).where(VerificationToken.token == token_value)
            result = await self.db.execute(stmt)
            token_model = result.scalar_one_or_none()

            if not token_model:
                return Failure(VerificationTokenNotFoundError(token_value=token_value))
            
            return Success(VerificationTokenInDB.from_attributes(token_model))
        except SQLAlchemyError as e:
            logger.error(
                f"Error de BD al obtener token de verificación por valor '{token_value[:10]}...': {str(e)}",
                exc_info=True
            )
            return Failure(DatabaseError(detail=f"Error de BD al buscar token"))

    async def mark_verification_token_as_used(
        self, token_id: int
    ) -> Result[VerificationTokenInDB, VerificationTokenNotFoundError | DatabaseError]:
        """
        Marca un token de verificación como usado.
        """
        from app.users.models import VerificationToken # Local import
        try:
            token_model = await self.db.get(VerificationToken, token_id)
            if not token_model:
                return Failure(VerificationTokenNotFoundError(criteria=f"ID {token_id}"))

            if token_model.is_used:
                logger.info(f"Token ID {token_id} ya estaba marcado como usado.")
                return Success(VerificationTokenInDB.from_attributes(token_model))

            token_model.is_used = True
            # token_model.updated_at = datetime.utcnow() # Si VerificationToken tiene updated_at
            
            self.db.add(token_model)
            await self.db.flush()
            await self.db.refresh(token_model)
            
            return Success(VerificationTokenInDB.from_attributes(token_model))
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(
                f"Error de BD al marcar token ID {token_id} como usado: {str(e)}",
                exc_info=True
            )
            return Failure(DatabaseError(detail=f"Error de BD al actualizar estado de token"))

