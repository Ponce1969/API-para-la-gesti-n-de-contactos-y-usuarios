"""
Repositorio para operaciones de base de datos relacionadas con usuarios.

Este módulo proporciona funciones para interactuar con la tabla de usuarios
en la base de datos, siguiendo el patrón de repositorio.
"""
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
import logging

from sqlalchemy import select, update, delete, or_
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.exc import SQLAlchemyError, IntegrityError

from app.users.models import User
from app.users.schemas import UserCreate, UserUpdate, UserInDB
from app.common.errors import DatabaseError, ResourceNotFoundError, ValidationError

logger = logging.getLogger(__name__)

class UserRepository:
    """Repositorio para operaciones de base de datos de usuarios."""
    
    def __init__(self, db: AsyncSession):
        """Inicializa el repositorio con una sesión de base de datos."""
        self.db = db
    
    async def create(self, user_data: UserCreate) -> UserInDB:
        """
        Crea un nuevo usuario en la base de datos.
        
        Args:
            user_data: Datos del usuario a crear.
            
        Returns:
            UserInDB: El usuario creado.
            
        Raises:
            DatabaseError: Si ocurre un error al crear el usuario.
            ValidationError: Si ya existe un usuario con el mismo correo.
        """
        try:
            # Verificar si ya existe un usuario con el mismo correo
            existing_user = await self.get_by_email(user_data.email)
            if existing_user:
                raise ValidationError("Ya existe un usuario con este correo electrónico")
            
            # Crear el usuario
            db_user = User(
                email=user_data.email,
                full_name=user_data.full_name,
                hashed_password=user_data.password,  # La contraseña ya debe estar hasheada
                is_active=user_data.is_active,
                is_superuser=user_data.is_superuser,
                is_verified=user_data.is_verified,
            )
            
            self.db.add(db_user)
            await self.db.commit()
            await self.db.refresh(db_user)
            
            return UserInDB.model_validate(db_user.__dict__)
            
        except IntegrityError as e:
            await self.db.rollback()
            logger.error(f"Error de integridad al crear usuario: {str(e)}")
            raise ValidationError("Error de validación al crear el usuario") from e
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error de base de datos al crear usuario: {str(e)}")
            raise DatabaseError("Error al crear el usuario") from e
    
    async def get_by_id(self, user_id: int) -> Optional[UserInDB]:
        """
        Obtiene un usuario por su ID.
        
        Args:
            user_id: ID del usuario a buscar.
            
        Returns:
            Optional[UserInDB]: El usuario encontrado o None si no existe.
            
        Raises:
            DatabaseError: Si ocurre un error al consultar la base de datos.
        """
        try:
            result = await self.db.execute(
                select(User).where(User.id == user_id)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                return None
                
            return UserInDB.model_validate(user.__dict__)
            
        except SQLAlchemyError as e:
            logger.error(f"Error al obtener usuario por ID {user_id}: {str(e)}")
            raise DatabaseError("Error al obtener el usuario") from e
    
    async def get_by_email(self, email: str) -> Optional[UserInDB]:
        """
        Obtiene un usuario por su correo electrónico.
        
        Args:
            email: Correo electrónico del usuario a buscar.
            
        Returns:
            Optional[UserInDB]: El usuario encontrado o None si no existe.
            
        Raises:
            DatabaseError: Si ocurre un error al consultar la base de datos.
        """
        try:
            result = await self.db.execute(
                select(User).where(User.email == email)
            )
            user = result.scalar_one_or_none()
            
            if not user:
                return None
                
            return UserInDB.model_validate(user.__dict__)
            
        except SQLAlchemyError as e:
            logger.error(f"Error al obtener usuario por email {email}: {str(e)}")
            raise DatabaseError("Error al obtener el usuario por correo") from e
    
    async def update(self, user_id: int, user_data: UserUpdate) -> Optional[UserInDB]:
        """
        Actualiza un usuario existente.
        
        Args:
            user_id: ID del usuario a actualizar.
            user_data: Datos a actualizar.
            
        Returns:
            Optional[UserInDB]: El usuario actualizado o None si no se encontró.
            
        Raises:
            DatabaseError: Si ocurre un error al actualizar el usuario.
            ValidationError: Si los datos no son válidos.
        """
        try:
            # Obtener el usuario existente
            existing_user = await self.get_by_id(user_id)
            if not existing_user:
                return None
            
            # Preparar los datos a actualizar
            update_data = user_data.model_dump(exclude_unset=True)
            
            # Si se está actualizando el correo, verificar que no esté en uso
            if 'email' in update_data and update_data['email'] != existing_user.email:
                if await self.get_by_email(update_data['email']):
                    raise ValidationError("El correo electrónico ya está en uso")
            
            # Actualizar el usuario
            result = await self.db.execute(
                update(User)
                .where(User.id == user_id)
                .values(**update_data)
                .returning(User)
            )
            
            await self.db.commit()
            
            updated_user = result.scalar_one_or_none()
            if not updated_user:
                return None
                
            return UserInDB.model_validate(updated_user.__dict__)
            
        except IntegrityError as e:
            await self.db.rollback()
            logger.error(f"Error de integridad al actualizar usuario: {str(e)}")
            raise ValidationError("Error de validación al actualizar el usuario") from e
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error de base de datos al actualizar usuario: {str(e)}")
            raise DatabaseError("Error al actualizar el usuario") from e
    
    async def delete(self, user_id: int) -> bool:
        """
        Elimina un usuario por su ID.
        
        Args:
            user_id: ID del usuario a eliminar.
            
        Returns:
            bool: True si se eliminó correctamente, False si no se encontró el usuario.
            
        Raises:
            DatabaseError: Si ocurre un error al eliminar el usuario.
        """
        try:
            result = await self.db.execute(
                delete(User).where(User.id == user_id)
            )
            await self.db.commit()
            
            return result.rowcount > 0
            
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error al eliminar usuario con ID {user_id}: {str(e)}")
            raise DatabaseError("Error al eliminar el usuario") from e
    
    async def list_users(
        self,
        skip: int = 0,
        limit: int = 100,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_verified: Optional[bool] = None,
    ) -> List[UserInDB]:
        """
        Lista usuarios con paginación y filtros opcionales.
        
        Args:
            skip: Número de registros a omitir (para paginación).
            limit: Número máximo de registros a devolver.
            search: Texto para buscar en nombre o correo.
            is_active: Filtrar por estado activo/inactivo.
            is_verified: Filtrar por estado de verificación.
            
        Returns:
            List[UserInDB]: Lista de usuarios que coinciden con los criterios.
            
        Raises:
            DatabaseError: Si ocurre un error al consultar la base de datos.
        """
        try:
            query = select(User)
            
            # Aplicar filtros
            if search:
                search_term = f"%{search}%"
                query = query.where(
                    or_(
                        User.email.ilike(search_term),
                        User.full_name.ilike(search_term)
                    )
                )
                
            if is_active is not None:
                query = query.where(User.is_active == is_active)
                
            if is_verified is not None:
                query = query.where(User.is_verified == is_verified)
            
            # Aplicar paginación
            query = query.offset(skip).limit(limit)
            
            # Ejecutar consulta
            result = await self.db.execute(query)
            users = result.scalars().all()
            
            return [UserInDB.model_validate(user.__dict__) for user in users]
            
        except SQLAlchemyError as e:
            logger.error(f"Error al listar usuarios: {str(e)}")
            raise DatabaseError("Error al listar usuarios") from e
    
    async def count(
        self,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_verified: Optional[bool] = None,
    ) -> int:
        """
        Cuenta el número total de usuarios que coinciden con los filtros.
        
        Args:
            search: Texto para buscar en nombre o correo.
            is_active: Filtrar por estado activo/inactivo.
            is_verified: Filtrar por estado de verificación.
            
        Returns:
            int: Número total de usuarios que coinciden con los criterios.
            
        Raises:
            DatabaseError: Si ocurre un error al consultar la base de datos.
        """
        try:
            from sqlalchemy import func
            
            query = select(func.count(User.id))
            
            # Aplicar filtros (deben coincidir con los de list_users)
            if search:
                search_term = f"%{search}%"
                query = query.where(
                    or_(
                        User.email.ilike(search_term),
                        User.full_name.ilike(search_term)
                    )
                )
                
            if is_active is not None:
                query = query.where(User.is_active == is_active)
                
            if is_verified is not None:
                query = query.where(User.is_verified == is_verified)
            
            # Ejecutar consulta
            result = await self.db.execute(query)
            return result.scalar_one()
            
        except SQLAlchemyError as e:
            logger.error(f"Error al contar usuarios: {str(e)}")
            raise DatabaseError("Error al contar usuarios") from e
    
    async def update_last_login(self, user_id: int) -> None:
        """
        Actualiza la fecha del último inicio de sesión de un usuario.
        
        Args:
            user_id: ID del usuario.
            
        Raises:
            DatabaseError: Si ocurre un error al actualizar la base de datos.
        """
        try:
            await self.db.execute(
                update(User)
                .where(User.id == user_id)
                .values(last_login=datetime.utcnow())
            )
            await self.db.commit()
            
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error al actualizar último inicio de sesión: {str(e)}")
            raise DatabaseError("Error al actualizar el último inicio de sesión") from e
    
    async def update_password(self, user_id: int, hashed_password: str) -> None:
        """
        Actualiza la contraseña de un usuario.
        
        Args:
            user_id: ID del usuario.
            hashed_password: Nueva contraseña ya hasheada.
            
        Raises:
            DatabaseError: Si ocurre un error al actualizar la contraseña.
        """
        try:
            await self.db.execute(
                update(User)
                .where(User.id == user_id)
                .values(hashed_password=hashed_password)
            )
            await self.db.commit()
            
        except SQLAlchemyError as e:
            await self.db.rollback()
            logger.error(f"Error al actualizar contraseña: {str(e)}")
            raise DatabaseError("Error al actualizar la contraseña") from e