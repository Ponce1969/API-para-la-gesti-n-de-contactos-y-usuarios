"""
Repositorio para el dominio de roles.

Este módulo proporciona acceso a la base de datos para el dominio de roles,
implementando operaciones CRUD básicas y consultas especializadas.
"""

from datetime import datetime, timezone # Import timezone
from typing import List, Optional, Tuple, Dict, Any

from returns.result import Result, Success, Failure
from sqlalchemy import select, insert, update, delete, and_, or_, func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.errors import DatabaseError
from app.roles.errors import (
    RoleNotFoundError,
    RoleAlreadyExistsError,
    PermissionNotFoundError,
    PermissionAlreadyExistsError,
    RoleDeleteError,
    SystemRoleModificationError,
    RoleAssignmentError,
    PermissionAssignmentError
)
from app.roles.models import Role, Permission, role_permissions, user_roles


class RoleRepository:
    """Repositorio para operaciones CRUD de roles."""

    @staticmethod
    async def get_by_id(
        db: AsyncSession, role_id: int
    ) -> Result[Role, RoleNotFoundError]:
        """
        Obtiene un rol por su ID.

        Args:
            db: Sesión de base de datos.
            role_id: ID del rol a buscar.

        Returns:
            Result[Role, RoleNotFoundError]: Un Result que contiene el rol si se encuentra,
            o un RoleNotFoundError si no existe.
        """
        try:
            query = select(Role).where(Role.id == role_id)
            result = await db.execute(query)
            role = result.scalars().first()

            if role is None:
                return Failure(RoleNotFoundError(role_id=role_id))

            return Success(role)
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener rol: {str(e)}"))

    @staticmethod
    async def get_by_name(
        db: AsyncSession, name: str
    ) -> Result[Role, RoleNotFoundError]:
        """
        Obtiene un rol por su nombre.

        Args:
            db: Sesión de base de datos.
            name: Nombre del rol a buscar.

        Returns:
            Result[Role, RoleNotFoundError]: Un Result que contiene el rol si se encuentra,
            o un RoleNotFoundError si no existe.
        """
        try:
            query = select(Role).where(func.lower(Role.name) == func.lower(name))
            result = await db.execute(query)
            role = result.scalars().first()

            if role is None:
                return Failure(RoleNotFoundError(role_name=name))

            return Success(role)
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener rol: {str(e)}"))

    @staticmethod
    async def get_all(
        db: AsyncSession, 
        skip: int = 0, 
        limit: int = 100,
        include_inactive: bool = False
    ) -> Result[List[Role], DatabaseError]:
        """
        Obtiene todos los roles con paginación.

        Args:
            db: Sesión de base de datos.
            skip: Número de registros a saltar para paginación.
            limit: Límite de registros a retornar.
            include_inactive: Si es True, incluye roles inactivos.

        Returns:
            Result[List[Role], DatabaseError]: Un Result que contiene la lista de roles,
            o un DatabaseError si ocurre un error.
        """
        try:
            query = select(Role)
            if not include_inactive:
                query = query.where(Role.is_active == True)
            
            query = query.offset(skip).limit(limit)
            result = await db.execute(query)
            roles = result.scalars().all()

            return Success(list(roles))
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener roles: {str(e)}"))

    @staticmethod
    async def create(
        db: AsyncSession, 
        name: str, 
        description: Optional[str] = None,
        is_system: bool = False
    ) -> Result[Role, RoleAlreadyExistsError]:
        """
        Crea un nuevo rol.

        Args:
            db: Sesión de base de datos.
            name: Nombre del rol.
            description: Descripción del rol.
            is_system: Indica si es un rol del sistema.

        Returns:
            Result[Role, RoleAlreadyExistsError]: Un Result que contiene el rol creado,
            o un RoleAlreadyExistsError si ya existe un rol con ese nombre.
        """
        try:
            # Verificar si ya existe un rol con el mismo nombre
            name_exists_result = await RoleRepository.get_by_name(db, name)
            if name_exists_result.is_success():
                return Failure(RoleAlreadyExistsError(role_name=name))

            # Crear el nuevo rol
            new_role = Role(
                name=name,
                description=description,
                is_system=is_system,
                is_active=True,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            db.add(new_role)
            await db.flush()  # Para obtener el ID asignado

            return Success(new_role)
        except IntegrityError as e:
            await db.rollback()
            if "unique constraint" in str(e).lower() and "name" in str(e).lower():
                return Failure(RoleAlreadyExistsError(role_name=name))
            return Failure(DatabaseError(detail=f"Error de integridad al crear rol: {str(e)}"))
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error al crear rol: {str(e)}"))

    @staticmethod
    async def update(
        db: AsyncSession,
        role_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None,
        is_active: Optional[bool] = None
    ) -> Result[Role, RoleNotFoundError | SystemRoleModificationError | RoleAlreadyExistsError]:
        """
        Actualiza un rol existente.

        Args:
            db: Sesión de base de datos.
            role_id: ID del rol a actualizar.
            name: Nuevo nombre del rol.
            description: Nueva descripción del rol.
            is_active: Nuevo estado de activación del rol.

        Returns:
            Result[Role, Error]: Un Result que contiene el rol actualizado,
            o un error si no se encuentra el rol, se intenta modificar un rol del sistema,
            o ya existe otro rol con el nuevo nombre.
        """
        try:
            # Obtener el rol existente
            role_result = await RoleRepository.get_by_id(db, role_id)
            if role_result.is_failure():
                return role_result

            role = role_result.unwrap()

            # Verificar si es un rol del sistema y se está intentando modificar campos protegidos
            if role.is_system and (name is not None or is_active is not None):
                return Failure(SystemRoleModificationError(role_id=role_id))

            # Verificar si el nuevo nombre ya existe (solo si se está cambiando)
            if name is not None and name != role.name:
                name_exists_result = await RoleRepository.get_by_name(db, name)
                if name_exists_result.is_success():
                    return Failure(RoleAlreadyExistsError(role_name=name))

            # Actualizar campos
            if name is not None:
                role.name = name
            if description is not None:
                role.description = description
            if is_active is not None:
                role.is_active = is_active

            role.updated_at = datetime.now(timezone.utc)
            await db.flush()

            return Success(role)
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error al actualizar rol: {str(e)}"))

    @staticmethod
    async def delete(
        db: AsyncSession, role_id: int
    ) -> Result[bool, RoleNotFoundError | SystemRoleModificationError | RoleDeleteError]:
        """
        Elimina un rol de la base de datos.

        Args:
            db: Sesión de base de datos.
            role_id: ID del rol a eliminar.

        Returns:
            Result[bool, Error]: Un Result que contiene True si se eliminó correctamente,
            o un error si no se encuentra el rol, es un rol del sistema, o hay un error al eliminar.
        """
        try:
            # Obtener el rol existente
            role_result = await RoleRepository.get_by_id(db, role_id)
            if role_result.is_failure():
                return role_result

            role = role_result.unwrap()

            # Verificar si es un rol del sistema
            if role.is_system:
                return Failure(SystemRoleModificationError(role_id=role_id))

            # Verificar si tiene usuarios asignados
            query = select(user_roles.c.user_id).where(user_roles.c.role_id == role_id)
            result = await db.execute(query)
            if result.first() is not None:
                return Failure(RoleDeleteError(
                    role_id=role_id,
                    message=f"No se puede eliminar el rol con ID {role_id} porque tiene usuarios asignados"
                ))

            # Eliminar asignaciones de permisos al rol
            delete_permissions = delete(role_permissions).where(role_permissions.c.role_id == role_id)
            await db.execute(delete_permissions)

            # Eliminar el rol
            await db.delete(role)
            await db.flush()

            return Success(True)
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error al eliminar rol: {str(e)}"))

    @staticmethod
    async def assign_permission(
        db: AsyncSession, role_id: int, permission_id: int, assigned_by: Optional[int] = None
    ) -> Result[Dict[str, Any], RoleNotFoundError | PermissionNotFoundError | PermissionAssignmentError]:
        """
        Asigna un permiso a un rol.

        Args:
            db: Sesión de base de datos.
            role_id: ID del rol.
            permission_id: ID del permiso a asignar.
            assigned_by: ID del usuario que realiza la asignación.

        Returns:
            Result[Dict[str, Any], Error]: Un Result que contiene información de la asignación,
            o un error si no se encuentra el rol o el permiso, o hay un error en la asignación.
        """
        try:
            # Verificar que el rol existe
            role_result = await RoleRepository.get_by_id(db, role_id)
            if role_result.is_failure():
                return role_result

            # Verificar que el permiso existe
            permission_result = await PermissionRepository.get_by_id(db, permission_id)
            if permission_result.is_failure():
                return permission_result

            # Verificar si el permiso ya está asignado al rol
            query = select(role_permissions).where(
                and_(
                    role_permissions.c.role_id == role_id,
                    role_permissions.c.permission_id == permission_id
                )
            )
            result = await db.execute(query)
            existing_assignment = result.first()

            if existing_assignment is not None:
                # El permiso ya está asignado, devolver la información existente
                return Success({
                    "role_id": role_id,
                    "permission_id": permission_id,
                    "assigned_at": existing_assignment.assigned_at,
                    "assigned_by": existing_assignment.assigned_by,
                    "already_assigned": True
                })

            # Asignar el permiso al rol
            now_utc_val = datetime.now(timezone.utc)
            values = {
                "role_id": role_id,
                "permission_id": permission_id,
                "assigned_at": now_utc_val,
                "assigned_by": assigned_by
            }

            stmt = insert(role_permissions).values(**values)
            await db.execute(stmt)
            await db.flush()

            return Success({
                "role_id": role_id,
                "permission_id": permission_id,
                "assigned_at": now_utc_val,
                "assigned_by": assigned_by,
                "already_assigned": False
            })
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(PermissionAssignmentError(
                message=f"Error al asignar permiso {permission_id} al rol {role_id}: {str(e)}"
            ))

    @staticmethod
    async def remove_permission(
        db: AsyncSession, role_id: int, permission_id: int
    ) -> Result[bool, RoleNotFoundError | PermissionNotFoundError | PermissionAssignmentError]:
        """
        Elimina un permiso de un rol.

        Args:
            db: Sesión de base de datos.
            role_id: ID del rol.
            permission_id: ID del permiso a eliminar.

        Returns:
            Result[bool, Error]: Un Result que contiene True si se eliminó correctamente,
            o un error si no se encuentra el rol o el permiso, o hay un error al eliminar.
        """
        try:
            # Verificar que el rol existe
            role_result = await RoleRepository.get_by_id(db, role_id)
            if role_result.is_failure():
                return role_result

            # Verificar que el permiso existe
            permission_result = await PermissionRepository.get_by_id(db, permission_id)
            if permission_result.is_failure():
                return permission_result

            # Eliminar la asignación
            stmt = delete(role_permissions).where(
                and_(
                    role_permissions.c.role_id == role_id,
                    role_permissions.c.permission_id == permission_id
                )
            )
            result = await db.execute(stmt)

            # Verificar si se eliminó alguna fila
            if result.rowcount == 0:
                return Success(False)  # No había asignación para eliminar

            await db.flush()
            return Success(True)
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(PermissionAssignmentError(
                message=f"Error al eliminar permiso {permission_id} del rol {role_id}: {str(e)}"
            ))

    @staticmethod
    async def get_permissions_by_role_id(
        db: AsyncSession, role_id: int
    ) -> Result[List[Permission], RoleNotFoundError]:
        """
        Obtiene todos los permisos asignados a un rol.

        Args:
            db: Sesión de base de datos.
            role_id: ID del rol.

        Returns:
            Result[List[Permission], RoleNotFoundError]: Un Result que contiene la lista de permisos,
            o un RoleNotFoundError si no se encuentra el rol.
        """
        try:
            # Verificar que el rol existe
            role_result = await RoleRepository.get_by_id(db, role_id)
            if role_result.is_failure():
                return role_result

            role = role_result.unwrap()
            return Success(role.permissions)
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener permisos del rol: {str(e)}"))


class PermissionRepository:
    """Repositorio para operaciones CRUD de permisos."""

    @staticmethod
    async def get_by_id(
        db: AsyncSession, permission_id: int
    ) -> Result[Permission, PermissionNotFoundError]:
        """
        Obtiene un permiso por su ID.

        Args:
            db: Sesión de base de datos.
            permission_id: ID del permiso a buscar.

        Returns:
            Result[Permission, PermissionNotFoundError]: Un Result que contiene el permiso si se encuentra,
            o un PermissionNotFoundError si no existe.
        """
        try:
            query = select(Permission).where(Permission.id == permission_id)
            result = await db.execute(query)
            permission = result.scalars().first()

            if permission is None:
                return Failure(PermissionNotFoundError(permission_id=permission_id))

            return Success(permission)
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener permiso: {str(e)}"))

    @staticmethod
    async def get_by_code(
        db: AsyncSession, code: str
    ) -> Result[Permission, PermissionNotFoundError]:
        """
        Obtiene un permiso por su código.

        Args:
            db: Sesión de base de datos.
            code: Código del permiso a buscar.

        Returns:
            Result[Permission, PermissionNotFoundError]: Un Result que contiene el permiso si se encuentra,
            o un PermissionNotFoundError si no existe.
        """
        try:
            query = select(Permission).where(func.lower(Permission.code) == func.lower(code))
            result = await db.execute(query)
            permission = result.scalars().first()

            if permission is None:
                return Failure(PermissionNotFoundError(permission_code=code))

            return Success(permission)
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener permiso: {str(e)}"))

    @staticmethod
    async def get_all(
        db: AsyncSession, skip: int = 0, limit: int = 100
    ) -> Result[List[Permission], DatabaseError]:
        """
        Obtiene todos los permisos con paginación.

        Args:
            db: Sesión de base de datos.
            skip: Número de registros a saltar para paginación.
            limit: Límite de registros a retornar.

        Returns:
            Result[List[Permission], DatabaseError]: Un Result que contiene la lista de permisos,
            o un DatabaseError si ocurre un error.
        """
        try:
            query = select(Permission).offset(skip).limit(limit)
            result = await db.execute(query)
            permissions = result.scalars().all()

            return Success(list(permissions))
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener permisos: {str(e)}"))

    @staticmethod
    async def create(
        db: AsyncSession, name: str, code: str, description: Optional[str] = None
    ) -> Result[Permission, PermissionAlreadyExistsError]:
        """
        Crea un nuevo permiso.

        Args:
            db: Sesión de base de datos.
            name: Nombre del permiso.
            code: Código único del permiso.
            description: Descripción del permiso.

        Returns:
            Result[Permission, PermissionAlreadyExistsError]: Un Result que contiene el permiso creado,
            o un PermissionAlreadyExistsError si ya existe un permiso con ese código o nombre.
        """
        try:
            # Verificar si ya existe un permiso con el mismo código
            code_exists_result = await PermissionRepository.get_by_code(db, code)
            if code_exists_result.is_success():
                return Failure(PermissionAlreadyExistsError(permission_code=code))

            # Crear el nuevo permiso
            new_permission = Permission(
                name=name,
                code=code,
                description=description,
                created_at=datetime.now(timezone.utc),
                updated_at=datetime.now(timezone.utc)
            )

            db.add(new_permission)
            await db.flush()  # Para obtener el ID asignado

            return Success(new_permission)
        except IntegrityError as e:
            await db.rollback()
            error_message = str(e).lower()
            if "unique constraint" in error_message:
                if "code" in error_message:
                    return Failure(PermissionAlreadyExistsError(permission_code=code))
                elif "name" in error_message:
                    return Failure(PermissionAlreadyExistsError(permission_name=name))
            return Failure(DatabaseError(detail=f"Error de integridad al crear permiso: {str(e)}"))
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error al crear permiso: {str(e)}"))

    @staticmethod
    async def update(
        db: AsyncSession,
        permission_id: int,
        name: Optional[str] = None,
        description: Optional[str] = None
    ) -> Result[Permission, PermissionNotFoundError | PermissionAlreadyExistsError]:
        """
        Actualiza un permiso existente.

        Args:
            db: Sesión de base de datos.
            permission_id: ID del permiso a actualizar.
            name: Nuevo nombre del permiso.
            description: Nueva descripción del permiso.

        Returns:
            Result[Permission, Error]: Un Result que contiene el permiso actualizado,
            o un error si no se encuentra el permiso o ya existe otro con el nuevo nombre.
        """
        try:
            # Obtener el permiso existente
            permission_result = await PermissionRepository.get_by_id(db, permission_id)
            if permission_result.is_failure():
                return permission_result

            permission = permission_result.unwrap()

            # Actualizar campos
            if name is not None:
                # Verificar si otro permiso ya tiene ese nombre
                query = select(Permission).where(
                    and_(
                        func.lower(Permission.name) == func.lower(name),
                        Permission.id != permission_id
                    )
                )
                result = await db.execute(query)
                if result.scalars().first() is not None:
                    return Failure(PermissionAlreadyExistsError(permission_name=name))
                
                permission.name = name
                
            if description is not None:
                permission.description = description

            permission.updated_at = datetime.now(timezone.utc)
            await db.flush()

            return Success(permission)
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error al actualizar permiso: {str(e)}"))

    @staticmethod
    async def delete(
        db: AsyncSession, permission_id: int
    ) -> Result[bool, PermissionNotFoundError]:
        """
        Elimina un permiso de la base de datos.

        Args:
            db: Sesión de base de datos.
            permission_id: ID del permiso a eliminar.

        Returns:
            Result[bool, PermissionNotFoundError]: Un Result que contiene True si se eliminó correctamente,
            o un PermissionNotFoundError si no se encuentra el permiso.
        """
        try:
            # Obtener el permiso existente
            permission_result = await PermissionRepository.get_by_id(db, permission_id)
            if permission_result.is_failure():
                return permission_result

            permission = permission_result.unwrap()

            # Eliminar asignaciones de este permiso a roles
            delete_roles = delete(role_permissions).where(role_permissions.c.permission_id == permission_id)
            await db.execute(delete_roles)

            # Eliminar el permiso
            await db.delete(permission)
            await db.flush()

            return Success(True)
        except SQLAlchemyError as e:
            await db.rollback()
            return Failure(DatabaseError(detail=f"Error al eliminar permiso: {str(e)}"))

    @staticmethod
    async def get_roles_by_permission_id(
        db: AsyncSession, permission_id: int
    ) -> Result[List[Role], PermissionNotFoundError]:
        """
        Obtiene todos los roles que tienen asignado un permiso específico.

        Args:
            db: Sesión de base de datos.
            permission_id: ID del permiso.

        Returns:
            Result[List[Role], PermissionNotFoundError]: Un Result que contiene la lista de roles,
            o un PermissionNotFoundError si no se encuentra el permiso.
        """
        try:
            # Verificar que el permiso existe
            permission_result = await PermissionRepository.get_by_id(db, permission_id)
            if permission_result.is_failure():
                return permission_result

            permission = permission_result.unwrap()
            return Success(permission.roles)
        except SQLAlchemyError as e:
            return Failure(DatabaseError(detail=f"Error al obtener roles del permiso: {str(e)}"))
