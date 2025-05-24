"""Modelos SQLAlchemy para el dominio de Roles.

Este módulo define los modelos de base de datos relacionados con los roles de usuario,
utilizando SQLAlchemy ORM con soporte asíncrono.
"""
from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.database import Base

# Tabla de asociación para la relación muchos a muchos entre usuarios y roles
user_roles = Table(
    'user_roles',
    Base.metadata,
    Column('user_id', Integer, primary_key=True),
    Column('role_id', Integer, primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow, nullable=False),
    Column('assigned_by', Integer, nullable=True),
    Column('is_active', Boolean, default=True, nullable=False),
    Column('expires_at', DateTime, nullable=True),
    comment='Tabla de asociación entre usuarios y roles con metadatos adicionales',
)


class Role(Base):
    """Modelo que representa un rol en el sistema.
    
    Los roles definen los permisos y el nivel de acceso que tiene un usuario en el sistema.
    """
    __tablename__ = 'roles'
    __table_args__ = {
        'comment': 'Almacena los diferentes roles que pueden tener los usuarios en el sistema',
    }
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, 
                                          comment='Indica si es un rol del sistema que no se puede eliminar')
    
    # Relaciones
    permissions: Mapped[List['Permission']] = relationship(
        'Permission',
        secondary='role_permissions',
        back_populates='roles',
        lazy='selectin',
    )
    
    # Usuarios que tienen este rol
    users: Mapped[List['User']] = relationship(
        'User',
        secondary=user_roles,
        back_populates='roles',
        lazy='selectin',
    )
    
    # Auditoría
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow,
        nullable=False,
    )
    
    def __repr__(self) -> str:
        return f'<Role {self.name}>'


class Permission(Base):
    """Modelo que representa un permiso en el sistema.
    
    Los permisos definen acciones específicas que pueden realizarse en el sistema.
    """
    __tablename__ = 'permissions'
    __table_args__ = {
        'comment': 'Almacena los permisos que pueden asignarse a los roles',
    }
    
    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    code: Mapped[str] = mapped_column(String(50), unique=True, nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    # Relaciones
    roles: Mapped[List[Role]] = relationship(
        'Role',
        secondary='role_permissions',
        back_populates='permissions',
        lazy='selectin',
    )
    
    # Auditoría
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime, 
        default=datetime.utcnow, 
        onupdate=datetime.utcnow,
        nullable=False,
    )
    
    def __repr__(self) -> str:
        return f'<Permission {self.code} ({self.name})>'


# Tabla de asociación para la relación muchos a muchos entre roles y permisons
role_permissions = Table(
    'role_permissions',
    Base.metadata,
    Column('role_id', Integer, primary_key=True),
    Column('permission_id', Integer, primary_key=True),
    Column('assigned_at', DateTime, default=datetime.utcnow, nullable=False),
    Column('assigned_by', Integer, nullable=True),
    comment='Tabla de asociación entre roles y permisos',
)