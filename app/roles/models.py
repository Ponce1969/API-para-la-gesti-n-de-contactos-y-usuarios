"""Modelos SQLAlchemy para el dominio de Roles.

Este módulo define los modelos de base de datos relacionados con los roles de usuario,
utilizando SQLAlchemy ORM con soporte asíncrono.
"""

from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Table
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.database import Base
from app.users.models import User

# Tabla de asociación para la relación muchos a muchos entre usuarios y roles
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column(
        "user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "assigned_at",
        DateTime(timezone=True), # Ensure timezone aware
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    ),
    Column("assigned_by", Integer, nullable=True), # Should this be ForeignKey?
    Column("is_active", Boolean, default=True, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=True), # Ensure timezone aware
    comment="Tabla de asociación entre usuarios y roles con metadatos adicionales",
)


class Role(Base):
    """Modelo que representa un rol en el sistema.

    Los roles definen los permisos y el nivel de acceso que tiene un usuario en el sistema.
    """

    __tablename__ = "roles"
    __table_args__ = {
        "comment": "Almacena los diferentes roles que pueden tener los usuarios en el sistema",
    }

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )
    name: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_system: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Indica si es un rol del sistema que no se puede eliminar",
    )

    # Relaciones
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission",
        secondary="role_permissions",
        back_populates="roles",
        lazy="selectin",
    )

    # Usuarios que tienen este rol
    users: Mapped[list["User"]] = relationship(
        "User",
        secondary=user_roles,
        back_populates="roles",
        lazy="selectin",
    )

    # Auditoría
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Role {self.name}>"


class Permission(Base):
    """Modelo que representa un permiso en el sistema.

    Los permisos definen acciones específicas que pueden realizarse en el sistema.
    """

    __tablename__ = "permissions"
    __table_args__ = {
        "comment": "Almacena los permisos que pueden asignarse a los roles",
    }

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )
    name: Mapped[str] = mapped_column(
        String(100), unique=True, nullable=False, index=True
    )
    code: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    description: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Relaciones
    roles: Mapped[list[Role]] = relationship(
        "Role",
        secondary="role_permissions",
        back_populates="permissions",
        lazy="selectin",
    )

    # Auditoría
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self) -> str:
        return f"<Permission {self.code} ({self.name})>"


# Tabla de asociación para la relación muchos a muchos entre roles y permisos
role_permissions = Table(
    "role_permissions",
    Base.metadata,
    Column(
        "role_id", Integer, ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    ),
    Column(
        "permission_id",
        Integer,
        ForeignKey("permissions.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "assigned_at",
        DateTime(timezone=True), # Ensure timezone aware
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    ),
    Column("assigned_by", Integer, nullable=True), # Should this be ForeignKey?
    comment="Tabla de asociación entre roles y permisos",
)
