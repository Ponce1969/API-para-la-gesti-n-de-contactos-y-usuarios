"""Modelos SQLAlchemy para el dominio de Usuarios.

Este módulo define los modelos de base de datos relacionados con los usuarios,
utilizando SQLAlchemy ORM con soporte asíncrono.
"""

from datetime import datetime
from typing import List, Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.database import Base
from app.roles.models import Role, user_roles


class User(Base):
    """Modelo que representa un usuario en el sistema.

    Los usuarios son las cuentas que pueden autenticarse y realizar acciones en el sistema.
    """

    __tablename__ = "users"
    __table_args__ = {
        "comment": "Almacena la información de los usuarios del sistema",
    }

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )

    # Información de autenticación
    email: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Correo electrónico del usuario (debe ser único)",
    )
    hashed_password: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
        comment="Hash de la contraseña del usuario (nunca almacenar en texto plano)",
    )

    # Información personal
    first_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, comment="Nombre(s) del usuario"
    )
    last_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, comment="Apellido(s) del usuario"
    )
    avatar_url: Mapped[Optional[str]] = mapped_column(
        String(512), nullable=True, comment="URL de la imagen de perfil del usuario"
    )

    # Estado de la cuenta
    is_active: Mapped[bool] = mapped_column(
        Boolean,
        default=True,
        nullable=False,
        comment="Indica si la cuenta del usuario está activa",
    )
    is_verified: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Indica si el correo electrónico del usuario ha sido verificado",
    )
    is_superuser: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Indica si el usuario tiene privilegios de superusuario",
    )

    # Preferencias
    language: Mapped[str] = mapped_column(
        String(10),
        default="es",
        nullable=False,
        comment="Código de idioma preferido del usuario (ej: es, en)",
    )
    timezone: Mapped[str] = mapped_column(
        String(50),
        default="UTC",
        nullable=False,
        comment="Zona horaria preferida del usuario (ej: America/Argentina/Buenos_Aires)",
    )

    # Auditoría
    last_login: Mapped[Optional[datetime]] = mapped_column(
        DateTime,
        nullable=True,
        comment="Fecha y hora del último inicio de sesión exitoso",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        comment="Fecha y hora de creación del usuario",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
        comment="Fecha y hora de la última actualización del usuario",
    )

    # Relaciones
    roles: Mapped[List[Role]] = relationship(
        "Role",
        secondary=user_roles,
        back_populates="users",
        lazy="selectin",
    )

    # Relación con contactos (como propietario)
    owned_contacts: Mapped[List["Contact"]] = relationship(
        "Contact",
        back_populates="owner",
        foreign_keys="Contact.owner_id",
        lazy="selectin",
    )

    # Relación con contactos (como contacto)
    contact_entries: Mapped[List["Contact"]] = relationship(
        "Contact",
        back_populates="contact_user",
        foreign_keys="Contact.contact_user_id",
        lazy="selectin",
    )

    verification_tokens: Mapped[List["VerificationToken"]] = relationship(
        "VerificationToken",
        back_populates="user",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        return f"<User {self.email}>"

    @property
    def full_name(self) -> str:
        """Devuelve el nombre completo del usuario."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        return self.email.split("@")[0]


class VerificationToken(Base):
    """Modelo para tokens de verificación de correo y recuperación de contraseña."""

    __tablename__ = "verification_tokens"
    __table_args__ = {
        "comment": "Almacena tokens para verificación de correo y recuperación de contraseña",
    }

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )
    token: Mapped[str] = mapped_column(
        String(255),
        unique=True,
        nullable=False,
        index=True,
        comment="Token único para verificación o recuperación",
    )

    user_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        comment="ID del usuario asociado al token",
    )

    token_type: Mapped[str] = mapped_column(
        String(20),
        nullable=False,
        comment="Tipo de token (email_verification, password_reset, etc.)",
    )

    expires_at: Mapped[datetime] = mapped_column(
        DateTime, nullable=False, comment="Fecha y hora de expiración del token"
    )

    is_used: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Indica si el token ya fue utilizado",
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        comment="Fecha y hora de creación del token",
    )

    # Relaciones
    user: Mapped[User] = relationship("User", back_populates="verification_tokens")

    def __repr__(self) -> str:
        return f"<VerificationToken {self.token_type} for user {self.user_id}>"
