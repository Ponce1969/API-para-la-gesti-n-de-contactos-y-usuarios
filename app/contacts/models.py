"""Modelos SQLAlchemy para el dominio de Contactos.

Este módulo define los modelos de base de datos relacionados con los contactos de los usuarios,
utilizando SQLAlchemy ORM con soporte asíncrono.
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional

from sqlalchemy import Boolean, Column, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Integer, String, Table, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.common.database import Base
from app.users.models import User


class ContactType(str, Enum):
    """Tipos de contactos en el sistema."""

    PERSONAL = "personal"
    WORK = "work"
    FAMILY = "family"
    FRIEND = "friend"
    OTHER = "other"


class ContactStatus(str, Enum):
    """Estados posibles de un contacto."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    PENDING = "pending"
    BLOCKED = "blocked"


class Contact(Base):
    """Modelo que representa un contacto en el sistema.

    Los contactos son entradas en la libreta de direcciones de un usuario.
    """

    __tablename__ = "contacts"
    __table_args__ = {
        "comment": "Almacena los contactos de los usuarios",
    }

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )

    # Información básica
    first_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, comment="Nombre del contacto"
    )
    last_name: Mapped[Optional[str]] = mapped_column(
        String(100), nullable=True, comment="Apellido del contacto"
    )
    email: Mapped[Optional[str]] = mapped_column(
        String(255),
        nullable=True,
        index=True,
        comment="Correo electrónico del contacto",
    )
    phone: Mapped[Optional[str]] = mapped_column(
        String(50), nullable=True, index=True, comment="Número de teléfono del contacto"
    )
    company: Mapped[Optional[str]] = mapped_column(
        String(255), nullable=True, comment="Empresa u organización del contacto"
    )
    position: Mapped[Optional[str]] = mapped_column(
        String(100),
        nullable=True,
        comment="Cargo o posición del contacto en la empresa",
    )

    # Clasificación
    contact_type: Mapped[ContactType] = mapped_column(
        SQLEnum(ContactType, name="contact_type"),
        default=ContactType.OTHER,
        nullable=False,
        comment="Tipo de contacto (personal, trabajo, familiar, etc.)",
    )
    status: Mapped[ContactStatus] = mapped_column(
        SQLEnum(ContactStatus, name="contact_status"),
        default=ContactStatus.ACTIVE,
        nullable=False,
        comment="Estado actual del contacto",
    )
    is_favorite: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
        comment="Indica si el contacto está marcado como favorito",
    )

    # Información adicional
    address: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Dirección física completa del contacto"
    )
    notes: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Notas adicionales sobre el contacto"
    )
    custom_fields: Mapped[Optional[dict]] = mapped_column(
        JSONB,
        nullable=True,
        comment="Campos personalizados adicionales en formato JSON",
    )

    # Relaciones
    owner_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="ID del usuario propietario de este contacto",
    )

    # Si el contacto es otro usuario del sistema
    contact_user_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
        comment="ID del usuario de la plataforma si el contacto está registrado",
    )

    # Grupos a los que pertenece este contacto (relación muchos a muchos)
    groups: Mapped[List["ContactGroup"]] = relationship(
        "ContactGroup",
        secondary="contact_group_members",
        back_populates="contacts",
        lazy="selectin",
    )

    # Relación con el propietario (usuario que creó/posee este contacto)
    owner: Mapped[User] = relationship(
        "User",
        foreign_keys=[owner_id],
        back_populates="owned_contacts",
    )

    # Relación con el usuario de la plataforma (si aplica)
    contact_user: Mapped[Optional[User]] = relationship(
        "User",
        foreign_keys=[contact_user_id],
        back_populates="contact_entries",
    )

    # Auditoría
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        comment="Fecha y hora de creación del contacto",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
        comment="Fecha y hora de la última actualización del contacto",
    )

    def __repr__(self) -> str:
        return f"<Contact {self.full_name}>"

    @property
    def full_name(self) -> str:
        """Devuelve el nombre completo del contacto."""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        return "Contacto sin nombre"


class ContactGroup(Base):
    """Modelo que representa un grupo de contactos."""

    __tablename__ = "contact_groups"
    __table_args__ = {
        "comment": "Almacena los grupos de contactos creados por los usuarios",
    }

    id: Mapped[int] = mapped_column(
        Integer, primary_key=True, index=True, autoincrement=True
    )
    name: Mapped[str] = mapped_column(
        String(100), nullable=False, comment="Nombre del grupo de contactos"
    )
    description: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, comment="Descripción del grupo de contactos"
    )

    # Relaciones
    owner_id: Mapped[int] = mapped_column(
        Integer,
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
        comment="ID del usuario propietario de este grupo",
    )

    # Contactos que pertenecen a este grupo
    contacts: Mapped[List[Contact]] = relationship(
        "Contact",
        secondary="contact_group_members",
        back_populates="groups",
        lazy="selectin",
    )

    # Propietario del grupo
    owner: Mapped[User] = relationship("User")

    # Auditoría
    created_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        nullable=False,
        comment="Fecha y hora de creación del grupo",
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
        comment="Fecha y hora de la última actualización del grupo",
    )

    def __repr__(self) -> str:
        return f"<ContactGroup {self.name}>"


# Tabla de asociación para la relación muchos a muchos entre contactos y grupos
contact_group_members = Table(
    "contact_group_members",
    Base.metadata,
    Column(
        "contact_id",
        Integer,
        ForeignKey("contacts.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column(
        "group_id",
        Integer,
        ForeignKey("contact_groups.id", ondelete="CASCADE"),
        primary_key=True,
    ),
    Column("added_at", DateTime, default=datetime.utcnow, nullable=False),
    Column(
        "notes", Text, nullable=True, comment="Notas sobre la pertenencia a este grupo"
    ),
    comment="Relación muchos a muchos entre contactos y grupos",
)
