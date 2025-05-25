from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Evitamos importaciones problemáticas utilizando mocks
AsyncSession = MagicMock()


# Creamos clases mock para los schemas
class ContactCreate(MagicMock):
    pass


class ContactUpdate(MagicMock):
    pass


class ContactGroupCreate(MagicMock):
    pass


class ContactGroupUpdate(MagicMock):
    pass


# Patcheamos los módulos para evitar importaciones reales
patch("app.contacts.models.Contact", MagicMock()).start()
patch("app.contacts.models.ContactGroup", MagicMock()).start()


@pytest.fixture
def mock_db():
    """Fixture que proporciona un mock de AsyncSession para las pruebas."""
    db = AsyncMock(spec=AsyncSession)
    return db


@pytest.fixture
def mock_contact():
    """Fixture que proporciona un mock de Contact para las pruebas."""
    contact = MagicMock(spec=Contact)
    contact.id = 1
    contact.owner_id = 1
    contact.first_name = "Juan"
    contact.last_name = "Perez"
    contact.email = "juan.perez@example.com"
    contact.phone = "+1234567890"
    contact.company = "Example Corp"
    contact.position = "Developer"
    contact.contact_type = "professional"
    contact.status = "active"
    contact.is_favorite = False
    contact.address = "123 Main St"
    contact.notes = "Some notes about Juan"
    contact.custom_fields = {"project": "App Statica"}
    contact.contact_user_id = None
    contact.created_at = datetime.utcnow()
    contact.updated_at = datetime.utcnow()
    return contact


@pytest.fixture
def mock_group():
    """Fixture que proporciona un mock de ContactGroup para las pruebas."""
    group = MagicMock(spec=ContactGroup)
    group.id = 1
    group.owner_id = 1
    group.name = "Trabajo"
    group.description = "Contactos de trabajo"
    group.created_at = datetime.utcnow()
    group.updated_at = datetime.utcnow()
    return group


@pytest.fixture
def mock_contact_create():
    """Fixture que proporciona un mock de ContactCreate para las pruebas."""
    return ContactCreate(
        first_name="Juan",
        last_name="Perez",
        email="juan.perez@example.com",
        phone="+1234567890",
        company="Example Corp",
        position="Developer",
        contact_type="professional",
        status="active",
        is_favorite=False,
        address="123 Main St",
        notes="Some notes about Juan",
        custom_fields={"project": "App Statica"},
    )


@pytest.fixture
def mock_contact_update():
    """Fixture que proporciona un mock de ContactUpdate para las pruebas."""
    return ContactUpdate(
        first_name="Juan Actualizado",
        company="Nueva Empresa",
    )


@pytest.fixture
def mock_group_create():
    """Fixture que proporciona un mock de ContactGroupCreate para las pruebas."""
    return ContactGroupCreate(
        name="Trabajo",
        description="Contactos de trabajo",
    )


@pytest.fixture
def mock_group_update():
    """Fixture que proporciona un mock de ContactGroupUpdate para las pruebas."""
    return ContactGroupUpdate(
        name="Trabajo Actualizado",
        description="Descripciu00f3n actualizada",
    )
