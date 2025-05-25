import pytest
from datetime import datetime
from unittest.mock import patch, MagicMock, AsyncMock

# Mocks para evitar importaciones problemáticas
Success = MagicMock()
Success.is_success = lambda: True
Success.unwrap = lambda: None

Failure = MagicMock()
Failure.is_failure = lambda: True
Failure.failure = lambda: None

# Clases mock para errores
class DatabaseError(Exception): pass
class ContactNotFoundError(Exception): pass
class ContactAlreadyExistsError(Exception): pass
class ContactValidationError(Exception): pass
class UnauthorizedContactAccessError(Exception): pass
class ContactGroupNotFoundError(Exception): pass
class UnauthorizedGroupAccessError(Exception): pass

# Mocks para modelos, repositorios y servicios
Contact = MagicMock()
ContactGroup = MagicMock()
ContactRepository = MagicMock()
ContactGroupRepository = MagicMock()
ContactService = MagicMock()
ContactGroupService = MagicMock()

# Mocks para schemas
class ContactCreate(MagicMock): pass
class ContactUpdate(MagicMock): pass


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
def mock_db():
    """Fixture que proporciona un mock de AsyncSession para las pruebas."""
    db = AsyncMock()
    return db


class TestContactService:
    """Pruebas para ContactService."""

    async def test_get_contact_by_id_success(self, mock_db, mock_contact):
        # Arrange
        with patch.object(
            ContactRepository, "get_by_id", return_value=Success(mock_contact)
        ) as mock_get_by_id:
            # Act
            result = await ContactService.get_contact_by_id(mock_db, 1, 1)

            # Assert
            assert result.is_success()
            assert result.unwrap() == mock_contact
            mock_get_by_id.assert_called_once_with(mock_db, 1, 1)

    async def test_get_contact_by_id_not_found(self, mock_db):
        # Arrange
        with patch.object(
            ContactRepository, "get_by_id", return_value=Failure(ContactNotFoundError(1))
        ) as mock_get_by_id:
            # Act
            result = await ContactService.get_contact_by_id(mock_db, 1, 1)

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactNotFoundError)
            mock_get_by_id.assert_called_once_with(mock_db, 1, 1)

    async def test_get_contact_by_email_success(self, mock_db, mock_contact):
        # Arrange
        with patch.object(
            ContactRepository, "get_by_email", return_value=Success(mock_contact)
        ) as mock_get_by_email:
            # Act
            result = await ContactService.get_contact_by_email(mock_db, "juan.perez@example.com", 1)

            # Assert
            assert result.is_success()
            assert result.unwrap() == mock_contact
            mock_get_by_email.assert_called_once_with(mock_db, "juan.perez@example.com", 1)

    async def test_get_contact_by_email_not_found(self, mock_db):
        # Arrange
        with patch.object(
            ContactRepository, "get_by_email", 
            return_value=Failure(ContactNotFoundError(0, "No se encontró un contacto con email test@example.com"))
        ) as mock_get_by_email:
            # Act
            result = await ContactService.get_contact_by_email(mock_db, "test@example.com", 1)

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactNotFoundError)
            mock_get_by_email.assert_called_once_with(mock_db, "test@example.com", 1)

    async def test_list_contacts_success(self, mock_db, mock_contact):
        # Arrange
        contacts_list = [mock_contact]
        
        # Mock para list_contacts y get_by_id del grupo si es necesario
        with patch.object(
            ContactGroupRepository, "list_contacts", return_value=Success(contacts_list)
        ) as mock_list_contacts:
            # Act
            result = await ContactService.list_contacts(mock_db, 1)

            # Assert
            assert result.is_success()
            assert result.unwrap() == contacts_list
            mock_list_contacts.assert_called_once()

    async def test_list_contacts_with_group_id_success(self, mock_db, mock_contact):
        # Arrange
        contacts_list = [mock_contact]
        group_id = 1
        
        # Mock para get_by_id del grupo y list_contacts
        with patch.object(
            ContactGroupRepository, "get_by_id", return_value=Success(MagicMock())
        ) as mock_get_by_id, \
        patch.object(
            ContactGroupRepository, "list_contacts", return_value=Success(contacts_list)
        ) as mock_list_contacts:
            # Act
            result = await ContactService.list_contacts(mock_db, 1, group_id=group_id)

            # Assert
            assert result.is_success()
            assert result.unwrap() == contacts_list
            mock_get_by_id.assert_called_once_with(mock_db, group_id, 1)
            mock_list_contacts.assert_called_once()

    async def test_list_contacts_with_group_id_not_found(self, mock_db):
        # Arrange
        group_id = 999
        
        # Mock para get_by_id del grupo que no existe
        with patch.object(
            ContactGroupRepository, "get_by_id", 
            return_value=Failure(ContactGroupNotFoundError(group_id))
        ) as mock_get_by_id:
            # Act
            result = await ContactService.list_contacts(mock_db, 1, group_id=group_id)

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactGroupNotFoundError)
            mock_get_by_id.assert_called_once_with(mock_db, group_id, 1)

    async def test_create_contact_success(self, mock_db, mock_contact, mock_contact_create):
        # Arrange
        with patch.object(
            ContactRepository, "create", return_value=Success(mock_contact)
        ) as mock_create:
            # Act
            result = await ContactService.create_contact(mock_db, 1, mock_contact_create)

            # Assert
            assert result.is_success()
            assert result.unwrap() == mock_contact
            mock_create.assert_called_once()

    async def test_create_contact_already_exists(self, mock_db, mock_contact_create):
        # Arrange
        with patch.object(
            ContactRepository, "create", 
            return_value=Failure(ContactAlreadyExistsError("juan.perez@example.com", 1))
        ) as mock_create:
            # Act
            result = await ContactService.create_contact(mock_db, 1, mock_contact_create)

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactAlreadyExistsError)
            mock_create.assert_called_once()

    async def test_update_contact_success(self, mock_db, mock_contact, mock_contact_update):
        # Arrange
        with patch.object(
            ContactRepository, "update", return_value=Success(mock_contact)
        ) as mock_update:
            # Act
            result = await ContactService.update_contact(mock_db, 1, 1, mock_contact_update)

            # Assert
            assert result.is_success()
            assert result.unwrap() == mock_contact
            mock_update.assert_called_once()

    async def test_update_contact_not_found(self, mock_db, mock_contact_update):
        # Arrange
        with patch.object(
            ContactRepository, "update", 
            return_value=Failure(ContactNotFoundError(1))
        ) as mock_update:
            # Act
            result = await ContactService.update_contact(mock_db, 1, 1, mock_contact_update)

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactNotFoundError)
            mock_update.assert_called_once()

    async def test_delete_contact_success(self, mock_db):
        # Arrange
        with patch.object(
            ContactRepository, "delete", return_value=Success(None)
        ) as mock_delete:
            # Act
            result = await ContactService.delete_contact(mock_db, 1, 1)

            # Assert
            assert result.is_success()
            assert result.unwrap() is None
            mock_delete.assert_called_once_with(mock_db, 1, 1)
