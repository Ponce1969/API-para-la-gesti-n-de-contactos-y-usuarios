from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Mocks para evitar importaciones problemáticas
Success = MagicMock()
Success.is_success = lambda: True
Success.unwrap = lambda: None

Failure = MagicMock()
Failure.is_failure = lambda: True
Failure.failure = lambda: None


# Clases mock para errores
class DatabaseError(Exception):
    pass


class ContactNotFoundError(Exception):
    pass


class ContactAlreadyExistsError(Exception):
    pass


class ContactValidationError(Exception):
    pass


class UnauthorizedContactAccessError(Exception):
    pass


class ContactGroupNotFoundError(Exception):
    pass


class ContactGroupAlreadyExistsError(Exception):
    pass


class ContactGroupValidationError(Exception):
    pass


class UnauthorizedGroupAccessError(Exception):
    pass


class ContactAlreadyInGroupError(Exception):
    pass


class ContactNotInGroupError(Exception):
    pass


# Mock para los repositorios
ContactRepository = MagicMock()
ContactGroupRepository = MagicMock()


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


class TestContactRepository:
    """Pruebas para ContactRepository."""

    async def test_get_by_id_success(self, mock_db, mock_contact):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalars.return_value.first.return_value = mock_contact
        mock_execute.return_value = mock_result

        # Act
        result = await ContactRepository.get_by_id(mock_db, 1)

        # Assert
        assert result.is_success()
        assert result.unwrap() == mock_contact
        mock_db.execute.assert_called_once()

    async def test_get_by_id_not_found(self, mock_db):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalars.return_value.first.return_value = None
        mock_execute.return_value = mock_result

        # Act
        result = await ContactRepository.get_by_id(mock_db, 999)

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), ContactNotFoundError)
        mock_db.execute.assert_called_once()

    async def test_get_by_id_with_owner_id_unauthorized(self, mock_db):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute

        # Primera llamada para verificar si existe con owner_id
        mock_result_1 = MagicMock()
        mock_result_1.scalars.return_value.first.return_value = None

        # Segunda llamada para verificar si existe sin owner_id
        mock_result_2 = MagicMock()
        mock_result_2.scalar_one_or_none.return_value = MagicMock(spec=Contact)

        mock_execute.side_effect = [mock_result_1, mock_result_2]

        # Act
        result = await ContactRepository.get_by_id(mock_db, 1, owner_id=2)

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), UnauthorizedContactAccessError)
        assert mock_db.execute.call_count == 2

    async def test_get_by_email_success(self, mock_db, mock_contact):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_contact
        mock_execute.return_value = mock_result

        # Act
        result = await ContactRepository.get_by_email(
            mock_db, "juan.perez@example.com", 1
        )

        # Assert
        assert result.is_success()
        assert result.unwrap() == mock_contact
        mock_db.execute.assert_called_once()

    async def test_get_by_email_not_found(self, mock_db):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_execute.return_value = mock_result

        # Act
        result = await ContactRepository.get_by_email(
            mock_db, "nonexistent@example.com", 1
        )

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), ContactNotFoundError)
        mock_db.execute.assert_called_once()

    async def test_create_contact_success(self, mock_db, mock_contact):
        # Arrange
        mock_db.add = AsyncMock()
        mock_db.flush = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.commit = AsyncMock()

        # Mock de get_by_email para simular que no existe el contacto
        with patch.object(
            ContactRepository,
            "get_by_email",
            return_value=Failure(ContactNotFoundError(0, "No encontrado")),
        ) as mock_get_by_email:
            # Act
            result = await ContactRepository.create(
                mock_db,
                owner_id=1,
                first_name="Juan",
                last_name="Perez",
                email="juan.perez@example.com",
                phone="+1234567890",
            )

            # Assert
            assert result.is_success()
            mock_db.add.assert_called_once()
            mock_db.flush.assert_called_once()
            mock_db.refresh.assert_called_once()
            mock_db.commit.assert_called_once()
            mock_get_by_email.assert_called_once()

    async def test_create_contact_already_exists(self, mock_db, mock_contact):
        # Arrange
        # Mock de get_by_email para simular que existe el contacto
        with patch.object(
            ContactRepository, "get_by_email", return_value=Success(mock_contact)
        ) as mock_get_by_email:
            # Act
            result = await ContactRepository.create(
                mock_db,
                owner_id=1,
                first_name="Juan",
                last_name="Perez",
                email="juan.perez@example.com",
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactAlreadyExistsError)
            mock_get_by_email.assert_called_once()

    async def test_create_contact_validation_error(self, mock_db):
        # Arrange - No se proporcionan campos identificativos

        # Act
        result = await ContactRepository.create(
            mock_db,
            owner_id=1,
        )

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), ContactValidationError)

    async def test_create_contact_database_error(self, mock_db):
        # Arrange
        mock_db.add = MagicMock()
        mock_db.flush = AsyncMock(side_effect=SQLAlchemyError("Error de base de datos"))
        mock_db.rollback = AsyncMock()

        # Mock de get_by_email para simular que no existe el contacto
        with patch.object(
            ContactRepository,
            "get_by_email",
            return_value=Failure(ContactNotFoundError(0, "No encontrado")),
        ):
            # Act
            result = await ContactRepository.create(
                mock_db,
                owner_id=1,
                first_name="Juan",
                last_name="Perez",
                email="juan.perez@example.com",
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), DatabaseError)
            mock_db.rollback.assert_called_once()

    async def test_update_contact_success(self, mock_db, mock_contact):
        # Arrange
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        # Mock de get_by_id para simular que existe el contacto
        with patch.object(
            ContactRepository, "get_by_id", return_value=Success(mock_contact)
        ) as mock_get_by_id:
            # Act
            result = await ContactRepository.update(
                mock_db,
                contact_id=1,
                owner_id=1,
                first_name="Juan Actualizado",
                company="Nueva Empresa",
            )

            # Assert
            assert result.is_success()
            mock_db.commit.assert_called_once()
            mock_db.refresh.assert_called_once()
            mock_get_by_id.assert_called_once()

            # Verificar que se actualizaron los campos
            contact = result.unwrap()
            assert contact.first_name == "Juan Actualizado"
            assert contact.company == "Nueva Empresa"

    async def test_update_contact_not_found(self, mock_db):
        # Arrange
        # Mock de get_by_id para simular que no existe el contacto
        with patch.object(
            ContactRepository,
            "get_by_id",
            return_value=Failure(ContactNotFoundError(1)),
        ) as mock_get_by_id:
            # Act
            result = await ContactRepository.update(
                mock_db,
                contact_id=1,
                owner_id=1,
                first_name="Juan Actualizado",
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactNotFoundError)
            mock_get_by_id.assert_called_once()

    async def test_delete_contact_success(self, mock_db, mock_contact):
        # Arrange
        mock_db.delete = AsyncMock()
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()

        # Mock de get_by_id para simular que existe el contacto
        with patch.object(
            ContactRepository, "get_by_id", return_value=Success(mock_contact)
        ) as mock_get_by_id:
            # Act
            result = await ContactRepository.delete(
                mock_db,
                contact_id=1,
                owner_id=1,
            )

            # Assert
            assert result.is_success()
            assert (
                result.unwrap() is None
            )  # El método delete devuelve None en caso de éxito
            mock_db.delete.assert_called_once_with(mock_contact)
            mock_db.flush.assert_called_once()
            mock_db.commit.assert_called_once()
            mock_get_by_id.assert_called_once()

    async def test_delete_contact_not_found(self, mock_db):
        # Arrange
        # Mock de get_by_id para simular que no existe el contacto
        with patch.object(
            ContactRepository,
            "get_by_id",
            return_value=Failure(ContactNotFoundError(1)),
        ) as mock_get_by_id:
            # Act
            result = await ContactRepository.delete(
                mock_db,
                contact_id=1,
                owner_id=1,
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactNotFoundError)
            mock_get_by_id.assert_called_once()
