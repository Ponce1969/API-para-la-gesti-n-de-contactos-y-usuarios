from datetime import datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import sqlalchemy
from returns.result import Failure, Success
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.errors import DatabaseError
from app.contacts.errors import (
    ContactAlreadyExistsError,
    ContactAlreadyInGroupError,
    ContactGroupAlreadyExistsError,
    ContactGroupNotFoundError,
    ContactGroupValidationError,
    ContactNotFoundError,
    ContactNotInGroupError,
    ContactValidationError,
    UnauthorizedContactAccessError,
    UnauthorizedGroupAccessError,
)
from app.contacts.models import Contact, ContactGroup, contact_group_members
from app.contacts.repository import ContactGroupRepository, ContactRepository


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


class TestContactGroupRepository:
    """Pruebas para ContactGroupRepository."""

    async def test_get_by_id_success(self, mock_db, mock_group):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_group
        mock_execute.return_value = mock_result

        # Act
        result = await ContactGroupRepository.get_by_id(mock_db, 1)

        # Assert
        assert result.is_success()
        assert result.unwrap() == mock_group
        mock_db.execute.assert_called_once()

    async def test_get_by_id_not_found(self, mock_db):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_execute.return_value = mock_result

        # Act
        result = await ContactGroupRepository.get_by_id(mock_db, 999)

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), ContactGroupNotFoundError)
        mock_db.execute.assert_called_once()

    async def test_get_by_id_with_owner_id_unauthorized(self, mock_db):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute

        # Primera llamada para verificar si existe con owner_id
        mock_result_1 = MagicMock()
        mock_result_1.scalar_one_or_none.return_value = None

        # Segunda llamada para verificar si existe sin owner_id
        mock_result_2 = MagicMock()
        mock_result_2.scalar_one_or_none.return_value = MagicMock(spec=ContactGroup)

        mock_execute.side_effect = [mock_result_1, mock_result_2]

        # Act
        result = await ContactGroupRepository.get_by_id(mock_db, 1, owner_id=2)

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), UnauthorizedGroupAccessError)
        assert mock_db.execute.call_count == 2

    async def test_get_by_name_success(self, mock_db, mock_group):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = mock_group
        mock_execute.return_value = mock_result

        # Act
        result = await ContactGroupRepository.get_by_name(mock_db, "Trabajo", 1)

        # Assert
        assert result.is_success()
        assert result.unwrap() == mock_group
        mock_db.execute.assert_called_once()

    async def test_get_by_name_not_found(self, mock_db):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalar_one_or_none.return_value = None
        mock_execute.return_value = mock_result

        # Act
        result = await ContactGroupRepository.get_by_name(
            mock_db, "Grupo Inexistente", 1
        )

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), ContactGroupNotFoundError)
        mock_db.execute.assert_called_once()

    async def test_list_groups_success(self, mock_db, mock_group):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_group]
        mock_execute.return_value = mock_result

        # Act
        result = await ContactGroupRepository.list_groups(mock_db, 1)

        # Assert
        assert result.is_success()
        assert len(result.unwrap()) == 1
        assert result.unwrap()[0] == mock_group
        mock_db.execute.assert_called_once()

    async def test_list_groups_with_search(self, mock_db, mock_group):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_group]
        mock_execute.return_value = mock_result

        # Act
        result = await ContactGroupRepository.list_groups(mock_db, 1, search="Trab")

        # Assert
        assert result.is_success()
        assert len(result.unwrap()) == 1
        assert result.unwrap()[0] == mock_group
        mock_db.execute.assert_called_once()

    async def test_create_group_success(self, mock_db, mock_group):
        # Arrange
        mock_db.add = AsyncMock()
        mock_db.flush = AsyncMock()
        mock_db.refresh = AsyncMock()
        mock_db.commit = AsyncMock()

        # Mock de get_by_name para simular que no existe el grupo
        with patch.object(
            ContactGroupRepository,
            "get_by_name",
            return_value=Failure(ContactGroupNotFoundError(0, "No encontrado")),
        ) as mock_get_by_name:
            # Act
            result = await ContactGroupRepository.create(
                mock_db,
                owner_id=1,
                name="Trabajo",
                description="Contactos de trabajo",
            )

            # Assert
            assert result.is_success()
            mock_db.add.assert_called_once()
            mock_db.flush.assert_called_once()
            mock_db.refresh.assert_called_once()
            mock_db.commit.assert_called_once()
            mock_get_by_name.assert_called_once()

    async def test_create_group_already_exists(self, mock_db, mock_group):
        # Arrange
        # Mock de get_by_name para simular que existe el grupo
        with patch.object(
            ContactGroupRepository, "get_by_name", return_value=Success(mock_group)
        ) as mock_get_by_name:
            # Act
            result = await ContactGroupRepository.create(
                mock_db,
                owner_id=1,
                name="Trabajo",
                description="Contactos de trabajo",
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactGroupAlreadyExistsError)
            mock_get_by_name.assert_called_once()

    async def test_create_group_validation_error(self, mock_db):
        # Arrange - No se proporciona el nombre del grupo

        # Act
        result = await ContactGroupRepository.create(
            mock_db,
            owner_id=1,
            name="",  # Nombre vacu00edo
            description="Descripciu00f3n",
        )

        # Assert
        assert result.is_failure()
        assert isinstance(result.failure(), ContactGroupValidationError)

    async def test_update_group_success(self, mock_db, mock_group):
        # Arrange
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        # Mock de get_by_id para simular que existe el grupo
        with patch.object(
            ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
        ) as mock_get_by_id:
            # Act
            result = await ContactGroupRepository.update(
                mock_db,
                group_id=1,
                owner_id=1,
                description="Descripciu00f3n actualizada",
            )

            # Assert
            assert result.is_success()
            mock_db.commit.assert_called_once()
            mock_db.refresh.assert_called_once()
            mock_get_by_id.assert_called_once()

            # Verificar que se actualizu00f3 el campo
            group = result.unwrap()
            assert group.description == "Descripciu00f3n actualizada"

    async def test_update_group_name_conflict(self, mock_db, mock_group):
        # Arrange
        existing_group = MagicMock(spec=ContactGroup)
        existing_group.id = 2
        existing_group.name = "Otro Grupo"

        # Mock de get_by_id para simular que existe el grupo
        with (
            patch.object(
                ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
            ) as mock_get_by_id,
            patch.object(
                ContactGroupRepository,
                "get_by_name",
                return_value=Success(existing_group),
            ) as mock_get_by_name,
        ):
            # Act
            result = await ContactGroupRepository.update(
                mock_db,
                group_id=1,
                owner_id=1,
                name="Otro Grupo",  # Este nombre ya existe
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactGroupAlreadyExistsError)
            mock_get_by_id.assert_called_once()
            mock_get_by_name.assert_called_once()

    async def test_delete_group_success(self, mock_db, mock_group):
        # Arrange
        mock_db.delete = AsyncMock()
        mock_db.flush = AsyncMock()

        # Mock de get_by_id para simular que existe el grupo
        with patch.object(
            ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
        ) as mock_get_by_id:
            # Act
            result = await ContactGroupRepository.delete(
                mock_db,
                group_id=1,
                owner_id=1,
            )

            # Assert
            assert result.is_success()
            assert (
                result.unwrap() is None
            )  # El mu00e9todo delete devuelve None en caso de u00e9xito
            mock_db.delete.assert_called_once_with(mock_group)
            mock_db.flush.assert_called_once()
            mock_get_by_id.assert_called_once()

    async def test_add_contact_to_group_success(
        self, mock_db, mock_contact, mock_group
    ):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute

        # Mock para verificar si el contacto ya estu00e1 en el grupo
        mock_result = MagicMock()
        mock_result.first.return_value = None  # No estu00e1 en el grupo
        mock_execute.return_value = mock_result

        mock_db.commit = AsyncMock()

        # Mocks para get_by_id de contacto y grupo
        with (
            patch.object(
                ContactRepository, "get_by_id", return_value=Success(mock_contact)
            ) as mock_get_contact,
            patch.object(
                ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
            ) as mock_get_group,
        ):
            # Act
            result = await ContactGroupRepository.add_contact_to_group(
                mock_db,
                contact_id=1,
                group_id=1,
                owner_id=1,
                notes="Nota para el contacto en el grupo",
            )

            # Assert
            assert result.is_success()
            assert result.unwrap() is None
            mock_get_contact.assert_called_once()
            mock_get_group.assert_called_once()
            assert (
                mock_db.execute.call_count == 2
            )  # Una para verificar y otra para insertar
            mock_db.commit.assert_called_once()

    async def test_add_contact_to_group_already_in_group(
        self, mock_db, mock_contact, mock_group
    ):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute

        # Mock para verificar si el contacto ya estu00e1 en el grupo
        mock_result = MagicMock()
        mock_result.first.return_value = MagicMock()  # Ya estu00e1 en el grupo
        mock_execute.return_value = mock_result

        # Mocks para get_by_id de contacto y grupo
        with (
            patch.object(
                ContactRepository, "get_by_id", return_value=Success(mock_contact)
            ) as mock_get_contact,
            patch.object(
                ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
            ) as mock_get_group,
        ):
            # Act
            result = await ContactGroupRepository.add_contact_to_group(
                mock_db,
                contact_id=1,
                group_id=1,
                owner_id=1,
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactAlreadyInGroupError)
            mock_get_contact.assert_called_once()
            mock_get_group.assert_called_once()
            mock_db.execute.assert_called_once()

    async def test_remove_contact_from_group_success(
        self, mock_db, mock_contact, mock_group
    ):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute

        # Mock para verificar si el contacto estu00e1 en el grupo
        mock_result = MagicMock()
        mock_result.first.return_value = MagicMock()  # Estu00e1 en el grupo
        mock_execute.return_value = mock_result

        mock_db.commit = AsyncMock()

        # Mocks para get_by_id de contacto y grupo
        with (
            patch.object(
                ContactRepository, "get_by_id", return_value=Success(mock_contact)
            ) as mock_get_contact,
            patch.object(
                ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
            ) as mock_get_group,
        ):
            # Act
            result = await ContactGroupRepository.remove_contact_from_group(
                mock_db,
                contact_id=1,
                group_id=1,
                owner_id=1,
            )

            # Assert
            assert result.is_success()
            assert result.unwrap() is None
            mock_get_contact.assert_called_once()
            mock_get_group.assert_called_once()
            assert (
                mock_db.execute.call_count == 2
            )  # Una para verificar y otra para eliminar
            mock_db.commit.assert_called_once()

    async def test_remove_contact_from_group_not_in_group(
        self, mock_db, mock_contact, mock_group
    ):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute

        # Mock para verificar si el contacto estu00e1 en el grupo
        mock_result = MagicMock()
        mock_result.first.return_value = None  # No estu00e1 en el grupo
        mock_execute.return_value = mock_result

        # Mocks para get_by_id de contacto y grupo
        with (
            patch.object(
                ContactRepository, "get_by_id", return_value=Success(mock_contact)
            ) as mock_get_contact,
            patch.object(
                ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
            ) as mock_get_group,
        ):
            # Act
            result = await ContactGroupRepository.remove_contact_from_group(
                mock_db,
                contact_id=1,
                group_id=1,
                owner_id=1,
            )

            # Assert
            assert result.is_failure()
            assert isinstance(result.failure(), ContactNotInGroupError)
            mock_get_contact.assert_called_once()
            mock_get_group.assert_called_once()
            mock_db.execute.assert_called_once()

    async def test_list_contacts_in_group(self, mock_db, mock_contact, mock_group):
        # Arrange
        mock_execute = AsyncMock()
        mock_db.execute = mock_execute

        # Mock para la bu00fasqueda de contactos en el grupo
        mock_result = MagicMock()
        mock_result.scalars.return_value.all.return_value = [mock_contact]
        mock_execute.return_value = mock_result

        # Mock para get_by_id del grupo
        with patch.object(
            ContactGroupRepository, "get_by_id", return_value=Success(mock_group)
        ) as mock_get_group:
            # Act
            result = await ContactGroupRepository.list_contacts(
                mock_db,
                owner_id=1,
                group_id=1,
            )

            # Assert
            assert result.is_success()
            assert len(result.unwrap()) == 1
            assert result.unwrap()[0] == mock_contact
            mock_get_group.assert_called_once()
            mock_db.execute.assert_called_once()
