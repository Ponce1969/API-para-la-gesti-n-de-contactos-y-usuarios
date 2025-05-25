import pytest
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

from jose import jwt, JWTError
from pydantic import SecretStr

from app.auth import service as auth_service
from app.auth.schemas import TokenData
from app.auth import errors as auth_errors
from app.core.config import settings # We'll mock this

# Mock settings for tests
@pytest.fixture(autouse=True)
def mock_settings_for_auth_service(monkeypatch):
    mock_jwt_secret_key = SecretStr("test_secret_key_for_auth_service_testing_!@#$%")
    mock_jwt_algorithm = "HS256"
    # Patch settings within the auth_service module's scope if it imports settings directly
    monkeypatch.setattr(auth_service, "settings", MagicMock(
        JWT_SECRET_KEY=mock_jwt_secret_key,
        JWT_ALGORITHM=mock_jwt_algorithm,
        ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=7
    ))
    # Also patch the global settings object if it's used by other parts of the code indirectly called
    # This ensures consistency if auth_service functions call other utility functions that might import settings globally
    global_settings_mock = MagicMock(
        JWT_SECRET_KEY=mock_jwt_secret_key,
        JWT_ALGORITHM=mock_jwt_algorithm,
        ACCESS_TOKEN_EXPIRE_MINUTES=15,
        REFRESH_TOKEN_EXPIRE_DAYS=7
    )
    monkeypatch.setattr("app.core.config.settings", "JWT_SECRET_KEY", mock_jwt_secret_key, raising=False)
    monkeypatch.setattr("app.core.config.settings", "JWT_ALGORITHM", mock_jwt_algorithm, raising=False)
    monkeypatch.setattr("app.core.config.settings", "ACCESS_TOKEN_EXPIRE_MINUTES", 15, raising=False)
    monkeypatch.setattr("app.core.config.settings", "REFRESH_TOKEN_EXPIRE_DAYS", 7, raising=False)


class TestAuthServiceTokenCreation:

    def test_create_access_token_default_expiry(self):
        data = {"sub": "testuser@example.com"}
        token = auth_service.create_access_token(data)
        assert isinstance(token, str)

        decoded_token = jwt.decode(
            token, 
            auth_service.settings.JWT_SECRET_KEY.get_secret_value(), 
            algorithms=[auth_service.settings.JWT_ALGORITHM]
        )
        assert decoded_token["sub"] == "testuser@example.com"
        assert decoded_token["type"] == "access"
        expected_expiry = datetime.utcnow() + timedelta(minutes=auth_service.settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        assert abs(datetime.fromtimestamp(decoded_token["exp"]) - expected_expiry) < timedelta(seconds=5)

    def test_create_access_token_custom_expiry(self):
        data = {"sub": "testuser2@example.com"}
        custom_delta = timedelta(hours=1)
        token = auth_service.create_access_token(data, expires_delta=custom_delta)
        assert isinstance(token, str)

        decoded_token = jwt.decode(
            token, 
            auth_service.settings.JWT_SECRET_KEY.get_secret_value(), 
            algorithms=[auth_service.settings.JWT_ALGORITHM]
        )
        assert decoded_token["sub"] == "testuser2@example.com"
        assert decoded_token["type"] == "access"
        expected_expiry = datetime.utcnow() + custom_delta
        assert abs(datetime.fromtimestamp(decoded_token["exp"]) - expected_expiry) < timedelta(seconds=5)

    def test_create_refresh_token_default_expiry(self):
        data = {"sub": "refreshuser@example.com"}
        token = auth_service.create_refresh_token(data)
        assert isinstance(token, str)

        decoded_token = jwt.decode(
            token, 
            auth_service.settings.JWT_SECRET_KEY.get_secret_value(), 
            algorithms=[auth_service.settings.JWT_ALGORITHM]
        )
        assert decoded_token["sub"] == "refreshuser@example.com"
        assert decoded_token["type"] == "refresh"
        expected_expiry = datetime.utcnow() + timedelta(days=auth_service.settings.REFRESH_TOKEN_EXPIRE_DAYS)
        assert abs(datetime.fromtimestamp(decoded_token["exp"]) - expected_expiry) < timedelta(seconds=5)


@pytest.mark.asyncio
class TestAuthServiceTokenVerification:

    async def test_verify_token_valid_access_token(self):
        email = "verifyuser@example.com"
        token = auth_service.create_access_token(data={"sub": email})
        
        token_data = await auth_service.verify_token(token, token_type="access")
        assert isinstance(token_data, TokenData)
        assert token_data.sub == email

    async def test_verify_token_valid_refresh_token(self):
        email = "verifyrefresh@example.com"
        token = auth_service.create_refresh_token(data={"sub": email})
        
        token_data = await auth_service.verify_token(token, token_type="refresh")
        assert isinstance(token_data, TokenData)
        assert token_data.sub == email

    async def test_verify_token_expired(self):
        email = "expireduser@example.com"
        token = auth_service.create_access_token(
            data={"sub": email}, expires_delta=timedelta(seconds=-1) # Expired in the past
        )
        
        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_token(token, token_type="access")
        assert "Token ha expirado" in str(exc_info.value)

    async def test_verify_token_invalid_signature(self):
        email = "invalidsig@example.com"
        token_payload = {"sub": email, "exp": datetime.utcnow() + timedelta(minutes=15), "type": "access"}
        invalid_token = jwt.encode(
            token_payload, "wrong_secret_key", algorithm=auth_service.settings.JWT_ALGORITHM
        )

        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_token(invalid_token, token_type="access")
        assert "Firma de token inválida" in str(exc_info.value)

    async def test_verify_token_malformed(self):
        malformed_token = "this.is.not.a.jwt"
        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_token(malformed_token, token_type="access")
        # The actual message might depend on the jose library's specific error for malformed tokens
        assert "Token malformado" in str(exc_info.value) or "Not enough segments" in str(exc_info.value)

    async def test_verify_token_missing_sub(self):
        token_payload = {"exp": datetime.utcnow() + timedelta(minutes=15), "type": "access"}
        token_no_sub = jwt.encode(
            token_payload, auth_service.settings.JWT_SECRET_KEY.get_secret_value(), algorithm=auth_service.settings.JWT_ALGORITHM
        )
        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_token(token_no_sub, token_type="access")
        assert "El token no contiene un 'sub' (subject) válido" in str(exc_info.value)

    async def test_verify_token_incorrect_type(self):
        email = "wrongtype@example.com"
        refresh_token = auth_service.create_refresh_token(data={"sub": email})
        
        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_token(refresh_token, token_type="access")
        assert "Tipo de token incorrecto, se esperaba 'access' pero se obtuvo 'refresh'" in str(exc_info.value)

    async def test_verify_refresh_token_convenience_function(self):
        email = "refresh_convenience@example.com"
        token = auth_service.create_refresh_token(data={"sub": email})
        token_data = await auth_service.verify_refresh_token(token)
        assert isinstance(token_data, TokenData)
        assert token_data.sub == email

    async def test_verify_refresh_token_fails_with_access_token(self):
        email = "access_as_refresh@example.com"
        token = auth_service.create_access_token(data={"sub": email})
        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_refresh_token(token)
        assert "Tipo de token incorrecto, se esperaba 'refresh' pero se obtuvo 'access'" in str(exc_info.value)


class TestAuthServicePasswordUtils:

    def test_get_password_hash_returns_string(self):
        password = "testpassword123"
        hashed_password = auth_service.get_password_hash(password)
        assert isinstance(hashed_password, str)
        assert hashed_password != password

    def test_verify_password_correct(self):
        password = "securepassword!"
        hashed_password = auth_service.get_password_hash(password)
        assert auth_service.verify_password(password, hashed_password) is True

    def test_verify_password_incorrect(self):
        password = "securepassword!"
        hashed_password = auth_service.get_password_hash(password)
        assert auth_service.verify_password("wrongpassword", hashed_password) is False

    def test_verify_password_empty_input_password(self):
        # Assuming verify_password should handle empty passwords gracefully, though hashing them might be an issue.
        # Depending on PasswordHasher's behavior, this might need adjustment.
        # For now, let's assume it should return False if an empty password is provided against a valid hash.
        password = "valid_password"
        hashed_password = auth_service.get_password_hash(password)
        assert auth_service.verify_password("", hashed_password) is False

    def test_get_password_hash_different_for_same_password(self):
        # Argon2 should produce different hashes for the same password due to salting
        password = "samesame"
        hash1 = auth_service.get_password_hash(password)
        hash2 = auth_service.get_password_hash(password)
        assert hash1 != hash2
        assert auth_service.verify_password(password, hash1) is True
        assert auth_service.verify_password(password, hash2) is True


from app.users.models import User as UserModel # For creating mock User instances
from app.common.errors import UserNotFoundError, DatabaseError as CommonDatabaseError
from app.users import service as users_service_module # to mock user_service inside auth_service
from result import Ok, Err

# Mock SQLAlchemy User model for testing
# You might need to adjust attributes based on your actual User model
class MockUser(UserModel):
    def __init__(self, id=1, email="test@example.com", hashed_password="hashed_pass", is_active=True, is_verified=True, is_superuser=False, first_name="Test", last_name="User"):
        self.id = id
        self.email = email
        self.hashed_password = hashed_password
        self.is_active = is_active
        self.is_verified = is_verified
        self.is_superuser = is_superuser
        self.first_name = first_name
        self.last_name = last_name

    # Add any other methods or properties your User model might have if they are accessed
    # For example, if your User model is a SQLAlchemy declarative base, it might not need this __init__
    # and you'd set attributes directly. For simplicity in mocking, an __init__ is fine.


@pytest.mark.asyncio
class TestAuthServiceAuthenticateUser:

    @pytest.fixture
    def mock_db_session(self):
        return MagicMock(spec=auth_service.AsyncSession)

    @pytest.fixture
    def mock_user_service_get_by_email(self, monkeypatch):
        mock_func = MagicMock()
        # Patch where user_service is looked up by auth_service.authenticate_user
        # This assumes auth_service.user_service is the imported users_service_module
        monkeypatch.setattr(auth_service.user_service, "get_user_by_email", mock_func)
        return mock_func

    @pytest.fixture
    def mock_verify_password(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service, "verify_password", mock_func)
        return mock_func

    async def test_authenticate_user_success(self, mock_db_session, mock_user_service_get_by_email, mock_verify_password):
        test_email = "success@example.com"
        test_password = "correct_password"
        mock_user_instance = MockUser(email=test_email, hashed_password="hashed_pw", is_active=True, is_verified=True)
        
        mock_user_service_get_by_email.return_value = Ok(mock_user_instance)
        mock_verify_password.return_value = True

        authenticated_user = await auth_service.authenticate_user(mock_db_session, test_email, test_password)
        
        assert authenticated_user == mock_user_instance
        mock_user_service_get_by_email.assert_called_once_with(mock_db_session, test_email)
        mock_verify_password.assert_called_once_with(test_password, mock_user_instance.hashed_password)

    async def test_authenticate_user_not_found(self, mock_db_session, mock_user_service_get_by_email):
        test_email = "notfound@example.com"
        test_password = "any_password"
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError(f"User {test_email} not found"))

        with pytest.raises(auth_errors.InvalidCredentialsError) as exc_info:
            await auth_service.authenticate_user(mock_db_session, test_email, test_password)
        assert "Credenciales inválidas" in str(exc_info.value)
        mock_user_service_get_by_email.assert_called_once_with(mock_db_session, test_email)

    async def test_authenticate_user_incorrect_password(self, mock_db_session, mock_user_service_get_by_email, mock_verify_password):
        test_email = "wrongpass@example.com"
        test_password = "incorrect_password"
        mock_user_instance = MockUser(email=test_email, hashed_password="hashed_pw", is_active=True, is_verified=True)

        mock_user_service_get_by_email.return_value = Ok(mock_user_instance)
        mock_verify_password.return_value = False # Simulate incorrect password

        with pytest.raises(auth_errors.InvalidCredentialsError) as exc_info:
            await auth_service.authenticate_user(mock_db_session, test_email, test_password)
        assert "Credenciales inválidas" in str(exc_info.value)
        mock_verify_password.assert_called_once_with(test_password, mock_user_instance.hashed_password)

    async def test_authenticate_user_inactive(self, mock_db_session, mock_user_service_get_by_email, mock_verify_password):
        test_email = "inactive@example.com"
        test_password = "correct_password"
        mock_user_instance = MockUser(email=test_email, is_active=False, is_verified=True) # Inactive user

        mock_user_service_get_by_email.return_value = Ok(mock_user_instance)
        mock_verify_password.return_value = True

        with pytest.raises(auth_errors.InactiveUserError) as exc_info:
            await auth_service.authenticate_user(mock_db_session, test_email, test_password)
        assert "Usuario inactivo" in str(exc_info.value)

    async def test_authenticate_user_unverified(self, mock_db_session, mock_user_service_get_by_email, mock_verify_password):
        test_email = "unverified@example.com"
        test_password = "correct_password"
        mock_user_instance = MockUser(email=test_email, is_active=True, is_verified=False) # Unverified user

        mock_user_service_get_by_email.return_value = Ok(mock_user_instance)
        mock_verify_password.return_value = True

        with pytest.raises(auth_errors.UnverifiedAccountError) as exc_info:
            await auth_service.authenticate_user(mock_db_session, test_email, test_password)
        assert "Cuenta de usuario no verificada" in str(exc_info.value)
    
    async def test_authenticate_user_db_error_on_get_user(self, mock_db_session, mock_user_service_get_by_email):
        test_email = "dberror@example.com"
        test_password = "any_password"
        mock_user_service_get_by_email.return_value = Err(CommonDatabaseError("Simulated DB error"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.authenticate_user(mock_db_session, test_email, test_password)
        assert "Simulated DB error" in str(exc_info.value)


from app.auth.schemas import UserCreate # For UserCreate Pydantic model
from app.users.errors import UserAlreadyExistsError as UsersUserAlreadyExistsError # Specific error from user service

@pytest.mark.asyncio
class TestAuthServiceRegisterUser:

    @pytest.fixture
    def mock_db_session(self):
        return MagicMock(spec=auth_service.AsyncSession)

    @pytest.fixture
    def mock_user_service_get_by_email(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service.user_service, "get_user_by_email", mock_func)
        return mock_func

    @pytest.fixture
    def mock_get_password_hash(self, monkeypatch):
        mock_func = MagicMock(return_value="super_hashed_password")
        monkeypatch.setattr(auth_service, "get_password_hash", mock_func)
        return mock_func

    @pytest.fixture
    def mock_internal_user_service_instance(self, monkeypatch):
        mock_user_service_instance = MagicMock()
        mock_user_service_class = MagicMock(return_value=mock_user_service_instance)
        # Patch the UserService class where it's instantiated in auth_service.register_user
        monkeypatch.setattr(auth_service, "UserService", mock_user_service_class)
        return mock_user_service_instance

    @pytest.fixture
    def user_create_data(self):
        return UserCreate(email="newuser@example.com", password="newpassword123", first_name="New", last_name="User")

    async def test_register_user_success(self, mock_db_session, user_create_data, mock_user_service_get_by_email, mock_get_password_hash, mock_internal_user_service_instance):
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError("User not found")) # User does not exist
        
        mock_created_user = MockUser(email=user_create_data.email, first_name=user_create_data.first_name, last_name=user_create_data.last_name)
        mock_internal_user_service_instance.register_new_user.return_value = Ok(mock_created_user)

        registered_user = await auth_service.register_user(mock_db_session, user_create_data)

        assert registered_user == mock_created_user
        mock_user_service_get_by_email.assert_called_once_with(mock_db_session, user_create_data.email)
        mock_get_password_hash.assert_called_once_with(user_create_data.password)
        
        # Check that UserService was called with the correct data (hashed password)
        args, kwargs = mock_internal_user_service_instance.register_new_user.call_args
        assert "user_data" in kwargs
        user_data_arg = kwargs["user_data"]
        assert user_data_arg.email == user_create_data.email
        assert user_data_arg.hashed_password == "super_hashed_password"
        assert not hasattr(user_data_arg, "password") # Plain password should be removed

    async def test_register_user_email_already_exists_initial_check(self, mock_db_session, user_create_data, mock_user_service_get_by_email):
        mock_existing_user = MockUser(email=user_create_data.email)
        mock_user_service_get_by_email.return_value = Ok(mock_existing_user) # User already exists

        with pytest.raises(auth_errors.EmailAlreadyExistsError) as exc_info:
            await auth_service.register_user(mock_db_session, user_create_data)
        assert f"El correo electrónico {user_create_data.email} ya está registrado" in str(exc_info.value)
        mock_user_service_get_by_email.assert_called_once_with(mock_db_session, user_create_data.email)

    async def test_register_user_db_error_initial_check(self, mock_db_session, user_create_data, mock_user_service_get_by_email):
        mock_user_service_get_by_email.return_value = Err(CommonDatabaseError("Initial DB check failed"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.register_user(mock_db_session, user_create_data)
        assert "Initial DB check failed" in str(exc_info.value)

    async def test_register_user_internal_service_raises_user_already_exists(self, mock_db_session, user_create_data, mock_user_service_get_by_email, mock_internal_user_service_instance):
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError("User not found"))
        mock_internal_user_service_instance.register_new_user.return_value = Err(UsersUserAlreadyExistsError(f"User {user_create_data.email} already exists in sub-service"))

        with pytest.raises(auth_errors.EmailAlreadyExistsError) as exc_info:
            await auth_service.register_user(mock_db_session, user_create_data)
        assert f"User {user_create_data.email} already exists in sub-service" in str(exc_info.value)

    async def test_register_user_internal_service_raises_database_error(self, mock_db_session, user_create_data, mock_user_service_get_by_email, mock_internal_user_service_instance):
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError("User not found"))
        mock_internal_user_service_instance.register_new_user.return_value = Err(CommonDatabaseError("Internal service DB error"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.register_user(mock_db_session, user_create_data)
        assert "Internal service DB error" in str(exc_info.value)

    async def test_register_user_internal_service_raises_unexpected_error(self, mock_db_session, user_create_data, mock_user_service_get_by_email, mock_internal_user_service_instance):
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError("User not found"))
        mock_internal_user_service_instance.register_new_user.return_value = Err(ValueError("Some other unexpected error")) # Using ValueError as an example

        with pytest.raises(auth_errors.AuthServiceError) as exc_info:
            await auth_service.register_user(mock_db_session, user_create_data)
        assert "Error inesperado durante el registro del servicio de usuario: Some other unexpected error" in str(exc_info.value)


@pytest.mark.asyncio
class TestAuthServiceRequestPasswordReset:

    @pytest.fixture
    def mock_db_session(self):
        return MagicMock(spec=auth_service.AsyncSession)

    @pytest.fixture
    def mock_user_service_get_by_email(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service.user_service, "get_user_by_email", mock_func)
        return mock_func

    @pytest.fixture
    def mock_create_password_reset_token(self, monkeypatch):
        mock_func = MagicMock(return_value="mock_password_reset_token")
        # Assuming create_password_reset_token is a distinct function in auth_service
        # If it internally calls create_access_token, you might mock that instead or ensure this mock is correctly placed.
        monkeypatch.setattr(auth_service, "create_password_reset_token", mock_func)
        return mock_func

    @pytest.fixture
    def mock_send_password_reset_email_async(self, monkeypatch):
        # This function is defined inside request_password_reset, so we need to mock the email sending utility it calls.
        # Let's assume it calls a utility like `app.common.email_utils.send_email_async` or similar.
        # For this example, let's assume auth_service.send_password_reset_email_async is the direct target for mocking.
        # If it's an external library, the patch target would change.
        # We are mocking the internal helper `_send_password_reset_email_background` that `request_password_reset` calls.
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service, "_send_password_reset_email_background", mock_func)
        return mock_func

    async def test_request_password_reset_success(self, mock_db_session, mock_user_service_get_by_email, mock_create_password_reset_token, mock_send_password_reset_email_async):
        test_email = "user@example.com"
        mock_user = MockUser(email=test_email, first_name="Test", is_active=True, is_verified=True)
        mock_user_service_get_by_email.return_value = Ok(mock_user)

        result = await auth_service.request_password_reset(mock_db_session, test_email)

        assert result is None # Function returns None on success
        mock_user_service_get_by_email.assert_called_once_with(mock_db_session, test_email)
        mock_create_password_reset_token.assert_called_once_with(data={"sub": test_email})
        mock_send_password_reset_email_async.assert_called_once_with(test_email, "mock_password_reset_token", mock_user.first_name)

    async def test_request_password_reset_user_not_found(self, mock_db_session, mock_user_service_get_by_email):
        test_email = "nonexistent@example.com"
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError("Not found"))

        with pytest.raises(auth_errors.UserNotFoundHTTPError) as exc_info:
            await auth_service.request_password_reset(mock_db_session, test_email)
        assert f"Usuario con email {test_email} no encontrado" in str(exc_info.value.detail)

    async def test_request_password_reset_user_inactive(self, mock_db_session, mock_user_service_get_by_email):
        test_email = "inactive@example.com"
        mock_user = MockUser(email=test_email, is_active=False, is_verified=True)
        mock_user_service_get_by_email.return_value = Ok(mock_user)

        with pytest.raises(auth_errors.InactiveUserHTTPError) as exc_info:
            await auth_service.request_password_reset(mock_db_session, test_email)
        assert "El usuario está inactivo" in str(exc_info.value.detail)

    async def test_request_password_reset_user_not_verified(self, mock_db_session, mock_user_service_get_by_email):
        test_email = "unverified@example.com"
        mock_user = MockUser(email=test_email, is_active=True, is_verified=False)
        mock_user_service_get_by_email.return_value = Ok(mock_user)

        with pytest.raises(auth_errors.UnverifiedAccountHTTPError) as exc_info:
            await auth_service.request_password_reset(mock_db_session, test_email)
        assert "La cuenta de usuario no está verificada" in str(exc_info.value.detail)

    async def test_request_password_reset_db_error_on_get_user(self, mock_db_session, mock_user_service_get_by_email):
        test_email = "dberror@example.com"
        mock_user_service_get_by_email.return_value = Err(CommonDatabaseError("DB lookup failed"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.request_password_reset(mock_db_session, test_email)
        assert "DB lookup failed" in str(exc_info.value)


@pytest.mark.asyncio
class TestAuthServiceResetPassword:

    @pytest.fixture
    def mock_db_session(self):
        return MagicMock(spec=auth_service.AsyncSession)

    @pytest.fixture
    def mock_verify_token(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service, "verify_token", mock_func)
        return mock_func

    @pytest.fixture
    def mock_user_service_get_by_email(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service.user_service, "get_user_by_email", mock_func)
        return mock_func

    @pytest.fixture
    def mock_get_password_hash(self, monkeypatch):
        mock_func = MagicMock(return_value="new_hashed_password")
        monkeypatch.setattr(auth_service, "get_password_hash", mock_func)
        return mock_func

    @pytest.fixture
    def mock_user_service_update_password(self, monkeypatch):
        # This mock needs to be on the user_service instance that auth_service.reset_password uses.
        # Assuming auth_service.user_service is the imported module.
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service.user_service, "update_user_password", mock_func)
        return mock_func

    async def test_reset_password_success(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email, mock_get_password_hash, mock_user_service_update_password):
        test_token = "valid_reset_token"
        new_password = "newSecurePassword123"
        user_email = "user@example.com"
        
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user = MockUser(email=user_email, is_active=True)
        mock_user_service_get_by_email.return_value = Ok(mock_user)
        mock_user_service_update_password.return_value = Ok(mock_user) # Assume update returns the user

        result = await auth_service.reset_password(mock_db_session, test_token, new_password)

        assert result is None # Function returns None on success
        mock_verify_token.assert_called_once_with(test_token, auth_service.TokenType.PASSWORD_RESET)
        mock_user_service_get_by_email.assert_called_once_with(mock_db_session, user_email)
        mock_get_password_hash.assert_called_once_with(new_password)
        mock_user_service_update_password.assert_called_once_with(mock_db_session, user_email, "new_hashed_password")

    async def test_reset_password_invalid_token(self, mock_db_session, mock_verify_token):
        test_token = "invalid_token"
        new_password = "newpass"
        mock_verify_token.return_value = Err(auth_errors.InvalidTokenError("Token verification failed"))

        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.reset_password(mock_db_session, test_token, new_password)
        assert "Token verification failed" in str(exc_info.value)

    async def test_reset_password_token_no_sub(self, mock_db_session, mock_verify_token):
        test_token = "token_no_sub"
        new_password = "newpass"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=None)) # No subject in token

        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.reset_password(mock_db_session, test_token, new_password)
        assert "Token inválido o expirado (sin subject)" in str(exc_info.value)

    async def test_reset_password_user_not_found(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email):
        test_token = "valid_token_unknown_user"
        new_password = "newpass"
        user_email = "unknown@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError("User not found"))

        with pytest.raises(auth_errors.UserNotFoundHTTPError) as exc_info:
            await auth_service.reset_password(mock_db_session, test_token, new_password)
        assert f"Usuario con email {user_email} no encontrado" in str(exc_info.value.detail)

    async def test_reset_password_user_inactive(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email):
        test_token = "valid_token_inactive_user"
        new_password = "newpass"
        user_email = "inactive@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_inactive_user = MockUser(email=user_email, is_active=False)
        mock_user_service_get_by_email.return_value = Ok(mock_inactive_user)

        with pytest.raises(auth_errors.InactiveUserHTTPError) as exc_info:
            await auth_service.reset_password(mock_db_session, test_token, new_password)
        assert "El usuario está inactivo" in str(exc_info.value.detail)

    async def test_reset_password_db_error_on_get_user(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email):
        test_token = "valid_token_db_error_user"
        new_password = "newpass"
        user_email = "dberror@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user_service_get_by_email.return_value = Err(CommonDatabaseError("DB error during get_user"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.reset_password(mock_db_session, test_token, new_password)
        assert "DB error during get_user" in str(exc_info.value)

    async def test_reset_password_update_password_fails(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email, mock_get_password_hash, mock_user_service_update_password):
        test_token = "valid_token_update_fail"
        new_password = "newpass"
        user_email = "updatefail@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user = MockUser(email=user_email, is_active=True)
        mock_user_service_get_by_email.return_value = Ok(mock_user)
        mock_user_service_update_password.return_value = Err(CommonDatabaseError("Failed to update password"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.reset_password(mock_db_session, test_token, new_password)
        assert "Failed to update password" in str(exc_info.value)


@pytest.mark.asyncio
class TestAuthServiceVerifyEmailToken:

    @pytest.fixture
    def mock_db_session(self):
        return MagicMock(spec=auth_service.AsyncSession) # Though verify_email_token itself doesn't take db, its callees might

    @pytest.fixture
    def mock_verify_token(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service, "verify_token", mock_func)
        return mock_func

    @pytest.fixture
    def mock_user_service_get_by_email(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service.user_service, "get_user_by_email", mock_func)
        return mock_func

    @pytest.fixture
    def mock_user_service_update_verification_status(self, monkeypatch):
        mock_func = MagicMock()
        monkeypatch.setattr(auth_service.user_service, "update_user_verification_status", mock_func)
        return mock_func

    async def test_verify_email_token_success(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email, mock_user_service_update_verification_status):
        test_token = "valid_email_verify_token"
        user_email = "verify@example.com"

        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user = MockUser(email=user_email, is_verified=False)
        mock_user_service_get_by_email.return_value = Ok(mock_user)
        mock_user_service_update_verification_status.return_value = Ok(MockUser(email=user_email, is_verified=True))

        # The function verify_email_token actually needs a db session for its internal calls to user_service
        updated_user = await auth_service.verify_email_token(mock_db_session, test_token)

        assert updated_user is not None
        assert updated_user.is_verified is True
        mock_verify_token.assert_called_once_with(test_token, auth_service.TokenType.EMAIL_VERIFICATION)
        mock_user_service_get_by_email.assert_called_once_with(mock_db_session, user_email)
        mock_user_service_update_verification_status.assert_called_once_with(mock_db_session, user_email, True)

    async def test_verify_email_token_invalid_token(self, mock_db_session, mock_verify_token):
        test_token = "invalid_email_token"
        mock_verify_token.return_value = Err(auth_errors.InvalidTokenError("Token verification failed for email"))

        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_email_token(mock_db_session, test_token)
        assert "Token verification failed for email" in str(exc_info.value)

    async def test_verify_email_token_no_sub(self, mock_db_session, mock_verify_token):
        test_token = "email_token_no_sub"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=None))

        with pytest.raises(auth_errors.InvalidTokenError) as exc_info:
            await auth_service.verify_email_token(mock_db_session, test_token)
        assert "Token inválido o expirado (sin subject)" in str(exc_info.value)

    async def test_verify_email_token_user_not_found(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email):
        test_token = "valid_email_token_unknown_user"
        user_email = "unknown_verify@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user_service_get_by_email.return_value = Err(UserNotFoundError("User for email verification not found"))

        with pytest.raises(auth_errors.UserNotFoundHTTPError) as exc_info:
            await auth_service.verify_email_token(mock_db_session, test_token)
        assert f"Usuario con email {user_email} no encontrado" in str(exc_info.value.detail)

    async def test_verify_email_token_user_already_verified(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email):
        test_token = "valid_email_token_already_verified"
        user_email = "already_verified@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_verified_user = MockUser(email=user_email, is_verified=True)
        mock_user_service_get_by_email.return_value = Ok(mock_verified_user)

        with pytest.raises(auth_errors.UserAlreadyVerifiedError) as exc_info:
            await auth_service.verify_email_token(mock_db_session, test_token)
        assert "El usuario ya ha sido verificado previamente" in str(exc_info.value)

    async def test_verify_email_token_db_error_on_get_user(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email):
        test_token = "valid_token_db_error_user_email_verify"
        user_email = "dberror_verify@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user_service_get_by_email.return_value = Err(CommonDatabaseError("DB error during get_user for email verify"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.verify_email_token(mock_db_session, test_token)
        assert "DB error during get_user for email verify" in str(exc_info.value)

    async def test_verify_email_token_update_status_fails(self, mock_db_session, mock_verify_token, mock_user_service_get_by_email, mock_user_service_update_verification_status):
        test_token = "valid_token_update_verify_fail"
        user_email = "updateverifyfail@example.com"
        mock_verify_token.return_value = Ok(auth_service.TokenData(sub=user_email))
        mock_user = MockUser(email=user_email, is_verified=False)
        mock_user_service_get_by_email.return_value = Ok(mock_user)
        mock_user_service_update_verification_status.return_value = Err(CommonDatabaseError("Failed to update verification status"))

        with pytest.raises(CommonDatabaseError) as exc_info:
            await auth_service.verify_email_token(mock_db_session, test_token)
        assert "Failed to update verification status" in str(exc_info.value)


from fastapi import BackgroundTasks # For mocking BackgroundTasks

@pytest.mark.asyncio
class TestAuthServiceSendVerificationEmail:

    @pytest.fixture
    def mock_background_tasks(self):
        return MagicMock(spec=BackgroundTasks)

    @pytest.fixture
    def mock_create_email_verification_token(self, monkeypatch):
        mock_func = MagicMock(return_value="mock_email_verification_token")
        monkeypatch.setattr(auth_service, "create_email_verification_token", mock_func)
        return mock_func

    async def test_send_verification_email_success(self, mock_background_tasks, mock_create_email_verification_token):
        test_email = "new_user_to_verify@example.com"
        test_username = "newverifyuser"

        await auth_service.send_verification_email(mock_background_tasks, test_email, test_username)

        mock_create_email_verification_token.assert_called_once_with(data={"sub": test_email})
        # Verify that add_task was called with the correct background function and its arguments
        mock_background_tasks.add_task.assert_called_once_with(
            auth_service._send_verification_email_background, # The actual background function
            test_email,
            test_username,
            "mock_email_verification_token" # The mocked token
        )

    async def test_send_verification_email_token_creation_failure(self, mock_background_tasks, mock_create_email_verification_token):
        # This scenario assumes create_email_verification_token could raise an exception.
        # If it's a simple wrapper, this might be less relevant unless the underlying create_access_token fails.
        test_email = "token_fail@example.com"
        test_username = "tokenfailuser"
        mock_create_email_verification_token.side_effect = ValueError("Token creation error")

        with pytest.raises(ValueError) as exc_info:
            await auth_service.send_verification_email(mock_background_tasks, test_email, test_username)
        
        assert "Token creation error" in str(exc_info.value)
        mock_create_email_verification_token.assert_called_once_with(data={"sub": test_email})
        mock_background_tasks.add_task.assert_not_called() # Ensure add_task was not called if token creation failed


from app.common import email_utils # For mocking send_email_async

@pytest.mark.asyncio
class TestAuthServiceBackgroundEmailTasks:

    @pytest.fixture
    def mock_send_email_async(self, monkeypatch):
        mock_func = AsyncMock() # Use AsyncMock for async functions
        monkeypatch.setattr(email_utils, "send_email_async", mock_func)
        return mock_func

    @pytest.fixture
    def mock_auth_service_settings(self, monkeypatch, mock_settings_for_auth_service): # Reuse existing settings mock
        # mock_settings_for_auth_service already patches auth_service.settings
        # We just need to ensure it's active and potentially override specific values for these tests if needed.
        # For now, let's assume PROJECT_NAME and API_V1_STR are part of the global settings mock.
        # If specific overrides are needed for email link construction, they can be added here.
        # e.g., monkeypatch.setattr(auth_service.settings, "SERVER_HOST", "http://localhost:8000")
        return auth_service.settings # Return the already patched settings

    async def test_send_password_reset_email_background_success(self, mock_send_email_async, mock_auth_service_settings):
        test_email = "reset_user@example.com"
        test_token = "reset_token_123"
        test_username = "ResetUser"

        # Ensure settings have expected values for link construction
        mock_auth_service_settings.PROJECT_NAME = "TestApp"
        # The link in service.py is /reset-password?token=..., not using API_V1_STR directly for the base URL part
        # It uses settings.SERVER_HOST which is not explicitly in our global mock. Let's add it.
        mock_auth_service_settings.SERVER_HOST = "http://testserver.com"

        await auth_service._send_password_reset_email_background(test_email, test_token, test_username)

        expected_subject = f"Restablecimiento de contraseña para {mock_auth_service_settings.PROJECT_NAME}"
        expected_reset_link = f"{mock_auth_service_settings.SERVER_HOST}/reset-password?token={test_token}"
        expected_environment = {
            "project_name": mock_auth_service_settings.PROJECT_NAME,
            "username": test_username,
            "email": test_email,
            "reset_link": expected_reset_link,
            "valid_hours": mock_auth_service_settings.EMAIL_RESET_TOKEN_EXPIRE_HOURS
        }

        mock_send_email_async.assert_called_once_with(
            email_to=test_email,
            subject_template=expected_subject,
            html_template_name="password_reset.html",
            environment=expected_environment
        )

    async def test_send_password_reset_email_background_send_failure(self, mock_send_email_async, mock_auth_service_settings):
        test_email = "reset_fail@example.com"
        test_token = "reset_token_fail"
        test_username = "ResetFailUser"
        mock_send_email_async.side_effect = Exception("SMTP server down")

        mock_auth_service_settings.PROJECT_NAME = "TestAppFail"
        mock_auth_service_settings.SERVER_HOST = "http://testserverfail.com"

        # The function is designed to catch exceptions and log them, not re-raise.
        # So we check if it runs without error and if the mock was called.
        # For more robust testing, we could also mock the logger and check its output.
        try:
            await auth_service._send_password_reset_email_background(test_email, test_token, test_username)
        except Exception as e:
            pytest.fail(f"_send_password_reset_email_background should not raise an error: {e}")
        
        mock_send_email_async.assert_called_once()

    async def test_send_verification_email_background_success(self, mock_send_email_async, mock_auth_service_settings):
        test_email = "verify_user@example.com"
        test_username = "VerifyUser"
        test_token = "verify_token_456"

        mock_auth_service_settings.PROJECT_NAME = "TestVerifyApp"
        mock_auth_service_settings.SERVER_HOST = "http://testverifyserver.com"

        await auth_service._send_verification_email_background(test_email, test_username, test_token)

        expected_subject = f"Verificación de correo electrónico para {mock_auth_service_settings.PROJECT_NAME}"
        expected_verification_link = f"{mock_auth_service_settings.SERVER_HOST}{auth_service.settings.API_V1_STR}/auth/verify-email?token={test_token}"
        expected_environment = {
            "project_name": mock_auth_service_settings.PROJECT_NAME,
            "username": test_username,
            "email": test_email,
            "verification_link": expected_verification_link,
            "valid_hours": mock_auth_service_settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS
        }

        mock_send_email_async.assert_called_once_with(
            email_to=test_email,
            subject_template=expected_subject,
            html_template_name="email_verification.html",
            environment=expected_environment
        )

    async def test_send_verification_email_background_send_failure(self, mock_send_email_async, mock_auth_service_settings):
        test_email = "verify_fail@example.com"
        test_token = "verify_token_fail_789"
        test_username = "VerifyFailUser"
        mock_send_email_async.side_effect = Exception("SMTP server hiccup")

        mock_auth_service_settings.PROJECT_NAME = "TestVerifyAppFail"
        mock_auth_service_settings.SERVER_HOST = "http://testverifyserverfail.com"

        try:
            await auth_service._send_verification_email_background(test_email, test_username, test_token)
        except Exception as e:
            pytest.fail(f"_send_verification_email_background should not raise an error: {e}")
        
        mock_send_email_async.assert_called_once()

