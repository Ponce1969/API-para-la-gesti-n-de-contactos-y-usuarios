"""
Servicio de autenticación.

Este módulo proporciona funciones para manejar la autenticación de usuarios,
generación y verificación de tokens JWT, y operaciones relacionadas con la seguridad.
"""

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Union

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.config import settings
from app.common.errors import DatabaseError, ResourceNotFoundError
from app.users import service as user_service
import logging # Added for logging
from app.users.models import User
from app.users.schemas import UserCreate, UserUpdate # Import UserCreate and UserUpdate
from app.users.repository import UserRepository # Added
from app.users.service import UserService # Added
from app.users.errors import UserNotFoundError, UserAlreadyExistsError as UsersUserAlreadyExistsError # Added

from . import errors
from .schemas import TokenData

logger = logging.getLogger(__name__) # Added logger

# Configuración de contraseñas
pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verifica si una contraseña en texto plano coincide con un hash.

    Args:
        plain_password: Contraseña en texto plano.
        hashed_password: Hash de la contraseña almacenado.

    Returns:
        bool: True si la contraseña es válida, False en caso contrario.
    """
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    """
    Genera un hash seguro de una contraseña.

    Args:
        password: Contraseña en texto plano.

    Returns:
        str: Hash de la contraseña.
    """
    return pwd_context.hash(password)


async def authenticate_user(
    db: AsyncSession, email: str, password: str
) -> Optional[User]:
    """
    Autentica a un usuario con su correo electrónico y contraseña.

    El proceso de autenticación implica:
    1. Buscar al usuario por su correo electrónico utilizando `user_service.get_user_by_email`.
    2. Si el usuario no se encuentra, se considera una credencial inválida.
    3. Verificar la contraseña proporcionada contra el hash almacenado usando `verify_password`.
    4. Si la contraseña no coincide, se considera una credencial inválida.
    5. Comprobar si la cuenta del usuario está activa (`is_active`).
    6. Comprobar si la cuenta del usuario ha sido verificada (`is_verified`).

    Args:
        db: La sesión de base de datos asíncrona (`AsyncSession`).
        email: El correo electrónico del usuario a autenticar.
        password: La contraseña en texto plano del usuario.

    Returns:
        User: El objeto `User` (modelo SQLAlchemy) del usuario autenticado si las credenciales
              son válidas y la cuenta cumple con los requisitos de activación y verificación.
              Devuelve `None` implícitamente si el flujo no resulta en un usuario válido
              (aunque este caso se maneja levantando excepciones).

    Raises:
        errors.InvalidCredentialsError: Si el correo electrónico no se encuentra o si la
                                        contraseña proporcionada es incorrecta.
        errors.InactiveUserError: Si el usuario es encontrado y la contraseña es correcta,
                                  pero la cuenta está marcada como inactiva.
        errors.UnverifiedAccountError: Si el usuario es encontrado, la contraseña es correcta
                                       y la cuenta está activa, pero no ha sido verificada
                                       (e.g., mediante confirmación por correo electrónico).
    """
    user_result = await user_service.get_user_by_email(db, email)

    if user_result.is_failure():
        # Log the specific error from user_service if needed, then raise generic auth error
        # error = user_result.error()
        # logger.warning(f"Failed to find user '{email}' during auth: {error}")
        raise errors.InvalidCredentialsError("Email o contraseña incorrectos")

    user: User = user_result.unwrap()

    if not verify_password(password, user.hashed_password):
        raise errors.InvalidCredentialsError("Email o contraseña incorrectos")

    if not user.is_active:
        raise errors.InactiveUserError("Usuario inactivo")

    if not user.is_verified:
        raise errors.UnverifiedAccountError(
            "Por favor, verifique su correo electrónico"
        )

    return user


def create_access_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Crea un token de acceso JWT genérico.

    Esta función codifica los datos proporcionados en un token JWT, añadiendo una
    fecha de expiración y un tipo de token ("access") al payload.
    Utiliza la clave secreta JWT (`settings.JWT_SECRET_KEY`) y el algoritmo
    (`settings.JWT_ALGORITHM`) definidos en la configuración.

    Args:
        data (Dict[str, Any]): Un diccionario con los datos a incluir en el payload
                               del token (e.g., `{"sub": "user_email"}`).
        expires_delta (Optional[timedelta]): Un objeto `timedelta` que especifica
                                             la duración de validez del token. Si es `None`,
                                             se utiliza un valor predeterminado de 15 minutos.

    Returns:
        str: El token JWT firmado como una cadena de texto.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)

    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(
        to_encode, settings.JWT_SECRET_KEY.get_secret_value(), algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    data: Dict[str, Any], expires_delta: Optional[timedelta] = None
) -> str:
    """
    Crea un token de actualización JWT.

    Esta función codifica los datos proporcionados en un token JWT, añadiendo una
    fecha de expiración y un tipo de token ("refresh") al payload.
    Utiliza la clave secreta específica para tokens de actualización
    (`settings.JWT_REFRESH_SECRET_KEY`) y el algoritmo (`settings.JWT_ALGORITHM`)
    definidos en la configuración.

    Args:
        data (Dict[str, Any]): Un diccionario con los datos a incluir en el payload
                               del token (e.g., `{"sub": "user_email"}`).
        expires_delta (Optional[timedelta]): Un objeto `timedelta` que especifica
                                             la duración de validez del token. Si es `None`,
                                             se utiliza el valor predeterminado de
                                             `settings.REFRESH_TOKEN_EXPIRE_DAYS`.

    Returns:
        str: El token JWT de actualización firmado como una cadena de texto.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(
        to_encode,
        settings.JWT_REFRESH_SECRET_KEY.get_secret_value(), # Use the specific refresh token secret key
        algorithm=settings.JWT_ALGORITHM,
    )
    return encoded_jwt


def create_password_reset_token(data: Dict[str, Any]) -> str:
    """
    Crea un token específico para el restablecimiento de contraseña.

    Este token es un tipo especializado de token de acceso, con una expiración
    definida por `settings.RESET_PASSWORD_TOKEN_EXPIRE_HOURS`. Incluye los
    datos proporcionados (generalmente el email del usuario como 'sub') en el payload.
    Utiliza `create_access_token` internamente.

    Args:
        data (Dict[str, Any]): Datos a incluir en el token, típicamente `{"sub": email}`.

    Returns:
        str: El token JWT firmado para el restablecimiento de contraseña.
    """
    return create_access_token(
        data,
        expires_delta=timedelta(hours=settings.RESET_PASSWORD_TOKEN_EXPIRE_HOURS),
    )


def create_email_verification_token(data: Dict[str, Any]) -> str:
    """
    Crea un token específico para la verificación de correo electrónico.

    Este token es un tipo especializado de token de acceso, con una expiración
    definida por `settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS`. Incluye los
    datos proporcionados (generalmente el email del usuario como 'sub') en el payload.
    Utiliza `create_access_token` internamente.

    Args:
        data (Dict[str, Any]): Datos a incluir en el token, típicamente `{"sub": email}`.

    Returns:
        str: El token JWT firmado para la verificación de correo electrónico.
    """
    return create_access_token(
        data,
        expires_delta=timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS),
    )


async def verify_token(token: str, token_type: str = "access") -> TokenData:
    """
    Verifica y decodifica un token JWT, sea de acceso o de actualización.

    Esta función se encarga de:
    1. Seleccionar la clave secreta adecuada (`settings.JWT_SECRET_KEY` para 'access',
       `settings.JWT_REFRESH_SECRET_KEY` para 'refresh') según el `token_type`.
    2. Decodificar el token utilizando el algoritmo `settings.JWT_ALGORITHM`.
    3. Validar que el payload del token contenga el campo 'sub' (subject).
    4. Validar que el tipo de token en el payload ('type') coincida con el `token_type` esperado.

    Args:
        token (str): El token JWT (cadena) a verificar.
        token_type (str): El tipo de token esperado. Debe ser 'access' o 'refresh'.
                          Por defecto es 'access'.

    Returns:
        TokenData: Un objeto `TokenData` que contiene el 'sub' (subject) del token
                   si la verificación es exitosa.

    Raises:
        errors.InvalidTokenError: Si el `token_type` especificado es inválido,
                                  si el token está malformado, ha expirado,
                                  su firma es incorrecta, no contiene el campo 'sub',
                                  o si el tipo de token en el payload no coincide
                                  con el `token_type` esperado.
                                  También se levanta si ocurre cualquier `JWTError`
                                  durante la decodificación.
    """
    credentials_exception = errors.InvalidTokenError("No se pudo validar el token")

    try:
        if token_type == "access":
            secret_key = settings.JWT_SECRET_KEY.get_secret_value()
        elif token_type == "refresh":
            secret_key = settings.JWT_REFRESH_SECRET_KEY.get_secret_value()
        else:
            logger.error(f"Invalid token_type '{token_type}' specified for verification.")
            raise errors.InvalidTokenError("Tipo de token inválido especificado para verificación")

        payload = jwt.decode(
            token, secret_key, algorithms=[settings.JWT_ALGORITHM]
        )

        subject: Optional[str] = payload.get("sub")
        if subject is None:
            logger.warning("Token JWT no contiene 'sub' (subject) en el payload.")
            raise credentials_exception

        token_type_from_payload = payload.get("type")
        if token_type_from_payload != token_type:
            logger.warning(f"Tipo de token en payload ('{token_type_from_payload}') no coincide con el esperado ('{token_type}').")
            raise errors.InvalidTokenError(
                f"Tipo de token inválido: se esperaba {token_type} pero se obtuvo {token_type_from_payload}"
            )

        token_data = TokenData(sub=subject) # Use 'sub' for TokenData
        return token_data

    except JWTError as e:
        logger.warning(f"Error de JWT al verificar token ({token_type}): {e}")
        raise credentials_exception


async def verify_refresh_token(token: str) -> TokenData:
    """
    Verifica un token de actualización JWT.

    Esta función es un envoltorio conveniente alrededor de `verify_token`,
    llamándola específicamente con `token_type="refresh"`.

    Args:
        token (str): El token de actualización JWT a verificar.

    Returns:
        TokenData: Datos del token decodificados si la verificación es exitosa.

    Raises:
        errors.InvalidTokenError: Si el token es inválido, ha expirado, o no es
                                  un token de tipo 'refresh' válido.
    """
    return await verify_token(token, "refresh")


async def register_user(db: AsyncSession, user_data: UserCreate) -> User: # Returns SQLAlchemy User
    """
    Registra un nuevo usuario en el sistema.

    Este proceso implica:
    1. Verificar si ya existe un usuario con el correo electrónico proporcionado.
    2. Hashear la contraseña del nuevo usuario.
    3. Utilizar el servicio de usuarios (`UserService`) para crear la nueva entrada de usuario
       en la base de datos.
    4. Gestionar y propagar errores específicos si el correo ya existe o si ocurren
       problemas durante la interacción con la base de datos.

    Args:
        db: La sesión de base de datos asíncrona (`AsyncSession`).
        user_data: Un objeto `UserCreate` con los datos del usuario a registrar
                   (email, contraseña en texto plano, nombre completo, etc.).

    Returns:
        User: El objeto `User` (modelo SQLAlchemy) del usuario recién creado y guardado
              en la base de datos.

    Raises:
        errors.EmailAlreadyExistsError: Si el correo electrónico proporcionado ya está
                                        registrado en el sistema.
        DatabaseError: Si ocurre un error genérico de base de datos durante la verificación
                       de existencia del usuario o durante el proceso de registro.
        errors.AuthServiceError: Si ocurre un error inesperado no capturado específicamente
                                 durante el proceso de registro.
    """
    # 1. Check if user already exists
    # user_service.get_user_by_email now returns Result[User, UserNotFoundError | DatabaseError]
    existing_user_check = await user_service.get_user_by_email(db, user_data.email)
    if existing_user_check.is_success():
        logger.info(f"Intento de registro para email existente: {user_data.email}")
        raise errors.EmailAlreadyExistsError(f"El correo electrónico {user_data.email} ya está registrado")
    else:
        # User lookup failed, check the error type
        error = existing_user_check.error()
        if not isinstance(error, UserNotFoundError):
            # It's some other DatabaseError from user_service.get_user_by_email
            logger.error(f"Error de base de datos al verificar si el usuario '{user_data.email}' existe: {error}")
            raise DatabaseError(f"Error de base de datos al verificar la existencia del usuario: {error}")
        
        # Only proceed if UserNotFoundError, meaning user does not exist
        logger.info(f"Usuario con email '{user_data.email}' no encontrado, procediendo con el registro.")
        try:
            # 2. Register the new user using UserService
            user_repo = UserRepository(db)
            _user_service = UserService(user_repo)

            # Hashear la contraseña antes de crear el usuario
            hashed_password = get_password_hash(user_data.password)
            user_create_data_dict = user_data.model_dump()
            user_create_data_dict["hashed_password"] = hashed_password
            del user_create_data_dict["password"] # Remove plain password
            user_create_with_hashed_pwd = UserCreate(**user_create_data_dict)

            new_user_result = await _user_service.register_new_user(user_data=user_create_with_hashed_pwd)

            if new_user_result.is_failure():
                error = new_user_result.error()
                logger.error(f"Error al registrar nuevo usuario '{user_data.email}': {error}")
                if isinstance(error, UsersUserAlreadyExistsError):
                    # This specific error should ideally be caught by the initial check,
                    # but if it occurs here, it's still an EmailAlreadyExistsError.
                    raise errors.EmailAlreadyExistsError(str(error))
                elif isinstance(error, DatabaseError):
                    raise error # Re-raise the original DatabaseError
                else:
                    # Catch-all for other errors from _user_service.register_new_user
                    raise errors.AuthServiceError(f"Error inesperado durante el registro del servicio de usuario: {error}")

            created_user = new_user_result.unwrap()
            logger.info(f"Usuario '{created_user.email}' registrado exitosamente.")

            # Consider sending verification email after successful registration
            # try:
            #     await send_verification_email(db, created_user.email)
            # except Exception as e:
            #     logger.error(f"Error al enviar correo de verificación a {created_user.email}: {e}")

            return created_user

        except errors.EmailAlreadyExistsError as e_exists:
            logger.warning(f"Intento de registrar email existente '{user_data.email}' detectado dentro del bloque try: {e_exists}")
            raise  # Re-raise the EmailAlreadyExistsError
        except DatabaseError as db_err:
            logger.error(f"Error de base de datos durante el registro del usuario {user_data.email}: {db_err}", exc_info=True)
            raise # Re-raise the DatabaseError to be handled by the caller or a generic handler
        except errors.AuthServiceError as auth_svc_err:
            logger.error(f"Error del servicio de autenticación durante el registro {user_data.email}: {auth_svc_err}", exc_info=True)
            raise # Re-raise the AuthServiceError
        except Exception as e: # Catch any other unexpected errors during registration process
            logger.error(f"Error inesperado durante el proceso de registro del usuario {user_data.email}: {str(e)}", exc_info=True)
            raise errors.AuthServiceError(f"Error inesperado al registrar el usuario: {str(e)}")  # Ensure an error is raised


async def send_verification_email(db: AsyncSession, email: str) -> None:
    """
    Envía un correo electrónico de verificación al usuario especificado.

    Este proceso implica:
    1. Buscar al usuario por su correo electrónico.
    2. Si el usuario no se encuentra, se levanta `ResourceNotFoundError`.
    3. Si el usuario ya está verificado, se registra un mensaje informativo y no se envía correo.
    4. Generar un token de verificación de correo electrónico usando `create_email_verification_token`.
    5. Construir la URL de verificación que el usuario usará.
    6. Enviar el correo electrónico de forma asíncrona en segundo plano
       utilizando `_send_verification_email_background`.

    Args:
        db (AsyncSession): La sesión de base de datos asíncrona.
        email (str): El correo electrónico del usuario al que se enviará la verificación.

    Raises:
        errors.ResourceNotFoundError: Si no se encuentra ningún usuario con el `email` proporcionado.
        errors.UserAlreadyVerifiedError: Si el usuario ya tiene su cuenta verificada.
        errors.DatabaseError: Si ocurre un error al interactuar con la base de datos
                              (propagado desde `user_service.get_user_by_email`).
        errors.AuthServiceError: Si ocurre un error inesperado durante la generación del token
                                 o al encolar el envío del correo.
    """
    user_result = await user_service.get_user_by_email(db, email=email)
    if user_result.is_failure():
        error = user_result.error()
        # Log the error, but do not expose to the client whether the user exists or not.
        if isinstance(error, UserNotFoundError):
            logger.info(f"Solicitud de reseteo de contraseña para email no registrado: {email}")
        else: # DatabaseError
            logger.error(f"Error de BD al buscar usuario '{email}' para reseteo de contraseña: {error}")
        return # Silently return as per original logic
    
    user: User = user_result.unwrap()

    # Crear token de verificación
    token_data = {"sub": user.email} # 'sub' (subject) is typically user ID or unique identifier
    token = create_access_token(
        token_data,
        expires_delta=timedelta(hours=settings.EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS),
    )

    # Aquí iría la lógica para enviar el correo con el token
    # Por ejemplo, usando una biblioteca como fastapi-mail
    logger.info(f"Se enviaría correo de verificación a {user.email} con token: {token}")


async def verify_email_token(db: AsyncSession, token: str) -> User:
    """
    Verifica un token de verificación de correo electrónico y actualiza el estado del usuario.

    Este proceso implica:
    1. Verificar el token JWT proporcionado usando `verify_token` (esperando tipo 'access').
       Si el token es inválido o ha expirado, se levanta `errors.InvalidTokenError`.
    2. Extraer el correo electrónico del usuario (subject 'sub') del payload del token.
    3. Buscar al usuario en la base de datos por el correo electrónico extraído.
       Si no se encuentra, se levanta `errors.ResourceNotFoundError`.
    4. Comprobar si el usuario ya está verificado. Si es así, se devuelve el usuario
       sin realizar cambios, registrando un mensaje informativo.
    5. Si el usuario no está verificado, se actualiza su estado a `is_verified = True`.
    6. Guardar los cambios en la base de datos.
    7. Devolver el objeto `User` actualizado.

    Args:
        db (AsyncSession): La sesión de base de datos asíncrona.
        token (str): El token JWT de verificación de correo electrónico.

    Returns:
        User: El objeto `User` (modelo SQLAlchemy) con el estado `is_verified` actualizado a `True`.

    Raises:
        errors.InvalidTokenError: Si el token JWT es inválido, ha expirado, no es del tipo
                                  esperado, o no contiene un 'sub' (subject) válido.
        errors.ResourceNotFoundError: Si no se encuentra ningún usuario con el correo electrónico
                                      extraído del token.
        errors.DatabaseError: Si ocurre un error al interactuar con la base de datos durante
                              la búsqueda o actualización del usuario.
        errors.AuthServiceError: Si ocurre un error inesperado no capturado específicamente.
    """
    try:
        # Verificar el token
        token_payload: TokenData = await verify_token(token, token_type="access") # Assuming email verification token is an access token type
    except errors.InvalidTokenError as e:
        logger.warning(f"Intento de verificar email con token inválido: {e}")
        raise

    if not token_payload.sub:
        logger.error("Token de verificación de email no contiene 'sub'.")
        raise errors.InvalidTokenError("Token de verificación inválido (sin subject)")

    # Obtener el usuario
    user_result = await user_service.get_user_by_email(db, email=token_payload.sub)
    if user_result.is_failure():
        error = user_result.error()
        logger.warning(f"Usuario '{token_payload.sub}' no encontrado durante verificación de email: {error}")
        if isinstance(error, UserNotFoundError):
            # Use auth_errors.InvalidTokenError as the user tied to token doesn't exist
            raise errors.InvalidTokenError(f"Usuario asociado al token de verificación no encontrado.")
        else: # DatabaseError
            raise DatabaseError(f"Error de BD al buscar usuario {token_payload.sub} para verificar email.")
    
    user: User = user_result.unwrap()

    if user.is_verified:
        logger.info(f"Usuario '{user.email}' ya está verificado.")
        return user

    # Actualizar el estado de verificación del usuario
    user_update_schema = UserUpdate(is_verified=True)
    updated_user_result = await user_service.update_user(
        db,
        user_id=user.id,
        user_update_data=user_update_schema
    )
    if updated_user_result.is_failure():
        update_error = updated_user_result.error()
        logger.error(f"Error al actualizar usuario '{user.email}' a verificado: {update_error}")
        # Consider specific error types from user_service.update_user if available
        raise DatabaseError(f"Error al marcar usuario '{user.email}' como verificado.")
    
    logger.info(f"Usuario '{user.email}' verificado exitosamente.")
    return updated_user_result.unwrap()


async def send_password_reset_email(db: AsyncSession, email: str) -> None:
    """
    Envía un correo electrónico para restablecer la contraseña del usuario especificado.

    Este proceso implica:
    1. Buscar al usuario por su correo electrónico.
    2. Si el usuario no se encuentra, se levanta `ResourceNotFoundError`.
    3. Generar un token de restablecimiento de contraseña usando `create_password_reset_token`.
    4. Construir la URL de restablecimiento de contraseña que el usuario usará.
    5. Enviar el correo electrónico de forma asíncrona en segundo plano
       utilizando `_send_password_reset_email_background`.

    Args:
        db (AsyncSession): La sesión de base de datos asíncrona.
        email (str): El correo electrónico del usuario que solicitó el restablecimiento.

    Raises:
        errors.ResourceNotFoundError: Si no se encuentra ningún usuario con el `email` proporcionado.
        errors.DatabaseError: Si ocurre un error al interactuar con la base de datos
                              (propagado desde `user_service.get_user_by_email`).
        errors.AuthServiceError: Si ocurre un error inesperado durante la generación del token
                                 o al encolar el envío del correo.
    """
    user_result = await user_service.get_user_by_email(db, email=email)
    if user_result.is_failure():
        error = user_result.error()
        # Log the error, but do not expose to the client whether the user exists or not.
        if isinstance(error, UserNotFoundError):
            logger.info(f"Solicitud de reseteo de contraseña para email no registrado: {email}")
        else: # DatabaseError
            logger.error(f"Error de BD al buscar usuario '{email}' para reseteo de contraseña: {error}")
        return # Silently return as per original logic
    
    user: User = user_result.unwrap()

    # Crear token de restablecimiento
    token_data_payload = {"sub": user.email} # Ensure 'sub' contains the email
    token = create_access_token(
        token_data_payload,
        expires_delta=timedelta(hours=settings.RESET_PASSWORD_TOKEN_EXPIRE_HOURS),
    )

    # TODO: Implementar el envío real del correo electrónico
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token}"
    logger.info(f"Se enviaría correo de reseteo de contraseña a {user.email} con URL: {reset_url}")


async def reset_password(db: AsyncSession, token: str, new_password: str) -> User:
    """
    Restablece la contraseña de un usuario utilizando un token de restablecimiento.

    Este proceso implica:
    1. Verificar el token JWT de restablecimiento proporcionado usando `verify_token`
       (esperando tipo 'access'). Si es inválido o ha expirado, se levanta `errors.InvalidTokenError`.
    2. Extraer el correo electrónico del usuario (subject 'sub') del payload del token.
    3. Buscar al usuario en la base de datos por el correo electrónico extraído.
       Si no se encuentra, se levanta `errors.ResourceNotFoundError`.
    4. Hashear la nueva contraseña proporcionada usando `get_password_hash`.
    5. Actualizar la contraseña hasheada del usuario en la base de datos.
    6. Guardar los cambios en la base de datos.
    7. Devolver el objeto `User` actualizado.

    Args:
        db (AsyncSession): La sesión de base de datos asíncrona.
        token (str): El token JWT de restablecimiento de contraseña.
        new_password (str): La nueva contraseña en texto plano.

    Returns:
        User: El objeto `User` (modelo SQLAlchemy) con la contraseña actualizada.

    Raises:
        errors.InvalidTokenError: Si el token JWT es inválido, ha expirado, no es del tipo
                                  esperado, o no contiene un 'sub' (subject) válido.
        errors.ResourceNotFoundError: Si no se encuentra ningún usuario con el correo electrónico
                                      extraído del token.
        errors.DatabaseError: Si ocurre un error al interactuar con la base de datos durante
                              la búsqueda o actualización del usuario.
        errors.AuthServiceError: Si ocurre un error inesperado no capturado específicamente.
    """
    try:
        # Verificar el token (asumiendo que el token de reseteo es un 'access' token type)
        token_payload: TokenData = await verify_token(token, token_type="access")
    except errors.InvalidTokenError as e:
        logger.warning(f"Intento de resetear contraseña con token inválido: {e}")
        raise
        raise DatabaseError("Error inesperado durante el reseteo de contraseña.")


async def revoke_token(db: AsyncSession, token: str) -> None:
    """
    Revoca un token JWT agregándolo a la lista negra (blacklist) en la base de datos.

    Este proceso implica:
    1. Decodificar el token JWT para extraer su 'jti' (JWT ID) y 'exp' (expiration time).
       Si el token está malformado o no contiene estos campos, se levanta `errors.InvalidTokenError`.
    2. Crear una instancia del modelo `BlacklistedToken` con el `jti` y `exp` del token.
    3. Añadir la instancia a la sesión de la base de datos y confirmar los cambios.
       Si ocurre un error durante la interacción con la base de datos, se propaga.

    Nota: Esta función no verifica la validez de la firma del token ni si ha expirado
    antes de intentar decodificarlo para obtener el 'jti'. La validación de la firma
    y expiración debe hacerse antes de llamar a esta función si es necesario (e.g.,
    usando `verify_token`). El propósito principal aquí es registrar el 'jti' para
    prevenir su uso futuro, incluso si ya ha expirado (para evitar reutilización si
    la ventana de expiración es muy corta o si hay problemas de sincronización de tiempo).

    Args:
        db (AsyncSession): La sesión de base de datos asíncrona.
        token (str): El token JWT (cadena) que se va a revocar.

    Raises:
        errors.InvalidTokenError: Si el token no puede ser decodificado, no contiene
                                  el campo 'jti' o 'exp', o si el 'jti' ya existe
                                  en la lista negra (lo que podría indicar un intento
                                  de doble revocación o un problema de colisión de 'jti').
        errors.DatabaseError: Si ocurre un error al interactuar con la base de datos
                              al intentar guardar el token en la lista negra.
        errors.AuthServiceError: Si ocurre un error inesperado no capturado específicamente.
    """
    try:
        # Verificar el token para obtener la fecha de expiración
        payload = jwt.decode(
            token,
            settings.SECRET_KEY,
            algorithms=[settings.ALGORITHM],
            options={"verify_aud": False, "verify_exp": False},
        )

        # Calcular el tiempo restante hasta la expiración
        expire_timestamp = payload.get("exp")
        if not expire_timestamp:
            raise errors.InvalidTokenError("Token sin fecha de expiración")

        expire = datetime.utcfromtimestamp(expire_timestamp)
        now = datetime.utcnow()

        # Si el token ya expiró, no es necesario revocarlo
        if expire < now:
            return

        # Agregar el token a la lista negra
        # TODO: Implementar la lógica de lista negra en la base de datos
        # Por ahora, solo imprimimos el token revocado para pruebas
        print(f"Token revocado: {token}")

    except JWTError as e:
        raise errors.InvalidTokenError("Token inválido") from e
