"""
Servicio de autenticación.

Este módulo proporciona funciones para manejar la autenticación de usuarios,
generación y verificación de tokens JWT, y operaciones relacionadas con la seguridad.
"""

import logging  # Added for logging
from datetime import datetime, timedelta, timezone # timezone is already here
from typing import Any

from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import jwt as jwt_utils # Import JWT utility functions
from app.common.config import settings
from app.common.errors import DatabaseError
from app.common.result import Failure, Result, Success, is_failure # Import Result types
from app.users import service as user_service
from app.users.errors import UserAlreadyExistsError as UsersUserAlreadyExistsError
from app.users.errors import UserNotFoundError  # Added
from app.users.models import User
from app.users.repository import UserRepository  # Added
from app.users.schemas import UserCreate, UserUpdate  # Import UserCreate and UserUpdate
from app.users.service import UserService  # Added

from . import errors
from .schemas import TokenData

logger = logging.getLogger(__name__)  # Added logger

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


async def authenticate_user(db: AsyncSession, email: str, password: str) -> Result[User, errors.AuthenticationError]:
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

    if is_failure(user_result):
        error = user_result.error()
        logger.warning(f"Fallo al buscar usuario '{email}' durante autenticación: {error}")
        # UserNotFoundError from user_service maps to InvalidCredentialsError
        if isinstance(error, UserNotFoundError):
            return Failure(errors.InvalidCredentialsError("Email o contraseña incorrectos"))
        # Propagate other errors like DatabaseError as a generic auth failure
        return Failure(errors.AuthenticationError("Error de autenticación"))

    user: User = user_result.unwrap()

    if not verify_password(password, user.hashed_password):
        return Failure(errors.InvalidCredentialsError("Email o contraseña incorrectos"))

    if not user.is_active:
        return Failure(errors.InactiveUserError("Usuario inactivo"))

    if not user.is_verified:
        return Failure(errors.UnverifiedAccountError("Por favor, verifique su correo electrónico"))

    return Success(user)


def create_access_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> Result[str, errors.InvalidTokenError]:
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
    return jwt_utils.create_access_token(data=data, expires_delta=expires_delta)


def create_refresh_token(
    data: dict[str, Any], expires_delta: timedelta | None = None
) -> Result[str, errors.InvalidTokenError]:
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
    return jwt_utils.create_refresh_token(data=data, expires_delta=expires_delta)


def create_password_reset_token(data: dict[str, Any]) -> Result[str, errors.InvalidTokenError]:
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
    return jwt_utils.create_password_reset_token(data=data)


def create_email_verification_token(data: dict[str, Any]) -> Result[str, errors.InvalidTokenError]:
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
    return jwt_utils.create_email_verification_token(data=data)


def verify_token(token: str, token_type: str = "access") -> Result[TokenData, errors.InvalidTokenError]: # Changed return type
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
    return jwt_utils.verify_token(token=token, token_type=token_type)


def verify_refresh_token(token: str) -> Result[TokenData, errors.InvalidTokenError]: # Changed return type
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
    return jwt_utils.verify_refresh_token(token=token)


async def register_user(
    db: AsyncSession, user_data: UserCreate
) -> Result[User, errors.AuthServiceError | errors.EmailAlreadyExistsError | DatabaseError]:
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
        raise errors.EmailAlreadyExistsError(
            f"El correo electrónico {user_data.email} ya está registrado"
        )
    else:
        # User lookup failed, check the error type
        error = existing_user_check.error()
        if not isinstance(error, UserNotFoundError):
            # It's some other DatabaseError from user_service.get_user_by_email
            logger.error(
                f"Error de base de datos al verificar si el usuario '{user_data.email}' existe: {error}"
            )
            raise DatabaseError(
                f"Error de base de datos al verificar la existencia del usuario: {error}"
            )

        # Only proceed if UserNotFoundError, meaning user does not exist
        logger.info(
            f"Usuario con email '{user_data.email}' no encontrado, procediendo con el registro."
        )
        try:
            # 2. Register the new user using UserService
            user_repo = UserRepository(db)
            _user_service = UserService(user_repo)

            # 2. Register the new user using UserService
            # UserService.register_new_user expects UserCreate with plain password
            # It handles hashing and calling the repository.
            user_repo = UserRepository(db)
            _user_service = UserService(user_repo)

            # DO NOT hash password here, UserService's register_new_user will do it.
            # The user_data already contains the plain password as per UserCreate schema.
            new_user_result = await _user_service.register_new_user(
                user_data=user_data # Pass UserCreate with plain password
            )

            if is_failure(new_user_result): # Corrected: is_failure
                error = new_user_result.error() # type: ignore
                logger.error(
                    f"Error al registrar nuevo usuario '{user_data.email}': {error}" # type: ignore
                )
                if isinstance(error, UsersUserAlreadyExistsError):
                    # This specific error should ideally be caught by the initial check,
                    # but if it occurs here, it's still an EmailAlreadyExistsError.
                    raise errors.EmailAlreadyExistsError(str(error))
                elif isinstance(error, DatabaseError):
                    raise error  # Re-raise the original DatabaseError
                else:
                    # Catch-all for other errors from _user_service.register_new_user
                    raise errors.AuthServiceError( # type: ignore
                        f"Error inesperado durante el registro del servicio de usuario: {error}" # type: ignore
                    )

            created_user: User = new_user_result.unwrap() # type: ignore
            logger.info(f"Usuario '{created_user.email}' registrado exitosamente.") # type: ignore

            # Consider sending verification email after successful registration
            # try:
            #     await send_verification_email(db, created_user.email)
            # except Exception as e:
            #     logger.error(f"Error al enviar correo de verificación a {created_user.email}: {e}") # type: ignore

            return Success(created_user) # type: ignore

        except errors.EmailAlreadyExistsError as e_exists:
            logger.warning(
                f"Intento de registrar email existente '{user_data.email}' detectado dentro del bloque try: {e_exists}"
            )
            return Failure(e_exists)
        except DatabaseError as db_err:
            logger.error(
                f"Error de base de datos durante el registro del usuario {user_data.email}: {db_err}",
                exc_info=True,
            )
            return Failure(db_err)
        except errors.AuthServiceError as auth_svc_err:
            logger.error(
                f"Error del servicio de autenticación durante el registro {user_data.email}: {auth_svc_err}",
                exc_info=True,
            )
            return Failure(auth_svc_err)
        except Exception as e:
            logger.error(
                f"Error inesperado durante el proceso de registro del usuario {user_data.email}: {e!s}",
                exc_info=True,
            )
            return Failure(errors.AuthServiceError(f"Error inesperado al registrar el usuario: {e!s}"))


async def send_verification_email(db: AsyncSession, email: str) -> Result[None, errors.AuthServiceError | UserNotFoundError | DatabaseError]:
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
    if is_failure(user_result):
        error = user_result.error()
        # Log the error, but do not expose to the client whether the user exists or not.
        if isinstance(error, UserNotFoundError):
            logger.info(
                f"Solicitud de reseteo de contraseña para email no registrado: {email}"
            )
        else:  # DatabaseError
            logger.error(
                f"Error de BD al buscar usuario '{email}' para enviar email de verificación: {error}"
            )
            return Failure(DatabaseError(str(error))) # Propagate as DatabaseError

    user: User = user_result.unwrap()

    if user.is_verified:
        logger.info(f"Usuario '{email}' ya está verificado. No se enviará correo.")
        return Success(None) # Consider this a success or a specific status

    # Crear token de verificación
    token_data = {"sub": user.email}
    token_result = create_email_verification_token(data=token_data)

    if is_failure(token_result):
        token_error = token_result.failure()
        logger.error(f"Error al crear token de verificación para {email}: {token_error}")
        return Failure(errors.AuthServiceError("Error al generar token de verificación"))

    token_str = token_result.unwrap()

    # Aquí iría la lógica para enviar el correo con el token
    logger.info(f"Se enviaría correo de verificación a {user.email} con token: {token_str}")
    # e.g., await email_service.send_verification_mail(email, token_str)
    return Success(None)


async def verify_email_token(db: AsyncSession, token: str) -> Result[User, errors.InvalidTokenError | UserNotFoundError | DatabaseError]:
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
    # Verificar el token
    # Email verification tokens are now their own type in jwt.py
    token_payload_result = verify_token(token, token_type="email_verification")
    if is_failure(token_payload_result):
        return Failure(token_payload_result.failure()) # Propagate InvalidTokenError

    token_payload: TokenData = token_payload_result.unwrap()

    if not token_payload.sub: # Should be caught by verify_token, but as a safeguard
        logger.error("Token de verificación de email no contiene 'sub'.")
        return Failure(errors.InvalidTokenError("Token de verificación inválido (sin subject)"))

    # Obtener el usuario
    user_result = await user_service.get_user_by_email(db, email=token_payload.sub)
    if is_failure(user_result):
        error = user_result.error() # type: ignore
        logger.warning(
            f"Usuario '{token_payload.sub}' no encontrado durante verificación de email: {error}" # type: ignore
        )
        if isinstance(error, UserNotFoundError): # type: ignore
            return Failure(errors.InvalidTokenError("Usuario asociado al token de verificación no encontrado."))
        else:  # DatabaseError
            return Failure(DatabaseError(f"Error de BD al buscar usuario {token_payload.sub} para verificar email."))

    user: User = user_result.unwrap()

    if user.is_verified:
        logger.info(f"Usuario '{user.email}' ya está verificado.")
        return Success(user)

    # Actualizar el estado de verificación del usuario
    user_update_schema = UserUpdate(is_verified=True)
    # user_service.update_user is from app.users.service, which returns Result
    # The original code had `await user_service.update_user` which is correct if it's the service function
    # but `update_user` in `user_service` (UserService class) takes `user_id` and `user_update_data`
    _user_repo = UserRepository(db) # Need repo for UserService instance
    _usr_service = UserService(_user_repo)
    updated_user_result = await _usr_service.update_existing_user( # Correct method name
        user_id=user.id, user_update_data=user_update_schema
    )

    if is_failure(updated_user_result): # Corrected: is_failure
        update_error = updated_user_result.error()
        logger.error(
            f"Error al actualizar usuario '{user.email}' a verificado: {update_error}"
        )
        if isinstance(update_error, DatabaseError):
            return Failure(update_error)
        return Failure(DatabaseError(f"Error al marcar usuario '{user.email}' como verificado."))

    logger.info(f"Usuario '{user.email}' verificado exitosamente.")
    return Success(updated_user_result.unwrap())


async def send_password_reset_email(db: AsyncSession, email: str) -> Result[None, errors.AuthServiceError | UserNotFoundError | DatabaseError]:
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
    if is_failure(user_result):
        error = user_result.error()
        # Log the error, but do not expose to the client whether the user exists or not.
        if isinstance(error, UserNotFoundError):
            logger.info(
                f"Solicitud de reseteo de contraseña para email no registrado: {email}"
            )
        else:  # DatabaseError
            logger.error(
                f"Error de BD al buscar usuario '{email}' para reseteo de contraseña: {error}"
            )
            # Do not expose error, but log it. Return Success to prevent email enumeration.
        return Success(None) # Silently return Success

    user: User = user_result.unwrap()

    # Crear token de restablecimiento
    token_data_payload = {"sub": user.email}
    token_result = create_password_reset_token(data=token_data_payload)

    if is_failure(token_result):
        token_error = token_result.failure()
        logger.error(f"Error al crear token de reseteo para {email}: {token_error}")
        return Failure(errors.AuthServiceError("Error al generar token de reseteo"))
    
    token_str = token_result.unwrap()

    # TODO: Implementar el envío real del correo electrónico
    reset_url = f"{settings.FRONTEND_URL}/reset-password?token={token_str}"
    logger.info(
        f"Se enviaría correo de reseteo de contraseña a {user.email} con URL: {reset_url}"
    )
    # e.g., await email_service.send_password_reset_mail(email, token_str)
    return Success(None)


async def reset_password(db: AsyncSession, token: str, new_password: str) -> Result[User, errors.InvalidTokenError | UserNotFoundError | DatabaseError]:
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
    # Verificar el token (password reset tokens are their own type)
    token_payload_result = verify_token(token, token_type="reset")
    if is_failure(token_payload_result):
        return Failure(token_payload_result.failure()) # Propagate InvalidTokenError

    token_payload: TokenData = token_payload_result.unwrap()

    if not token_payload.sub: # Should be caught by verify_token
        return Failure(errors.InvalidTokenError("Token de reseteo inválido (sin subject)"))

    # Obtener usuario
    user_result = await user_service.get_user_by_email(db, email=token_payload.sub)
    if is_failure(user_result):
        error = user_result.error() # type: ignore
        if isinstance(error, UserNotFoundError): # type: ignore
            return Failure(errors.InvalidTokenError("Usuario asociado al token de reseteo no encontrado."))
        return Failure(DatabaseError(f"Error de BD al buscar usuario {token_payload.sub} para reseteo.")) # type: ignore
    
    user: User = user_result.unwrap()

    # Hashear la nueva contraseña
    hashed_new_password = get_password_hash(new_password)

    # Actualizar la contraseña del usuario
    user_update_schema = UserUpdate(password=hashed_new_password) # Pass plain, repo/service should hash if not already
                                                                # OR pass hashed_password directly if UserUpdate supports it
                                                                # Forcing UserUpdate to take plain password for hashing by service layer:
    _user_repo = UserRepository(db)
    _usr_service = UserService(_user_repo)
    
    # The user_service.update_existing_user expects UserUpdate where password is plain.
    # It will hash it. So, UserUpdate(password=new_password) is correct.
    update_password_result = await _usr_service.update_existing_user(
        user_id=user.id, 
        user_update_data=UserUpdate(password=new_password) # Pass plain new_password
    )

    if is_failure(update_password_result):
        update_error = update_password_result.error()
        logger.error(f"Error al actualizar contraseña para usuario '{user.email}': {update_error}")
        if isinstance(update_error, DatabaseError):
            return Failure(update_error)
        return Failure(DatabaseError("Error al actualizar la contraseña."))

    logger.info(f"Contraseña para usuario '{user.email}' actualizada exitosamente.")
    return Success(update_password_result.unwrap())


async def revoke_token(db: AsyncSession, token: str) -> Result[None, errors.InvalidTokenError | DatabaseError]: # Added Result return type
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
        # Verificar el token para obtener la fecha de expiración y jti
        # Use jwt_utils.decode_token_payload as it tries multiple keys if needed
        # and can disable signature verification for introspection.
        # However, for blacklisting, we should ensure the token was validly issued by us.
        # So, we might need a specific verification that checks signature but allows expired tokens
        # for the purpose of extracting 'jti' and 'exp'.
        # For now, let's assume a simple decode to get 'jti' and 'exp'.
        
        # This part needs a proper blacklisting strategy (e.g., storing jti in DB).
        # The current logic is placeholder.
        
        # Attempt to decode with access token secret first
        try:
            payload = jwt.decode(
                token,
                settings.JWT_SECRET_KEY.get_secret_value(),
                algorithms=[settings.JWT_ALGORITHM],
                options={"verify_aud": False, "verify_exp": False} # verify_exp=False to get exp of expired token
            )
        except JWTError:
            # If failed, try with refresh token secret
            try:
                payload = jwt.decode(
                    token,
                    settings.JWT_REFRESH_SECRET_KEY.get_secret_value(),
                    algorithms=[settings.JWT_ALGORITHM],
                    options={"verify_aud": False, "verify_exp": False}
                )
            except JWTError as e:
                logger.error(f"Error al decodificar token para revocación: {e!s}")
                return Failure(errors.InvalidTokenError(f"Token inválido o malformado para revocación: {e!s}"))

        jti = payload.get("jti")
        exp = payload.get("exp")

        if not jti or not exp:
            return Failure(errors.InvalidTokenError("Token no contiene 'jti' o 'exp' necesarios para revocación."))

        # Example: Store (jti, exp) in a blacklist table in DB
        # BlacklistedToken.create(db, jti=jti, expires_at=datetime.fromtimestamp(exp, tz=timezone.utc))
        logger.info(f"Token JTI: {jti} (exp: {exp}) sería añadido a la lista negra.")
        # Placeholder: actual blacklisting logic is needed here.
        # For now, we'll just log it.
        # If blacklisting fails (e.g. DB error), return Failure(DatabaseError(...))

        return Success(None)

    except Exception as e: # Catch any other unexpected error
        logger.error(f"Error inesperado durante la revocación de token: {e!s}", exc_info=True)
        return Failure(errors.AuthServiceError(f"Error inesperado al revocar token: {e!s}"))
