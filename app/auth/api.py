"""
Módulo de rutas de la API para autenticación y autorización.

Este módulo define los endpoints para el inicio de sesión, registro,
renovación de tokens y recuperación de contraseñas.
"""

from datetime import timedelta

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.common.config import settings
from app.common.database import get_db

# Import specific errors from common.errors, AuthenticationError is not defined there
from app.common.errors import (  # Assuming ResourceNotFoundError might be useful
    DatabaseError,
)
from app.users import service as user_service  # Import user service
from app.users.errors import (
    UserNotFoundError as UsersUserNotFoundError,  # Specific user not found from user service
)
from app.users.models import User as UserModel  # User model is in the users slice, aliased
from app.users.schemas import (  # User schemas are in the users slice
    UserCreate,
    UserResponse, # This is BaseResponse with data: UserPublic | None
    UserPublic, # This is the schema for the actual user data
)

from . import errors as auth_errors  # Import auth specific errors
from . import schemas, service
from .schemas import Token, Msg # Token and Msg schemas are local to auth

router = APIRouter()


@router.post(
    "/login",
    response_model=Token,
    summary="Iniciar sesión",
    description="Autentica un usuario y devuelve un token de acceso.",
)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: AsyncSession = Depends(get_db),
) -> schemas.Token:
    """
    Autentica a un usuario y devuelve un token de acceso JWT.

    Este endpoint maneja el inicio de sesión del usuario.
    Realiza las siguientes operaciones:
    1. Recibe las credenciales del usuario (correo electrónico como `username` y contraseña)
       a través de un formulario (`OAuth2PasswordRequestForm`).
    2. Llama al servicio `auth_service.authenticate_user` para verificar las credenciales
       contra la base de datos y el estado de la cuenta (activa y verificada).
    3. Si la autenticación es exitosa, genera un token de acceso JWT utilizando
       `auth_service.create_access_token`.
    4. Devuelve el token de acceso y el tipo de token ("bearer").

    Args:
        form_data (OAuth2PasswordRequestForm, optional): Un formulario que contiene
                                                         el `username` (correo electrónico del usuario)
                                                         y la `password`. Inyectado por FastAPI.
                                                         Defaults to Depends().
        db (AsyncSession, optional): La sesión de base de datos asíncrona, inyectada
                                     por FastAPI. Defaults to Depends(get_db).

    Returns:
        Token: Un objeto que contiene el `access_token` JWT y `token_type` ("bearer").
               Se valida contra el esquema `Token`.

    Raises:
        HTTPException (401 Unauthorized): Si las credenciales proporcionadas son inválidas
                                          (email no encontrado, contraseña incorrecta),
                                          o si la cuenta del usuario está inactiva o no verificada.
                                          Incluye un encabezado `WWW-Authenticate: Bearer`.
        HTTPException (500 Internal Server Error): Si ocurre un error inesperado durante
                                                   el proceso de autenticación, como un
                                                   problema de conexión con la base de datos.
    """
    try:
        # service.authenticate_user will raise specific errors if authentication fails
        user = await service.authenticate_user(
            db, email=form_data.username, password=form_data.password
        )
        # If authenticate_user returns without error, user is valid.

        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = service.create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires
        )

        return Token(
            access_token=access_token,
            token_type="bearer",
            # Token schema does not include 'user' field
        )
    except (
        auth_errors.InvalidCredentialsError,
        auth_errors.InactiveUserError,
        auth_errors.UnverifiedAccountError,
    ) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),  # Use the message from the specific auth error
            headers={"WWW-Authenticate": "Bearer"},
        )
    except DatabaseError:
        # Handle potential database errors during authentication if any
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de base de datos durante la autenticación.",
        )


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Registrar nuevo usuario",
    description="Crea una nueva cuenta de usuario.",
)
async def register_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
) -> UserResponse: # UserResponse is BaseResponse(data: UserPublic | None)
    """
    Registra un nuevo usuario en el sistema.

    Este endpoint permite la creación de una nueva cuenta de usuario.
    Realiza las siguientes operaciones:
    1. Recibe los datos del usuario para el registro (`user_data`) que deben cumplir
       con el esquema `UserCreate`.
    2. Llama al servicio `auth_service.register_user` para procesar la lógica de negocio,
       que incluye la validación de datos, el hash de la contraseña y la creación
       del usuario en la base de datos.
    3. Si el registro es exitoso, devuelve los datos del usuario creado (sin la contraseña)
       según el esquema `UserResponse` y un código de estado HTTP 201 (Created).

    Args:
        user_data (UserCreate): Un objeto que contiene los datos del nuevo usuario,
                                incluyendo email, contraseña y nombre completo.
                                Se valida contra el esquema `UserCreate`.
        db (AsyncSession, optional): La sesión de base de datos asíncrona, inyectada
                                     por FastAPI. Defaults to Depends(get_db).

    Returns:
        UserResponse: Un objeto que contiene los datos del usuario recién creado,
                      excluyendo información sensible como la contraseña.
                      Se valida contra el esquema `UserResponse`.

    Raises:
        HTTPException (409 Conflict): Si el correo electrónico proporcionado en `user_data`
                                      ya está registrado en el sistema.
        HTTPException (500 Internal Server Error): Si ocurre un error inesperado durante
                                                   el proceso de registro, como un problema
                                                   de conexión con la base de datos u otro
                                                   error interno del servidor.
    """
    try:
        user_result = await service.register_user(db, user_data)

        if user_result.is_failure():
            error = user_result.failure()
            if isinstance(error, auth_errors.EmailAlreadyExistsError):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT, # Changed to 409 Conflict
                    detail=str(error),
                )
            elif isinstance(error, DatabaseError): # Assuming service might return DatabaseError
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error de base de datos al registrar usuario.",
                )
            else: # Generic fallback
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error inesperado al registrar usuario.",
                )
        
        created_user_model: UserModel = user_result.unwrap()
        
        # Convert UserModel to UserPublic schema for the response
        user_public_data = UserPublic.model_validate(created_user_model)
        
        return UserResponse(
            success=True,
            message="Usuario registrado exitosamente.",
            data=user_public_data
        )

    except auth_errors.EmailAlreadyExistsError as e: # This specific catch might be redundant if service returns Result
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, # Changed to 409 Conflict
            detail=str(e),  # Use the message from the specific auth error
        )
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error al crear el usuario.",
        )


@router.post(
    "/token/refresh",
    response_model=Token,
    summary="Renovar token",
    description="Renueva el token de acceso usando un refresh token.",
)
async def refresh_token(
    token_data: schemas.TokenRefresh,
    db: AsyncSession = Depends(get_db),
) -> schemas.Token:
    """
    Renueva un token de acceso utilizando un token de actualización (refresh token).

    Este endpoint permite a los usuarios obtener un nuevo token de acceso JWT
    sin necesidad de volver a ingresar sus credenciales, siempre y cuando
    proporcionen un token de actualización válido.

    El proceso es el siguiente:
    1. Recibe un token de actualización (`refresh_token`) a través del cuerpo de la solicitud,
       validado por el esquema `schemas.TokenRefresh`.
    2. Llama a `service.verify_refresh_token` para validar el token de actualización.
       Esto verifica su firma, expiración y tipo.
    3. Si el token de actualización es válido, extrae el 'subject' (email del usuario)
       del payload del token.
    4. Busca al usuario en la base de datos utilizando `user_service.get_user_by_email`.
    5. Si el usuario se encuentra y está activo, genera un nuevo token de acceso JWT
       utilizando `service.create_access_token`.
    6. Devuelve el nuevo token de acceso y el tipo de token ("bearer").

    Args:
        token_data (schemas.TokenRefresh): Un objeto que contiene el `refresh_token` (str).
        db (AsyncSession, optional): La sesión de base de datos asíncrona, inyectada
                                     por FastAPI. Defaults to Depends(get_db).

    Returns:
        Token: Un objeto que contiene el nuevo `access_token` JWT y `token_type` ("bearer").
               Se valida contra el esquema `Token`.

    Raises:
        HTTPException (401 Unauthorized): Si el token de actualización es inválido,
                                          ha expirado, está malformado, o si el usuario
                                          asociado no se encuentra, no está activo,
                                          o si el token no es del tipo 'refresh'.
                                          Incluye un encabezado `WWW-Authenticate: Bearer`.
        HTTPException (500 Internal Server Error): Si ocurre un error inesperado durante
                                                   el proceso, como un problema de
                                                   conexión con la base de datos.
    """
    try:
        # Verificar el refresh token. service.verify_refresh_token returns TokenData
        token_payload = service.verify_refresh_token(token_data.refresh_token)
        if not token_payload or not token_payload.sub:
            raise auth_errors.InvalidTokenError(
                "Token de actualización inválido o malformado"
            )

        email_from_token = token_payload.sub

        # Obtener el usuario usando user_service
        user_result = await user_service.get_user_by_email(db, email_from_token)
        if user_result.is_failure():
            error = user_result.error()
            if isinstance(error, UsersUserNotFoundError):
                raise auth_errors.InvalidTokenError(
                    "Usuario asociado al token no encontrado."
                )
            else:  # DatabaseError
                raise DatabaseError(
                    "Error de base de datos al buscar usuario para refrescar token."
                )

        user: User = user_result.unwrap()

        # Generar nuevo access token
        access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
        new_access_token = service.create_access_token(
            data={"sub": user.email}, expires_delta=access_token_expires # user is UserModel
        )

        return Token(
            access_token=new_access_token,
            token_type="bearer"
        )
    except auth_errors.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
            headers={"WWW-Authenticate": "Bearer"},
        )
    except DatabaseError:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error de base de datos durante la renovación del token.",
        )


@router.post(
    "/password-recovery/{email}",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Solicitar recuperación de contraseña",
    description="Envía un correo con un enlace para restablecer la contraseña.",
)
async def recover_password(
    email: str, # Changed from email_data: schemas.EmailSchema for simplicity if just email is needed
    db: AsyncSession = Depends(get_db),
) -> Msg: # Use the defined Msg schema
    """
    Inicia el proceso de recuperación de contraseña para un usuario.

    Este endpoint permite a un usuario solicitar un restablecimiento de contraseña.
    El proceso es el siguiente:
    1. Recibe la dirección de correo electrónico del usuario (`email_data.email`)
       validada por el esquema `schemas.EmailSchema`.
    2. Llama al servicio `auth_service.send_password_reset_email`. Este servicio:
        a. Busca al usuario por el correo electrónico.
        b. Si el usuario existe, genera un token de restablecimiento de contraseña.
        c. Envía un correo electrónico al usuario con un enlace que contiene este token.
    3. Devuelve un mensaje genérico indicando que, si la cuenta existe, se ha enviado
       un correo. Esto se hace para no revelar si un correo electrónico está o no
       registrado en el sistema.

    Args:
        email_data (schemas.EmailSchema): Un objeto que contiene el `email` del usuario
                                          que solicita la recuperación de contraseña.
        db (AsyncSession, optional): La sesión de base de datos asíncrona, inyectada
                                     por FastAPI. Defaults to Depends(get_db).

    Returns:
        schemas.Msg: Un objeto con un mensaje genérico de confirmación.

    Raises:
        HTTPException (500 Internal Server Error): Si ocurre un error inesperado durante
                                                   el proceso, como un problema de
                                                   conexión con la base de datos o un fallo
                                                   al intentar enviar el correo electrónico.
    """
    # The service should handle UserNotFoundError gracefully and not expose it.
    # The goal is to always return a 202 Accepted to prevent email enumeration.
    try:
        await service.send_password_reset_email(db, email)
    except Exception as e:
        # Log the error for internal review, but don't expose details to the client.
        # logger.error(f"Error during password recovery request for {email}: {e}", exc_info=True)
        pass # Fall through to the generic success message

    return Msg(message="Si el correo existe, se ha enviado un enlace de recuperación")


@router.post(
    "/reset-password/",
    status_code=status.HTTP_200_OK,
    summary="Restablecer contraseña",
    description="Restablece la contraseña usando un token de restablecimiento.",
)
async def reset_password(
    reset_data: schemas.ResetPasswordSchema,
    db: AsyncSession = Depends(get_db),
) -> Msg: # Use the defined Msg schema
    """
    Restablece la contraseña de un usuario utilizando un token de restablecimiento.

    Este endpoint permite a un usuario establecer una nueva contraseña después de
    haber solicitado una recuperación de contraseña y haber recibido un token válido.

    El proceso es el siguiente:
    1. Recibe los datos para el restablecimiento, que incluyen el `token` de
       restablecimiento y la `new_password`, validados por el esquema
       `schemas.ResetPasswordSchema`.
    2. Llama al servicio `auth_service.reset_password` con el token y la nueva contraseña.
       Este servicio se encarga de:
        a. Verificar la validez del token (no expirado, tipo correcto).
        b. Encontrar al usuario asociado al token.
        c. Hashear la nueva contraseña.
        d. Actualizar la contraseña del usuario en la base de datos.
        e. Invalidar el token de restablecimiento usado.
    3. Si el restablecimiento es exitoso, devuelve un mensaje de confirmación.

    Args:
        reset_data (schemas.ResetPasswordSchema): Un objeto que contiene el `token` (str)
                                                  de restablecimiento de contraseña y la
                                                  `new_password` (str) para el usuario.
        db (AsyncSession, optional): La sesión de base de datos asíncrona, inyectada
                                     por FastAPI. Defaults to Depends(get_db).

    Returns:
        schemas.Msg: Un objeto con un mensaje de confirmación indicando que la
                     contraseña ha sido restablecida exitosamente.

    Raises:
        HTTPException (400 Bad Request): Si el token de restablecimiento es inválido,
                                         ha expirado, está malformado, o si el usuario
                                         asociado no se encuentra.
        HTTPException (500 Internal Server Error): Si ocurre un error inesperado durante
                                                   el proceso, como un problema de
                                                   conexión con la base de datos o un
                                                   fallo al actualizar la contraseña.
    """
    try:
        password_reset_result = await service.reset_password(db, reset_data.token, reset_data.new_password)
        
        if password_reset_result.is_failure():
            error = password_reset_result.failure()
            if isinstance(error, auth_errors.InvalidTokenError):
                 raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Token de restablecimiento inválido o expirado.",
                )
            elif isinstance(error, UsersUserNotFoundError): # If service can return this for token user
                 raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Usuario no encontrado para el token proporcionado.",
                )
            else: # DatabaseError or other
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al procesar el restablecimiento de contraseña.",
                )
        
        return Msg(message="Contraseña actualizada correctamente")

    except auth_errors.AuthenticationError as e: # Fallback, though service.reset_password should return Result
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
