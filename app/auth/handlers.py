"""
Endpoints para la autenticación de usuarios.

Este módulo define los endpoints de la API para autenticación, incluyendo
login, registro, refresh token, verificación de email y reseteo de contraseña.
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession

from app.auth import service as auth_service
from app.auth.dependencies import get_current_active_user, get_current_user
from app.auth.errors import handle_auth_error
from app.auth.schemas import (
    Msg, # Import Msg
    PasswordResetRequest,
    ResetPasswordSchema,
    Token,
    TokenRefresh,
)
from app.common.database import get_db
from app.common.result import is_failure, Result
from app.users.models import User as UserModel # Alias UserModel
from app.users.schemas import UserCreate, UserResponse, UserPublic # Import UserPublic

# Crear el router
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
) -> Token: # Return Token object
    """
    Autentica a un usuario y genera un token de acceso JWT.

    Este endpoint recibe credenciales de usuario (email/username y contraseña)
    y realiza el proceso de autenticación. Si las credenciales son válidas,
    genera y devuelve un token de acceso JWT.

    Args:
        form_data: Formulario con username (email) y password.
        db: Sesión de base de datos.

    Returns:
        Dict[str, str]: Diccionario con el token de acceso y tipo de token.

    Raises:
        HTTPException: Si las credenciales son inválidas, la cuenta está inactiva
                      o no ha sido verificada.
    """
    try:
        # Autenticar al usuario
        user = await auth_service.authenticate_user(
            db=db,
            email=form_data.username,  # El username del form es el email en nuestro caso
            password=form_data.password,
        )

        # Crear datos para el token (sub = email)
        token_data = {"sub": user.email}

        # Crear token de acceso
        access_token_result = auth_service.create_access_token(data=token_data)
        if is_failure(access_token_result):
            error = access_token_result.failure()
            raise error

        access_token = access_token_result.unwrap()

        # Crear token de refresh
        refresh_token_result = auth_service.create_refresh_token(data=token_data)
        if is_failure(refresh_token_result):
            error = refresh_token_result.failure()
            raise error

        refresh_token = refresh_token_result.unwrap()

        # Actualizar la fecha de último login
        await auth_service.update_user_last_login(db, user)

        # Devolver el token
        return Token(
            access_token=access_token,
            token_type="bearer",
            # refresh_token is not part of Token schema in app.auth.schemas
            # If it should be, the Token schema needs to be updated.
            # For now, assuming refresh_token is handled separately or not in this response.
        )
        # If refresh_token is to be returned, Token schema should be:
        # class Token(BaseModel):
        #     access_token: str
        #     token_type: str = "bearer"
        #     refresh_token: str | None = None
        # And the return would be:
        # return Token(access_token=access_token, token_type="bearer", refresh_token=refresh_token)


    except auth_service.AuthenticationError as e:
        # Convertir el error de autenticación a HTTPException
        raise handle_auth_error(e)
    except Exception as e:
        # Manejar otros errores inesperados
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado: {e!s}",
        )


@router.post(
    "/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED
)
async def register_user(
    user_data: UserCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> UserResponse: # Return UserResponse object
    """
    Registra un nuevo usuario en el sistema.

    Este endpoint recibe los datos del nuevo usuario, lo registra en la base de datos
    y envía un correo de verificación si es necesario.

    Args:
        user_data: Datos del nuevo usuario (email, contraseña, etc.).
        background_tasks: Tareas en segundo plano (para envío de emails).
        db: Sesión de base de datos.

    Returns:
        User: El usuario recién creado.

    Raises:
        HTTPException: Si el email ya está registrado o hay un error en el proceso.
    """
    try:
        # auth_service.register_user returns Result[UserModel, ErrorType]
        user_registration_result: Result[UserModel, auth_service.EmailAlreadyExistsError | auth_service.DatabaseError] = await auth_service.register_user(db, user_data)

        if user_registration_result.is_failure():
            error = user_registration_result.failure()
            if isinstance(error, auth_service.EmailAlreadyExistsError):
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT, detail="El email ya está registrado"
                )
            # Assuming DatabaseError is another possible error from the service
            elif isinstance(error, auth_service.DatabaseError):
                 raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error de base de datos al registrar usuario."
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Error inesperado al registrar usuario: {str(error)}",
                )

        created_user_model: UserModel = user_registration_result.unwrap()

        # Enviar email de verificación en segundo plano
        background_tasks.add_task(auth_service.send_verification_email, db, created_user_model.email)
        
        # Convert UserModel to UserPublic for the response data
        user_public_data = UserPublic.model_validate(created_user_model)

        return UserResponse(
            success=True,
            message="Usuario registrado exitosamente. Por favor, verifica tu correo electrónico.",
            data=user_public_data
        )

    except Exception as e: # Catch any other unexpected error during the process
        # Log the exception e
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al registrar usuario: {e!s}",
        )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    token_data: TokenRefresh, db: AsyncSession = Depends(get_db)
) -> Token: # Return Token object
    """
    Refresca un token de acceso usando un token de refresh válido.

    Args:
        token_data: Datos con el token de refresh.
        db: Sesión de base de datos.

    Returns:
        Dict[str, str]: Diccionario con el nuevo token de acceso.

    Raises:
        HTTPException: Si el token de refresh es inválido o ha expirado.
    """
    try:
        # Verificar el token de refresh
        token_data_result = auth_service.verify_refresh_token(token_data.refresh_token)
        if token_data_result.is_failure():
            error = token_data_result.failure()
            raise error

        token_payload = token_data_result.unwrap()

        # Verificar que el usuario existe y está activo
        user_result = await auth_service.get_user_by_email(db, token_payload.sub)
        if user_result.is_failure():
            error = user_result.failure()
            raise error

        user = user_result.unwrap()
        if not user.is_active:
            raise auth_service.InactiveUserError("La cuenta está inactiva")

        # Crear nuevo token de acceso
        access_token_result = auth_service.create_access_token(data={"sub": user.email})
        if is_failure(access_token_result):
            error = access_token_result.failure()
            raise error

        access_token = access_token_result.unwrap()

        # Devolver el nuevo token
        return Token(access_token=access_token, token_type="bearer")

    except auth_service.InvalidTokenError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token de refresh inválido: {e!s}",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except auth_service.AuthenticationError as e:
        raise handle_auth_error(e)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al refrescar token: {e!s}",
        )


@router.post("/recover-password", status_code=status.HTTP_202_ACCEPTED)
async def recover_password(
    request: PasswordResetRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
) -> Msg: # Return Msg object
    """
    Inicia el proceso de recuperación de contraseña para un usuario.

    Este endpoint recibe el email del usuario y envía un correo con un enlace
    para restablecer la contraseña.

    Args:
        request: Datos con el email del usuario.
        background_tasks: Tareas en segundo plano (para envío de emails).
        db: Sesión de base de datos.

    Returns:
        Dict[str, str]: Mensaje de confirmación.

    Raises:
        HTTPException: Si hay un error en el proceso.
    """
    try:
        # Enviar correo de recuperación en segundo plano
        # No revelamos si el email existe o no por seguridad
        background_tasks.add_task(
            auth_service.send_password_reset_email, db, request.email
        )

        return Msg(message="Si el email existe, se ha enviado un correo con instrucciones para restablecer la contraseña")

    except Exception: # Generic catch for safety, service should ideally handle errors gracefully
        # No revelamos detalles específicos por seguridad
        # Log the actual error internally
        return Msg(message="Si el email existe, se ha enviado un correo con instrucciones para restablecer la contraseña")


@router.post("/reset-password", status_code=status.HTTP_200_OK, response_model=Msg) # Add response_model
async def reset_password(
    reset_data: ResetPasswordSchema, db: AsyncSession = Depends(get_db)
) -> Msg: # Return Msg object
    """
    Restablece la contraseña de un usuario usando un token de reseteo.

    Args:
        reset_data: Datos con el token de reseteo y la nueva contraseña.
        db: Sesión de base de datos.

    Returns:
        Dict[str, str]: Mensaje de confirmación.

    Raises:
        HTTPException: Si el token es inválido o ha expirado.
    """
    try:
        # auth_service.reset_password should return Result[None, ErrorType]
        reset_result = await auth_service.reset_password(db, reset_data.token, reset_data.new_password)

        if reset_result.is_failure():
            error = reset_result.failure()
            if isinstance(error, auth_service.InvalidTokenError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="El enlace de restablecimiento no es válido o ha expirado.",
                )
            # Assuming ResourceNotFoundError maps to UserNotFoundError from user service
            elif isinstance(error, auth_service.UserNotFoundError): # Or a more specific error
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado."
                )
            else: # DatabaseError or other
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al procesar el restablecimiento de contraseña.",
                )
        
        return Msg(message="Contraseña restablecida con éxito")

    except Exception as e: # Fallback for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al restablecer contraseña: {e!s}",
        )


@router.post("/verify-email/{token}", status_code=status.HTTP_200_OK, response_model=Msg) # Add response_model
async def verify_email(
    token: str, db: AsyncSession = Depends(get_db)
) -> Msg: # Return Msg object
    """
    Verifica el correo electrónico de un usuario usando un token de verificación.

    Args:
        token: Token de verificación de email.
        db: Sesión de base de datos.

    Returns:
        Dict[str, str]: Mensaje de confirmación.

    Raises:
        HTTPException: Si el token es inválido o ha expirado.
    """
    try:
        # auth_service.verify_email_token should return Result[None, ErrorType]
        verification_result = await auth_service.verify_email_token(db, token)

        if verification_result.is_failure():
            error = verification_result.failure()
            if isinstance(error, auth_service.InvalidTokenError):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="El enlace de verificación no es válido o ha expirado.",
                )
            elif isinstance(error, auth_service.UserNotFoundError): # Or a more specific error
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado para el token."
                )
            else: # DatabaseError or other
                 raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail="Error al procesar la verificación del correo.",
                )

        return Msg(message="Correo electrónico verificado con éxito")

    except Exception as e: # Fallback for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar email: {e!s}",
        )


@router.post("/logout", status_code=status.HTTP_200_OK, response_model=Msg) # Add response_model
async def logout(
    db: AsyncSession = Depends(get_db), current_user: UserModel = Depends(get_current_user) # Use UserModel
) -> Msg: # Return Msg object
    """
    Cierra la sesión del usuario actual revocando su token de acceso.

    Args:
        db: Sesión de base de datos.
        current_user: Usuario actualmente autenticado.

    Returns:
        Dict[str, str]: Mensaje de confirmación.

    Raises:
        HTTPException: Si hay un error al revocar el token.
    """
    try:
        # La lógica para revocar el token iría aquí
        # Si se usa JWT con lista negra, se agregaría el token a la lista negra
        # En la implementación actual, solo devolvemos un mensaje de éxito
        # Note: True JWT logout on the server-side requires token blacklisting.
        # This endpoint is often a client-side hint to clear tokens.

        return Msg(message="Sesión cerrada con éxito")

    except Exception as e: # Fallback for unexpected errors
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al cerrar sesión: {e!s}",
        )


@router.get("/me", response_model=UserResponse)
async def get_user_me(current_user: UserModel = Depends(get_current_active_user)) -> UserResponse: # Return UserResponse
    """
    Obtiene información del usuario actualmente autenticado.

    Args:
        current_user: Usuario actualmente autenticado (UserModel).

    Returns:
        UserResponse: Datos del usuario actual (UserPublic dentro de UserResponse).
    """
    user_public_data = UserPublic.model_validate(current_user)
    return UserResponse(
        success=True,
        message="Datos del usuario obtenidos exitosamente.",
        data=user_public_data
    )
