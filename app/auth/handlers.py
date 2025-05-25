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
    PasswordResetRequest,
    ResetPasswordSchema,
    Token,
    TokenRefresh,
)
from app.common.database import get_db
from app.common.result import is_failure
from app.users.models import User
from app.users.schemas import UserCreate, UserResponse

# Crear el router
router = APIRouter(prefix="/auth", tags=["auth"])


@router.post("/login", response_model=Token)
async def login_for_access_token(
    form_data: OAuth2PasswordRequestForm = Depends(), db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
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
        return {
            "access_token": access_token,
            "token_type": "bearer",
            "refresh_token": refresh_token,
        }

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
) -> User:
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
        # Registrar al usuario
        user = await auth_service.register_user(db, user_data)

        # Enviar email de verificación en segundo plano
        background_tasks.add_task(auth_service.send_verification_email, db, user.email)

        return user

    except auth_service.EmailAlreadyExistsError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT, detail="El email ya está registrado"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al registrar usuario: {e!s}",
        )


@router.post("/refresh", response_model=Token)
async def refresh_token(
    token_data: TokenRefresh, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
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
        return {"access_token": access_token, "token_type": "bearer"}

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
) -> dict[str, str]:
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

        return {
            "message": "Si el email existe, se ha enviado un correo con instrucciones para restablecer la contraseña"
        }

    except Exception:
        # No revelamos detalles específicos por seguridad
        return {
            "message": "Si el email existe, se ha enviado un correo con instrucciones para restablecer la contraseña"
        }


@router.post("/reset-password", status_code=status.HTTP_200_OK)
async def reset_password(
    reset_data: ResetPasswordSchema, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
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
        # Restablecer la contraseña
        await auth_service.reset_password(db, reset_data.token, reset_data.new_password)

        return {"message": "Contraseña restablecida con éxito"}

    except auth_service.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El enlace de restablecimiento no es válido o ha expirado",
        )
    except auth_service.ResourceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al restablecer contraseña: {e!s}",
        )


@router.post("/verify-email/{token}", status_code=status.HTTP_200_OK)
async def verify_email(
    token: str, db: AsyncSession = Depends(get_db)
) -> dict[str, str]:
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
        # Verificar el email
        await auth_service.verify_email_token(db, token)

        return {"message": "Correo electrónico verificado con éxito"}

    except auth_service.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="El enlace de verificación no es válido o ha expirado",
        )
    except auth_service.ResourceNotFoundError:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al verificar email: {e!s}",
        )


@router.post("/logout", status_code=status.HTTP_200_OK)
async def logout(
    db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)
) -> dict[str, str]:
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

        return {"message": "Sesión cerrada con éxito"}

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error al cerrar sesión: {e!s}",
        )


@router.get("/me", response_model=UserResponse)
async def get_user_me(current_user: User = Depends(get_current_active_user)) -> User:
    """
    Obtiene información del usuario actualmente autenticado.

    Args:
        current_user: Usuario actualmente autenticado.

    Returns:
        User: Datos del usuario actual.
    """
    return current_user
