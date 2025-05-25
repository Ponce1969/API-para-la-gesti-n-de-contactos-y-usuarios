# app/users/service.py
import logging
from typing import Optional, List, TYPE_CHECKING
from uuid import UUID, uuid4 # Para el token si se usa UUID
from datetime import datetime, timedelta # Para la expiración del token

from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import EmailStr

from app.common.hashing import get_password_hash, verify_password # Para creación y login
from app.common.result import Result, Success, Failure
if TYPE_CHECKING:
    from app.users.models import User, VerificationToken # Asegúrate de que VerificationToken esté definido
from app.users.repository import UserRepository
from app.users.schemas import UserCreate, UserUpdate, UserInDB, VerificationTokenServiceCreate, VerificationTokenCreateInternal, VerificationTokenInDB # Añadir esquemas de token
from app.users.errors import (
    UserAlreadyExistsError,
    UserNotFoundError,
    VerificationTokenNotFoundError,
    TokenInvalidError,
)
from app.common.errors import DatabaseError, AppError # Error genérico de BD y AppError

logger = logging.getLogger(__name__)

# Podríamos definir una constante para la duración del token
VERIFICATION_TOKEN_EXPIRE_MINUTES = 60 * 24 # 24 horas

class UserService:
    def __init__(self, user_repository: UserRepository):
        self.user_repository = user_repository

    async def get_user_by_id(self, user_id: int) -> Result[UserInDB, UserNotFoundError | DatabaseError]:
        """Obtiene un usuario por su ID."""
        # Llama directamente al método del repositorio que ya devuelve un Result.
        return await self.user_repository.get_by_id(user_id)

    async def get_users_list(
        self, skip: int = 0, limit: int = 100
    ) -> Result[List[UserInDB], DatabaseError]:
        """Obtiene una lista de usuarios con paginación."""
        # Llama directamente al método del repositorio que ya devuelve un Result.
        return await self.user_repository.list_users(skip=skip, limit=limit)

    async def update_existing_user(
        self, user_id: int, user_update_data: UserUpdate
    ) -> Result[UserInDB, UserNotFoundError | UserAlreadyExistsError | DatabaseError]:
        """
        Actualiza un usuario existente.
        La contraseña, si se proporciona en UserUpdate, debe ser texto plano y se hasheará aquí.
        """
        # Convertir UserUpdate a un diccionario de los campos que realmente se quieren actualizar.
        # El método del repositorio 'update' espera los campos individuales.
        update_kwargs = user_update_data.model_dump(exclude_unset=True)

        # Si la contraseña está presente en los datos de actualización, debe ser hasheada.
        if "password" in update_kwargs and update_kwargs["password"] is not None:
            # Asumimos que UserUpdate.password es de tipo Optional[SecretStr] o str
            # Si es SecretStr, necesitamos get_secret_value()
            password_to_hash = update_kwargs["password"]
            if hasattr(password_to_hash, 'get_secret_value'): # Check if it's SecretStr
                hashed_new_password = hash_password(password_to_hash.get_secret_value())
            else: # Assume it's a plain string (less ideal for Pydantic models)
                hashed_new_password = hash_password(password_to_hash)
            update_kwargs["hashed_password"] = hashed_new_password
            del update_kwargs["password"] # Eliminar la contraseña en texto plano

        # El repositorio espera los argumentos como kwargs, no un dict directamente.
        return await self.user_repository.update(user_id=user_id, **update_kwargs)

    async def delete_user_by_id(self, user_id: int) -> Result[None, UserNotFoundError | DatabaseError]:
        """
        Elimina un usuario por su ID (borrado lógico o físico según el repositorio).
        """
        # Llama directamente al método del repositorio que ya devuelve un Result.
        return await self.user_repository.delete(user_id)


    # Ejemplo de un método de servicio que podríamos implementar:
    # async def register_new_user(
    #     self, user_data: UserCreate
    # ) -> Result[UserInDB, UserAlreadyExistsError | DatabaseError]:
    #     """
    #     Registra un nuevo usuario y potencialmente envía un token de verificación.
    #     """
    #     # Verificar si el usuario ya existe (lógica que podría estar en el repo o aquí)
    #     existing_user_result = await self.user_repository.get_by_email(user_data.email)
    #     if existing_user_result.is_success():
    #         return Failure(UserAlreadyExistsError(email=user_data.email))
    #     
    #     # Hashear la contraseña
    #     hashed_pass = hash_password(user_data.password)
    #     
    #     # Crear el usuario en el repositorio
    #     # El repositorio ahora toma todos los campos necesarios
    #     created_user_result = await self.user_repository.create(
    #         email=user_data.email,
    #         hashed_password=hashed_pass,
    #         first_name=user_data.first_name,
    #         last_name=user_data.last_name
    #         # is_active podría ser False hasta la verificación
    #     )
    #     
    #     if created_user_result.is_failure():
    #         return created_user_result # Propagar el error (DatabaseError)
    #         
    #     # Aquí se podría añadir la lógica para crear y enviar un token de verificación
    #     # new_user = created_user_result.value
    #     # await self.create_and_send_verification_token(new_user.id)
    #     
    #     return created_user_result

    # Más métodos relacionados con tokens, roles, etc. irán aquí.

    async def register_new_user(
        self, user_data: UserCreate
    ) -> Result[UserInDB, UserAlreadyExistsError | DatabaseError]:
        """
        Registra un nuevo usuario.
        La contraseña en user_data.password se espera en texto plano.
        """
        # 1. Verificar si ya existe un usuario con el mismo email
        # Usamos el método get_by_email del repositorio que ya devuelve Result
        existing_user_by_email_result = await self.user_repository.get_by_email(user_data.email)

        if existing_user_by_email_result.is_success():
            # Si get_by_email tiene éxito, significa que el usuario ya existe
            return Failure(UserAlreadyExistsError(email=user_data.email))
        
        # Si el error de get_by_email no es UserNotFoundError, podría ser un DatabaseError
        # que deberíamos propagar o manejar. Por ahora, asumimos que si no es success,
        # es porque no existe o es un error de BD que el repo ya maneja.
        # Si es UserNotFoundError, es el escenario esperado para continuar.
        if existing_user_by_email_result.is_failure():
            error = existing_user_by_email_result.error()
            if not isinstance(error, UserNotFoundError):
                # Si es un DatabaseError u otro error inesperado del repo, lo propagamos
                logger.error(f"Error inesperado al verificar email {user_data.email}: {error}")
                return Failure(error) # Propaga el error original del repositorio

        # 2. Hashear la contraseña
        hashed_pass = hash_password(user_data.password.get_secret_value())

        # 3. Llamar al user_repository.create
        # El repositorio create espera todos los campos necesarios.
        # Asumimos que UserCreate tiene first_name y last_name.
        # is_active podría ser False por defecto hasta la verificación por email.
        create_user_params = {
            "email": user_data.email,
            "hashed_password": hashed_pass,
            "first_name": user_data.first_name,
            "last_name": user_data.last_name,
            "is_active": user_data.is_active if user_data.is_active is not None else False, # Default False, activar tras verificación
            "is_superuser": user_data.is_superuser if user_data.is_superuser is not None else False,
            "is_verified": user_data.is_verified if user_data.is_verified is not None else False, # Default False
        }
        
        created_user_result = await self.user_repository.create(**create_user_params)

        if created_user_result.is_failure():
            # El repositorio ya devuelve UserAlreadyExistsError o DatabaseError
            return created_user_result 
        
        # new_user_in_db = created_user_result.value
        # Aquí podríamos, por ejemplo, crear un token de verificación
        # token_result = await self.create_verification_token(new_user_in_db.id)
        # if token_result.is_success():
        #     # Enviar email con el token (lógica de notificación)
        #     pass 
        # else:
        #     # ¿Qué hacer si la creación del token falla? ¿Rollback de usuario?
        #     # Por ahora, solo logueamos y devolvemos el usuario.
        #     logger.error(f"No se pudo crear el token de verificación para {new_user_in_db.email}: {token_result.error()}")

        new_user_in_db = created_user_result.value # UserInDB

        # Ahora, crear el token de verificación para el nuevo usuario
        token_service_data = VerificationTokenServiceCreate(
            user_id=new_user_in_db.id,
            token_type="email_verification" # Tipo de token estándar para esto
        )
        
        token_creation_result = await self.create_verification_token_for_user(token_service_data)

        if token_creation_result.is_failure():
            # Loguear el error, pero no fallar el registro del usuario por esto por ahora.
            # En un sistema de producción, esto podría encolar un reintento o alertar.
            logger.error(
                f"Usuario {new_user_in_db.email} (ID: {new_user_in_db.id}) creado, "
                f"pero falló la creación del token de verificación: {token_creation_result.error()}"
            )
        else:
            verification_token = token_creation_result.value
            logger.info(
                f"Token de verificación (ID: {verification_token.id}, Tipo: {verification_token.token_type}) "
                f"creado para el usuario {new_user_in_db.email} (ID: {new_user_in_db.id})."
            )
            # Aquí iría la lógica para enviar el email con el token.
            # Por ejemplo: await self.email_service.send_verification_email(new_user_in_db, verification_token.token)
            
        return created_user_result # Devolver el resultado de la creación del usuario

    async def create_verification_token_for_user(
        self, token_create_data: VerificationTokenServiceCreate
    ) -> Result[VerificationTokenInDB, UserNotFoundError | DatabaseError]:
        """
        Crea un token de verificación para un usuario específico.
        Genera el token y su fecha de expiración.
        """
        # 1. Verificar que el usuario exista
        user_result = await self.user_repository.get_by_id(token_create_data.user_id)
        if user_result.is_failure():
            # Propaga UserNotFoundError o DatabaseError desde el repositorio
            return user_result 

        # user_in_db = user_result.value # No necesitamos el valor del usuario aquí, solo confirmar que existe

        # 2. Generar un string de token único
        token_str = uuid4().hex

        # 3. Calcular la fecha de expiración del token
        expires_delta = timedelta(minutes=VERIFICATION_TOKEN_EXPIRE_MINUTES)
        expires_at_dt = datetime.utcnow() + expires_delta

        # 4. Preparar los datos para el repositorio
        repo_token_data = VerificationTokenCreateInternal(
            token=token_str,
            user_id=token_create_data.user_id,
            token_type=token_create_data.token_type,
            expires_at=expires_at_dt
        )

        # 5. Llamar al user_repository.create_verification_token
        create_token_result = await self.user_repository.create_verification_token(repo_token_data)
        
        # create_token_result ya es Result[VerificationTokenInDB, DatabaseError]
        return create_token_result

    async def use_verification_token(
        self, token_value: str, expected_token_type: str
    ) -> Result[UserInDB, VerificationTokenNotFoundError | TokenInvalidError | UserNotFoundError | DatabaseError]:
        """
        Valida y utiliza un token de verificación.
        Si el token es válido y del tipo esperado (ej: "email_verification"),
        actualiza el estado del usuario (ej: is_verified = True) y marca el token como usado.

        Args:
            token_value: El string del token a verificar.
            expected_token_type: El tipo de token que se espera (ej: "email_verification").

        Returns:
            Result con el usuario actualizado (UserInDB) o un error apropiado.
        """
        # 1. Obtener el token por su valor
        token_result = await self.user_repository.get_verification_token_by_value(token_value)
        if token_result.is_failure():
            # Propaga VerificationTokenNotFoundError o DatabaseError
            return token_result 
        
        token_in_db = token_result.value

        # 2. Validar el token
        if token_in_db.is_used:
            return Failure(TokenInvalidError(token_value=token_value, reason="Token ya ha sido utilizado."))
        
        if datetime.utcnow() > token_in_db.expires_at:
            return Failure(TokenInvalidError(token_value=token_value, reason="Token ha expirado."))

        if token_in_db.token_type != expected_token_type:
            logger.warning(
                f"Intento de uso de token ID {token_in_db.id} con tipo incorrecto. "
                f"Esperado: '{expected_token_type}', Obtenido: '{token_in_db.token_type}'"
            )
            return Failure(TokenInvalidError(token_value=token_value, reason="Tipo de token incorrecto."))

        # 3. Obtener el usuario asociado al token
        user_result = await self.user_repository.get_by_id(token_in_db.user_id)
        if user_result.is_failure():
            # Esto sería inesperado si el token es válido, pero es una guarda de seguridad.
            # Propaga UserNotFoundError o DatabaseError.
            logger.error(f"Usuario ID {token_in_db.user_id} no encontrado para token válido ID {token_in_db.id}")
            return user_result
        
        user_to_update = user_result.value # UserInDB

        # 4. Realizar la acción específica del token (si aplica) y actualizar el usuario
        updated_user_in_db: Optional[UserInDB] = None

        if expected_token_type == "email_verification":
            if user_to_update.is_verified:
                logger.info(f"Usuario {user_to_update.email} ya estaba verificado. Token ID: {token_in_db.id}")
                updated_user_in_db = user_to_update
            else:
                update_user_result = await self.user_repository.update(
                    user_id=user_to_update.id, 
                    is_verified=True
                )
                if update_user_result.is_failure():
                    logger.error(f"Error al actualizar usuario {user_to_update.id} a verificado: {update_user_result.error()}")
                    return update_user_result
                updated_user_in_db = update_user_result.value
        
        # Aquí se podrían añadir otras lógicas para diferentes expected_token_type
        # elif expected_token_type == "password_reset":
        #     updated_user_in_db = user_to_update
        
        else:
            updated_user_in_db = user_to_update


        if updated_user_in_db is None: # Guarda por si una rama no asigna
             logger.error(f"updated_user_in_db no fue asignado para token {token_in_db.id} y tipo {expected_token_type}")
             return Failure(DatabaseError(detail="Error interno procesando el token."))


        # 5. Marcar el token como usado
        mark_used_result = await self.user_repository.mark_verification_token_as_used(token_in_db.id)
        if mark_used_result.is_failure():
            logger.error(
                f"Error al marcar token ID {token_in_db.id} como usado después de la acción del token. "
                f"Usuario ID: {user_to_update.id}. Error: {mark_used_result.error()}"
            )
            return mark_used_result

        return Success(updated_user_in_db)

async def create_user(db: AsyncSession, user_data: UserCreate) -> Result[UserInDB, UserAlreadyExistsError | DatabaseError]:
    """Registra un nuevo usuario utilizando UserService."""
    user_repo = UserRepository(db)
    user_service_instance = UserService(user_repo)
    return await user_service_instance.register_new_user(user_data)

async def get_user_by_id(db: AsyncSession, user_id: int) -> Result[UserInDB, UserNotFoundError | DatabaseError]:
    """Obtiene un usuario por su ID utilizando UserService."""
    user_repo = UserRepository(db)
    user_service_instance = UserService(user_repo)
    return await user_service_instance.get_user_by_id(user_id)

async def get_users(db: AsyncSession, skip: int = 0, limit: int = 100) -> Result[List[UserInDB], DatabaseError]:
    """Obtiene una lista de usuarios utilizando UserService."""
    user_repo = UserRepository(db)
    user_service_instance = UserService(user_repo)
    return await user_service_instance.get_users_list(skip=skip, limit=limit)

async def update_user(db: AsyncSession, user_id: int, user_update_data: UserUpdate) -> Result[UserInDB, UserNotFoundError | UserAlreadyExistsError | DatabaseError]:
    """Actualiza un usuario existente utilizando UserService."""
    user_repo = UserRepository(db)
    user_service_instance = UserService(user_repo)
    return await user_service_instance.update_existing_user(user_id=user_id, user_update_data=user_update_data)

async def delete_user(db: AsyncSession, user_id: int) -> Result[None, UserNotFoundError | DatabaseError]:
    """Elimina un usuario por su ID utilizando UserService."""
    user_repo = UserRepository(db)
    user_service_instance = UserService(user_repo)
    return await user_service_instance.delete_user_by_id(user_id)


# Funciones de servicio a nivel de módulo (pueden usar UserService internamente o directamente el repositorio)

async def get_user_by_email(db: AsyncSession, email: EmailStr) -> Result['User', UserNotFoundError | DatabaseError]:
    """
    Obtiene un usuario (modelo SQLAlchemy) por su correo electrónico.

    Args:
        db: Sesión de base de datos asíncrona.
        email: Correo electrónico del usuario a buscar.

    Returns:
        Result que contiene el modelo User de SQLAlchemy si se encuentra,
        o un error UserNotFoundError/DatabaseError.
    """
    user_repo = UserRepository(db)
    # UserRepository.get_by_email returns Result[UserInDB, ...]
    user_in_db_result = await user_repo.get_by_email(email=email)

    if user_in_db_result.is_failure():
        return user_in_db_result  # Pass through UserNotFoundError or DatabaseError

    # We have UserInDB, but need User (SQLAlchemy model) for auth.service
    user_in_db = user_in_db_result.unwrap()

    # Now, fetch the SQLAlchemy User model using the ID from UserInDB.
    # This assumes UserInDB has an 'id' field that corresponds to User.id.
    try:
        # db.get is efficient for Primary Key lookups.
        user_model = await db.get(User, user_in_db.id)
        if user_model is None:
            # This case should ideally not happen if UserInDB was found and IDs are consistent.
            logger.error(f"User ID {user_in_db.id} found via UserInDB but not as User model during re-fetch.")
            return Failure(UserNotFoundError(email=email, detail="User data consistency error after retrieval."))
        return Success(user_model)
    except SQLAlchemyError as e:
        logger.error(f"Database error when re-fetching User model for email {email} using ID {user_in_db.id}: {str(e)}", exc_info=True)
        return Failure(DatabaseError(detail=f"Error fetching full user details for email: {email}"))
