"""Errores específicos para el módulo de usuarios."""


from app.common.errors import AppError, ResourceNotFoundError


class UserNotFoundError(ResourceNotFoundError):
    """Excepción lanzada cuando no se encuentra un usuario específico."""

    def __init__(
        self, user_id: int | str | None = None, email: str | None = None
    ) -> None:
        resource_identifier = user_id if user_id is not None else email
        super().__init__(
            resource_name="usuario",
            resource_id=str(resource_identifier)
            if resource_identifier
            else "desconocido",
            # Puedes asignar un ErrorCode más específico si lo defines en common.errors.ErrorCode
            # code=ErrorCode.USER_NOT_FOUND
        )


class VerificationTokenNotFoundError(AppError):
    """Error para cuando no se encuentra un token de verificación."""

    def __init__(
        self,
        token_value: str | None = None,
        criteria: str | None = None,
        user_id: int | None = None,
    ) -> None:
        self.token_value = token_value
        self.criteria = criteria
        self.user_id = user_id

        message = "Token de verificación no encontrado"
        details = []
        if token_value:
            details.append(f"token: '{token_value}'")
        if criteria:
            details.append(f"criterio: '{criteria}'")
        if (
            user_id is not None
        ):  # Check against None to correctly handle user_id = 0 if possible
            details.append(f"ID de usuario: {user_id}")

        if details:
            message += f" ({', '.join(details)})."
        else:
            message += "."

        super().__init__(message, status_code=404)


class TokenInvalidError(AppError):
    """Error para cuando un token es inválido (expirado, usado, malformado)."""

    def __init__(self, token_value: str, reason: str) -> None:
        self.token_value = token_value
        self.reason = reason
        super().__init__(
            f"Token inválido: {token_value}. Razón: {reason}", status_code=400
        )


class UserAlreadyExistsError(AppError):
    """Excepción lanzada cuando se intenta crear un usuario que ya existe."""

    def __init__(self, email: str) -> None:
        super().__init__(
            detail=f"El usuario con el correo electrónico '{email}' ya existe.",
            # Puedes asignar un ErrorCode más específico si lo defines en common.errors.ErrorCode
            # code=ErrorCode.USER_ALREADY_EXISTS
        )
        # Sobrescribimos el código de error si queremos uno más específico que DUPLICATE_ENTRY
        # self.code = "USER_001" # Ejemplo
