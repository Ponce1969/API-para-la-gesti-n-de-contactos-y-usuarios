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
        
        from app.common.errors import ErrorCode # Import ErrorCode
        super().__init__(
            status_code=404,
            message=message,
            code=ErrorCode.RESOURCE_NOT_FOUND # Or a more specific code if defined
        )


class TokenInvalidError(AppError):
    """Error para cuando un token es inválido (expirado, usado, malformado)."""

    def __init__(self, token_value: str, reason: str) -> None:
        self.token_value = token_value
        self.reason = reason
        from app.common.errors import ErrorCode # Import ErrorCode
        super().__init__(
            status_code=400,
            message=f"Token inválido: {token_value}. Razón: {reason}",
            code=ErrorCode.INVALID_TOKEN # Or a more specific code if defined
        )


class UserAlreadyExistsError(AppError):
    """Excepción lanzada cuando se intenta crear un usuario que ya existe."""

    def __init__(self, email: str) -> None:
        from app.common.errors import ErrorCode

        super().__init__(
            message=f"El usuario con el correo electrónico '{email}' ya existe.",
            code=ErrorCode.DUPLICATE_ENTRY,
            status_code=409,  # Conflict
        )
