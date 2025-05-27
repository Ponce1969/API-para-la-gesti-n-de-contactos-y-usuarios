"""
Excepciones personalizadas para el módulo de contactos.

Este módulo define las excepciones específicas para manejar
errores relacionados con contactos y grupos de contactos,
siguiendo el patrón de manejo funcional de errores.
"""

from http import HTTPStatus
from typing import Any, Dict, Optional

from fastapi import HTTPException

from app.common.errors import AppError
from fastapi import HTTPException as AppException


# Errores generales
class DatabaseError(AppError):
    """Error de base de datos."""
    
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


# Errores de dominio de Contactos
class ContactError(AppError):
    """Clase base para errores relacionados con contactos."""

    pass


class ContactNotFoundError(ContactError):
    """Error lanzado cuando no se encuentra un contacto."""

    def __init__(self, contact_id: int, message: Optional[str] = None):
        self.contact_id = contact_id
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=message or f"No se encontró un contacto con ID {contact_id}"
        )


class ContactAlreadyExistsError(ContactError):
    """Error lanzado cuando se intenta crear un contacto con datos duplicados."""

    def __init__(self, email: str, message: Optional[str] = None):
        self.email = email
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.DUPLICATE_ENTRY,
            message=message or f"Ya existe un contacto con el email {email}"
        )


class ContactValidationError(ContactError):
    """Error lanzado cuando hay problemas de validación con los datos de un contacto."""

    def __init__(self, errors: Dict[str, Any], message: Optional[str] = None):
        self.errors = errors
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code=ErrorCode.VALIDATION_ERROR,
            message=message or f"Error de validación en los datos del contacto: {errors}",
            detail=errors
        )


# Errores de dominio de Grupos de Contactos
class ContactGroupError(AppError):
    """Clase base para errores relacionados con grupos de contactos."""

    pass


class ContactGroupNotFoundError(ContactGroupError):
    """Error lanzado cuando no se encuentra un grupo de contactos."""

    def __init__(self, group_id: int, message: Optional[str] = None):
        self.group_id = group_id
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=message or f"No se encontró un grupo de contactos con ID {group_id}"
        )


class ContactGroupAlreadyExistsError(ContactGroupError):
    """Error lanzado cuando se intenta crear un grupo de contactos con nombre duplicado."""

    def __init__(self, name: str, owner_id: int, message: Optional[str] = None):
        self.name = name
        self.owner_id = owner_id
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.DUPLICATE_ENTRY,
            message=message
            or f"Ya existe un grupo de contactos con el nombre {name} para este usuario"
        )


class ContactGroupValidationError(ContactGroupError):
    """Error lanzado cuando hay problemas de validación con los datos de un grupo de contactos."""

    def __init__(self, errors: Dict[str, Any], message: Optional[str] = None):
        self.errors = errors
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            code=ErrorCode.VALIDATION_ERROR,
            message=message
            or f"Error de validación en los datos del grupo de contactos: {errors}",
            detail=errors
        )


# Errores de relación entre Contactos y Grupos
class ContactGroupRelationError(AppError):
    """Clase base para errores relacionados con la relación entre contactos y grupos."""

    pass


class ContactNotInGroupError(ContactGroupRelationError):
    """Error lanzado cuando se intenta eliminar un contacto de un grupo al que no pertenece."""

    def __init__(self, contact_id: int, group_id: int, message: Optional[str] = None):
        self.contact_id = contact_id
        self.group_id = group_id
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND, # Or 400 Bad Request depending on context
            code=ErrorCode.VALIDATION_ERROR, # Or a custom code
            message=message
            or f"El contacto con ID {contact_id} no pertenece al grupo con ID {group_id}"
        )


class ContactAlreadyInGroupError(ContactGroupRelationError):
    """Error lanzado cuando se intenta agregar un contacto a un grupo al que ya pertenece."""

    def __init__(self, contact_id: int, group_id: int, message: Optional[str] = None):
        self.contact_id = contact_id
        self.group_id = group_id
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_409_CONFLICT,
            code=ErrorCode.DUPLICATE_ENTRY, # Or a custom code
            message=message
            or f"El contacto con ID {contact_id} ya pertenece al grupo con ID {group_id}"
        )


class UnauthorizedContactAccessError(ContactError):
    """Error lanzado cuando un usuario intenta acceder a un contacto que no le pertenece."""

    def __init__(self, contact_id: int, message: Optional[str] = None):
        self.contact_id = contact_id
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.INSUFFICIENT_PERMISSIONS,
            message=message
            or f"No está autorizado para acceder al contacto con ID {contact_id}"
        )


class UnauthorizedGroupAccessError(ContactGroupError):
    """Error lanzado cuando un usuario intenta acceder a un grupo que no le pertenece."""

    def __init__(self, group_id: int, message: Optional[str] = None):
        self.group_id = group_id
        from app.common.errors import ErrorCode, status # Import status
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            code=ErrorCode.INSUFFICIENT_PERMISSIONS,
            message=message or f"No está autorizado para acceder al grupo con ID {group_id}"
        )


# Excepciones HTTP para los errores del dominio de Contactos
class ContactHTTPException(AppException):
    """Clase base para excepciones HTTP relacionadas con contactos."""

    pass


class ContactNotFoundException(ContactHTTPException):
    """Excepción HTTP para contacto no encontrado."""

    def __init__(self, contact_id: int, message: Optional[str] = None):
        status_code = HTTPStatus.NOT_FOUND
        detail = message or f"No se encontró un contacto con ID {contact_id}"
        super().__init__(status_code=status_code, detail=detail)


class ContactAlreadyExistsException(ContactHTTPException):
    """Excepción HTTP para contacto ya existente."""

    def __init__(self, email: str, message: Optional[str] = None):
        status_code = HTTPStatus.CONFLICT
        detail = message or f"Ya existe un contacto con el email {email}"
        super().__init__(status_code=status_code, detail=detail)


class ContactValidationException(ContactHTTPException):
    """Excepción HTTP para errores de validación de contactos."""

    def __init__(self, errors: Dict[str, Any], message: Optional[str] = None):
        status_code = HTTPStatus.BAD_REQUEST
        detail = {
            "message": message or "Error de validación en los datos del contacto",
            "errors": errors,
        }
        super().__init__(status_code=status_code, detail=detail)


class ContactGroupNotFoundException(ContactHTTPException):
    """Excepción HTTP para grupo de contactos no encontrado."""

    def __init__(self, group_id: int, message: Optional[str] = None):
        status_code = HTTPStatus.NOT_FOUND
        detail = message or f"No se encontró un grupo de contactos con ID {group_id}"
        super().__init__(status_code=status_code, detail=detail)


class ContactGroupAlreadyExistsException(ContactHTTPException):
    """Excepción HTTP para grupo de contactos ya existente."""

    def __init__(self, name: str, message: Optional[str] = None):
        status_code = HTTPStatus.CONFLICT
        detail = (
            message
            or f"Ya existe un grupo de contactos con el nombre {name} para este usuario"
        )
        super().__init__(status_code=status_code, detail=detail)


class ContactNotInGroupException(ContactHTTPException):
    """Excepción HTTP para contacto no perteneciente a un grupo."""

    def __init__(self, contact_id: int, group_id: int, message: Optional[str] = None):
        status_code = HTTPStatus.NOT_FOUND
        detail = (
            message
            or f"El contacto con ID {contact_id} no pertenece al grupo con ID {group_id}"
        )
        super().__init__(status_code=status_code, detail=detail)


class ContactAlreadyInGroupException(ContactHTTPException):
    """Excepción HTTP para contacto ya perteneciente a un grupo."""

    def __init__(self, contact_id: int, group_id: int, message: Optional[str] = None):
        status_code = HTTPStatus.CONFLICT
        detail = (
            message
            or f"El contacto con ID {contact_id} ya pertenece al grupo con ID {group_id}"
        )
        super().__init__(status_code=status_code, detail=detail)


class UnauthorizedContactAccessException(ContactHTTPException):
    """Excepción HTTP para acceso no autorizado a un contacto."""

    def __init__(self, contact_id: int, message: Optional[str] = None):
        status_code = HTTPStatus.FORBIDDEN
        detail = (
            message
            or f"No está autorizado para acceder al contacto con ID {contact_id}"
        )
        super().__init__(status_code=status_code, detail=detail)


class UnauthorizedGroupAccessException(ContactHTTPException):
    """Excepción HTTP para acceso no autorizado a un grupo."""

    def __init__(self, group_id: int, message: Optional[str] = None):
        status_code = HTTPStatus.FORBIDDEN
        detail = (
            message or f"No está autorizado para acceder al grupo con ID {group_id}"
        )
        super().__init__(status_code=status_code, detail=detail)


# Función para convertir errores de dominio a excepciones HTTP
def contact_error_to_http_exception(error: AppError) -> HTTPException:
    """
    Convierte un error de dominio de contactos a una excepción HTTP.

    Args:
        error: El error de dominio a convertir.

    Returns:
        Una excepción HTTP adecuada para el error de dominio.
    """
    if isinstance(error, ContactNotFoundError):
        return ContactNotFoundException(error.contact_id)
    elif isinstance(error, ContactAlreadyExistsError):
        return ContactAlreadyExistsException(error.email)
    elif isinstance(error, ContactValidationError):
        return ContactValidationException(error.errors)
    elif isinstance(error, ContactGroupNotFoundError):
        return ContactGroupNotFoundException(error.group_id)
    elif isinstance(error, ContactGroupAlreadyExistsError):
        return ContactGroupAlreadyExistsException(error.name)
    elif isinstance(error, ContactNotInGroupError):
        return ContactNotInGroupException(error.contact_id, error.group_id)
    elif isinstance(error, ContactAlreadyInGroupError):
        return ContactAlreadyInGroupException(error.contact_id, error.group_id)
    elif isinstance(error, UnauthorizedContactAccessError):
        return UnauthorizedContactAccessException(error.contact_id)
    elif isinstance(error, UnauthorizedGroupAccessError):
        return UnauthorizedGroupAccessException(error.group_id)
    else:
        # Error genérico
        return HTTPException(
            status_code=HTTPStatus.INTERNAL_SERVER_ERROR,
            detail=f"Error inesperado: {str(error)}",
        )
