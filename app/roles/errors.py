"""
Módulo de excepciones personalizadas para el dominio de roles.

Este módulo define excepciones personalizadas para manejar errores
específicos del dominio de roles de manera consistente en toda la aplicación.
"""

from fastapi import HTTPException, status

from app.common.errors import AppError, ResourceNotFoundError, ConflictError


class RoleError(AppError):
    """Clase base para todos los errores relacionados con roles."""
    pass


class RoleNotFoundError(ResourceNotFoundError):
    """Excepción lanzada cuando no se encuentra un rol solicitado."""
    
    def __init__(self, role_id: int = None, role_name: str = None):
        if role_id is not None:
            super().__init__(
                resource_name="rol",
                resource_id=role_id,
                detail=f"No se encontró el rol con ID {role_id}"
            )
        elif role_name is not None:
            super().__init__(
                resource_name="rol",
                detail=f"No se encontró el rol con nombre '{role_name}'"
            )
        else:
            super().__init__(
                resource_name="rol",
                detail="No se encontró el rol solicitado"
            )


class RoleAlreadyExistsError(ConflictError):
    """Excepción lanzada cuando se intenta crear un rol que ya existe."""
    
    def __init__(self, role_name: str):
        super().__init__(
            detail=f"Ya existe un rol con el nombre '{role_name}'"
        )


class RoleDeleteError(RoleError):
    """Excepción lanzada cuando no se puede eliminar un rol."""
    
    def __init__(self, role_id: int = None, message: str = None):
        if message is None:
            if role_id is not None:
                message = f"No se puede eliminar el rol con ID {role_id}"
            else:
                message = "No se puede eliminar el rol solicitado"
        
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=message,
        )


class SystemRoleModificationError(RoleError):
    """Excepción lanzada cuando se intenta modificar un rol del sistema."""
    
    def __init__(self, role_id: int = None, role_name: str = None):
        detail = "No se puede modificar un rol del sistema"
        if role_id is not None:
            detail = f"No se puede modificar el rol del sistema con ID {role_id}"
        elif role_name is not None:
            detail = f"No se puede modificar el rol del sistema '{role_name}'"
        
        super().__init__(
            status_code=status.HTTP_403_FORBIDDEN,
            message=detail,
        )


class PermissionNotFoundError(ResourceNotFoundError):
    """Excepción lanzada cuando no se encuentra un permiso solicitado."""
    
    def __init__(self, permission_id: int = None, permission_code: str = None):
        if permission_id is not None:
            super().__init__(
                resource_name="permiso",
                resource_id=permission_id,
                detail=f"No se encontró el permiso con ID {permission_id}"
            )
        elif permission_code is not None:
            super().__init__(
                resource_name="permiso",
                detail=f"No se encontró el permiso con código '{permission_code}'"
            )
        else:
            super().__init__(
                resource_name="permiso",
                detail="No se encontró el permiso solicitado"
            )


class PermissionAlreadyExistsError(ConflictError):
    """Excepción lanzada cuando se intenta crear un permiso que ya existe."""
    
    def __init__(self, permission_code: str = None, permission_name: str = None):
        if permission_code is not None:
            super().__init__(
                detail=f"Ya existe un permiso con el código '{permission_code}'"
            )
        elif permission_name is not None:
            super().__init__(
                detail=f"Ya existe un permiso con el nombre '{permission_name}'"
            )
        else:
            super().__init__(
                detail="Ya existe un permiso con los datos proporcionados"
            )


class RoleAssignmentError(RoleError):
    """Excepción lanzada cuando hay un error al asignar un rol a un usuario."""
    
    def __init__(self, message: str = "Error al asignar rol al usuario"):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=message,
        )


class PermissionAssignmentError(RoleError):
    """Excepción lanzada cuando hay un error al asignar un permiso a un rol."""
    
    def __init__(self, message: str = "Error al asignar permiso al rol"):
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            message=message,
        )


# Excepciones HTTP para uso directo en los handlers
ROLE_NOT_FOUND_EXCEPTION = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="No se encontró el rol solicitado",
)

ROLE_ALREADY_EXISTS_EXCEPTION = HTTPException(
    status_code=status.HTTP_409_CONFLICT,
    detail="Ya existe un rol con ese nombre",
)

SYSTEM_ROLE_MODIFICATION_EXCEPTION = HTTPException(
    status_code=status.HTTP_403_FORBIDDEN,
    detail="No se puede modificar un rol del sistema",
)

PERMISSION_NOT_FOUND_EXCEPTION = HTTPException(
    status_code=status.HTTP_404_NOT_FOUND,
    detail="No se encontró el permiso solicitado",
)


def handle_role_error(error: RoleError) -> HTTPException:
    """
    Maneja una excepción de roles y devuelve la respuesta HTTP apropiada.

    Args:
        error: Excepción de roles.

    Returns:
        HTTPException: Respuesta HTTP con el código de estado y mensaje apropiados.
    """
    if isinstance(error, RoleNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        )
    elif isinstance(error, RoleAlreadyExistsError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )
    elif isinstance(error, SystemRoleModificationError):
        return HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(error),
        )
    elif isinstance(error, (RoleDeleteError, RoleAssignmentError, PermissionAssignmentError)):
        return HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(error),
        )
    elif isinstance(error, PermissionNotFoundError):
        return HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(error),
        )
    elif isinstance(error, PermissionAlreadyExistsError):
        return HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(error),
        )
    else:
        # Error no manejado específicamente
        return HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error inesperado en el sistema de roles",
        )
