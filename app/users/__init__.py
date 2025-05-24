"""
Módulo de usuarios.

Este módulo contiene la lógica de negocio, modelos y rutas para la gestión de usuarios.
"""
from . import models, schemas, service, errors, handlers
from .models import User
from .schemas import UserCreate, UserUpdate, UserResponse, UserInDB
from .service import (
    get_user_by_id,
    get_user_by_email,
    get_users,
    create_user,
    update_user,
    delete_user,
    authenticate_user,
    get_current_user,
    get_current_active_user,
)

__all__ = [
    'models',
    'schemas',
    'service',
    'errors',
    'handlers',
    'User',
    'UserCreate',
    'UserUpdate',
    'UserResponse',
    'UserInDB',
    'get_user_by_id',
    'get_user_by_email',
    'get_users',
    'create_user',
    'update_user',
    'delete_user',
    'authenticate_user',
    'get_current_user',
    'get_current_active_user',
]