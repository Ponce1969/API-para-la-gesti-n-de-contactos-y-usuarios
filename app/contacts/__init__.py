"""
Módulo de gestión de contactos.

Este módulo maneja la lógica de negocio, modelos y rutas para la gestión
de contactos y grupos de contactos en la aplicación.
"""

from . import errors, models, schemas

# Importar modelos
from .models import Contact, ContactGroup, contact_group_members

# Importar esquemas
from .schemas import (
    ContactCreate,
    ContactGroupCreate,
    ContactGroupResponse,
    ContactGroupUpdate,
    ContactInDB,
    ContactResponse,
    ContactUpdate,
    ContactListResponse,
    ContactGroupListResponse,
)

# Importar servicios
from .service import ContactService, ContactGroupService

# Importar enrutador para la API
from .handlers import router as contact_router
__all__ = [
    # Módulos
    "models",
    "schemas",
    "errors",
    
    # Modelos
    "Contact",
    "ContactGroup",
    "contact_group_members",
    
    # Esquemas
    "ContactCreate",
    "ContactUpdate",
    "ContactResponse",
    "ContactInDB",
    "ContactListResponse",
    "ContactGroupCreate",
    "ContactGroupUpdate",
    "ContactGroupResponse",
    "ContactGroupListResponse",
    
    # Servicios
    "ContactService",
    "ContactGroupService",
    
    # Router
    "contact_router",
]
