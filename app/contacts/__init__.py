"""
Módulo de gestión de contactos.

Este módulo maneja la lógica de negocio, modelos y rutas para la gestión
de contactos y grupos de contactos en la aplicación.
"""
from . import models, schemas, service, errors, api
from .models import Contact, ContactGroup, ContactGroupMember
from .schemas import (
    ContactCreate,
    ContactUpdate,
    ContactResponse,
    ContactInDB,
    ContactGroupCreate,
    ContactGroupResponse,
    ContactGroupUpdate,
)
from .service import (
    get_contact_by_id,
    get_contacts,
    create_contact,
    update_contact,
    delete_contact,
    get_contact_group_by_id,
    get_contact_groups,
    create_contact_group,
    update_contact_group,
    delete_contact_group,
    add_contact_to_group,
    remove_contact_from_group,
    get_contacts_in_group,
)

__all__ = [
    'models',
    'schemas',
    'service',
    'errors',
    'api',
    'Contact',
    'ContactGroup',
    'ContactGroupMember',
    'ContactCreate',
    'ContactUpdate',
    'ContactResponse',
    'ContactInDB',
    'ContactGroupCreate',
    'ContactGroupResponse',
    'ContactGroupUpdate',
    'get_contact_by_id',
    'get_contacts',
    'create_contact',
    'update_contact',
    'delete_contact',
    'get_contact_group_by_id',
    'get_contact_groups',
    'create_contact_group',
    'update_contact_group',
    'delete_contact_group',
    'add_contact_to_group',
    'remove_contact_from_group',
    'get_contacts_in_group',
]