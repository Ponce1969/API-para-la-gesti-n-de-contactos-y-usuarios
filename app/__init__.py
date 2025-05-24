"""
Paquete principal de la aplicación.

Este paquente contiene todos los módulos y paquetes que conforman la aplicación.
"""
from typing import List

# Importar configuraciones
try:
    from .common.config import settings, get_settings
    from .common.database import Base, SessionLocal, get_db
    from .common.logging import setup_logging
    
    # Configurar logging si no se ha configurado ya
    setup_logging()
    
    # Importar modelos para que SQLAlchemy los registre
    from .users import models as users_models
    from .auth import models as auth_models
    from .contacts import models as contacts_models
    from .roles import models as roles_models
    
    # Lista de todos los modelos para facilitar las importaciones
    __all__ = [
        'settings',
        'get_settings',
        'Base',
        'SessionLocal',
        'get_db',
        'setup_logging',
    ]
    
except ImportError as e:
    import warnings
    warnings.warn(f"No se pudieron importar todos los módulos comunes: {e}")
    
    # Definir variables por defecto para evitar errores de importación
    __all__: List[str] = []
