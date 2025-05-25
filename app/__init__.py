"""
Paquete principal de la aplicación.

Este paquente contiene todos los módulos y paquetes que conforman la aplicación.
"""

from typing import List

__all__: List[str] = []

# Importar configuraciones
try:
    from .common.config import get_settings, settings
    from .common.database import Base, SessionLocal, get_db
    from .common.logging import setup_logging

    # Configurar logging si no se ha configurado ya
    # setup_logging() # Temporarily commented out for pytest debugging

    # Importar modelos para que SQLAlchemy los registre
    # from .auth import models as auth_models  # noqa: F401 (app.auth.models does not exist)
    from .contacts import models as contacts_models  # noqa: F401
    from .roles import models as roles_models  # noqa: F401
    from .users import models as users_models  # noqa: F401

    # Lista de todos los modelos para facilitar las importaciones
    _exported_names = [
        "settings",
        "get_settings",
        "Base",
        "SessionLocal",
        "get_db",
        "setup_logging",
    ]
    __all__.extend(_exported_names)

except ImportError as e:
    import warnings
    # __all__ permanecerá como [] si las importaciones fallan, lo cual es la intención.
    warnings.warn(f"No se pudieron importar todos los módulos comunes: {e}")

    # No es necesario redefinir __all__ aquí, ya está inicializado.
