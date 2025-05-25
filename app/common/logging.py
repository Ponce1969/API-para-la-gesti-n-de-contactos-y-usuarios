"""
Módulo de configuración de logging para la aplicación.

Este módulo proporciona una función para configurar el logging de manera centralizada,
asegurando consistencia en el formato y nivel de logs en toda la aplicación.
"""

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional


def setup_logging(
    log_file: Optional[str] = None, log_level: int = logging.INFO
) -> None:
    """
    Configura el sistema de logging para la aplicación.

    Args:
        log_file: Ruta al archivo de log. Si es None, solo se mostrarán los logs en consola.
        log_level: Nivel de logging (por defecto: logging.INFO)
    """
    # Crear el directorio de logs si no existe
    if log_file:
        log_path = Path(log_file).parent
        log_path.mkdir(parents=True, exist_ok=True)

    # Configurar el formato de los logs
    formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Configurar el logger raíz
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Eliminar handlers existentes para evitar duplicados
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)

    # Configurar handler para consola
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)

    # Configurar handler para archivo si se especificó
    if log_file:
        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=10 * 1024 * 1024,  # 10 MB
            backupCount=5,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root_logger.addHandler(file_handler)

    # Configurar nivel de logging para bibliotecas específicas
    logging.getLogger("uvicorn").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)

    # Configurar el logger de la aplicación
    app_logger = logging.getLogger("app")
    app_logger.setLevel(log_level)

    logging.info("Logging configurado correctamente")
