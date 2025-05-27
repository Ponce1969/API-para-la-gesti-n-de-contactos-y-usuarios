"""Módulo de configuración de la aplicación.

Este módulo proporciona una forma de cargar y validar la configuración
desde variables de entorno, con valores por defecto y tipos fuertes.
"""

from functools import lru_cache
from typing import Any

from pydantic import AnyHttpUrl, EmailStr, Field, field_validator, model_validator, SecretStr # Import SecretStr
from pydantic.networks import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Configuración principal de la aplicación.

    Las variables de entorno deben estar prefijadas según se especifica en cada campo.
    """

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        env_nested_delimiter="__",
    )
    # ======================
    # Configuración de la aplicación
    # ======================
    DEBUG: bool = False
    SECRET_KEY: str = (
        "django-insecure-9f8h7g6f5d4s3a2s1d0a9s8d7f6g5h4j3k2l1q0w9e8r7t6y5"
    )
    ENVIRONMENT: str = "development"

    # Dominios permitidos para CORS
    CORS_ORIGINS: list[str] = ["http://localhost:3000"]  # Frontend por defecto

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def validate_cors_origins(cls, v: str | list[str]) -> list[str]:
        if isinstance(v, str) and not v.startswith("["):
            return [i.strip() for i in v.split(",")]
        elif isinstance(v, (list, str)):
            return v
        raise ValueError(
            "CORS_ORIGINS debe ser una lista o una cadena separada por comas"
        )

    # Tiempo de espera para operaciones asíncronas (segundos)
    ASYNC_TIMEOUT: int = 30

    # Configuración de la base de datos
    DATABASE_URL: PostgresDsn = (
        "postgresql+asyncpg://postgres:postgres@db:5432/app_statica_db"
    )
    DATABASE_ECHO: bool = False
    DATABASE_POOL_SIZE: int = 5
    DATABASE_MAX_OVERFLOW: int = 10

    # Configuración de autenticación
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 7  # 7 días
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30
    JWT_ALGORITHM: str = "HS256"
    JWT_SECRET_KEY: SecretStr = SecretStr( # Changed to SecretStr
        "django-insecure-9f8h7g6f5d4s3a2s1d0a9s8d7f6g5h4j3k2l1q0w9e8r7t6y5"
    )
    JWT_REFRESH_SECRET_KEY: SecretStr = SecretStr( # Changed to SecretStr
        "django-insecure-9f8h7g6f5d4s3a2s1d0a9s8d7f6g5h4j3k2l1q0w9e8r7t6y6"
    )

    # Configuración de expiración de tokens específicos
    EMAIL_VERIFICATION_TOKEN_EXPIRE_HOURS: int = Field(
        24, description="Horas de validez para el token de verificación de email"
    )
    RESET_PASSWORD_TOKEN_EXPIRE_HOURS: int = Field(
        2, description="Horas de validez para el token de reseteo de contraseña"
    )

    # URL del frontend (para emails, etc.)
    FRONTEND_URL: AnyHttpUrl = Field(
        "http://localhost:3000", description="URL base del frontend"
    )

    # ======================
    # Correo electrónico
    # ======================
    SMTP_TLS: bool = Field(
        True, env="APP_SMTP_TLS", description="Habilita TLS para conexiones SMTP"
    )

    SMTP_PORT: int | None = Field(
        None, env="APP_SMTP_PORT", description="Puerto del servidor SMTP"
    )

    SMTP_HOST: str | None = Field(
        None, env="APP_SMTP_HOST", description="Servidor SMTP para envío de correos"
    )

    SMTP_USER: str | None = Field(
        None, env="APP_SMTP_USER", description="Usuario para autenticación SMTP"
    )

    SMTP_PASSWORD: str | None = Field(
        None, env="APP_SMTP_PASSWORD", description="Contraseña para autenticación SMTP"
    )

    EMAILS_FROM_EMAIL: EmailStr | None = Field(
        None,
        env="APP_EMAILS_FROM_EMAIL",
        description="Dirección de correo del remitente por defecto",
    )

    EMAILS_FROM_NAME: str | None = Field(
        None, env="APP_EMAILS_FROM_NAME", description="Nombre del remitente por defecto"
    )

    # ======================
    # Configuración de la API
    # ======================
    API_V1_STR: str = Field(
        "/api/v1",
        env="APP_API_V1_STR",
        description="Prefijo para las rutas de la API v1",
    )

    PROJECT_NAME: str = Field(
        "App Estática",
        env="APP_PROJECT_NAME",
        description="Nombre del proyecto para documentación y metadatos",
    )

    VERSION: str = Field("0.1.0", env="APP_VERSION", description="Versión de la API")

    # ======================
    # Seguridad adicional
    # ======================
    SECURITY_PASSWORD_SALT: str = Field(
        "static_salt",  # Debe sobrescribirse en producción
        env="APP_SECURITY_PASSWORD_SALT",
        description="Sal para hashing de contraseñas",
    )

    RATE_LIMIT: int = Field(
        100,
        env="APP_RATE_LIMIT",
        description="Número máximo de peticiones por minuto por IP",
    )

    # ======================
    # Configuración de MCP (Model Context Protocol)
    # ======================
    MCP_ENABLED: bool = Field(
        default=False,
        env="APP_MCP_ENABLED",
        description="Habilitar servidor MCP para integración con IA",
    )

    MCP_API_KEY: str = Field(
        default="e5sGnoBF81qW40JqU2Pl8GS2ioZnUHgxBUbrGWd82nw",  # Debe cambiarse en producción
        env="APP_MCP_API_KEY",
        description="Clave API para que sistemas de IA se autentiquen con el servidor MCP",
    )

    # ======================
    # Configuraciones de desarrollo
    # ======================
    FIRST_SUPERUSER_EMAIL: EmailStr | None = Field(
        None,
        env="APP_FIRST_SUPERUSER_EMAIL",
        description="Email del primer superusuario (solo desarrollo)",
    )

    FIRST_SUPERUSER_PASSWORD: str | None = Field(
        None,
        env="APP_FIRST_SUPERUSER_PASSWORD",
        description="Contraseña del primer superusuario (solo desarrollo)",
    )

    @model_validator(mode="before")
    @classmethod
    def assemble_db_connection(cls, values: dict[str, Any]) -> dict[str, Any]:
        # Si ya hay una URL de base de datos, no hacer nada
        if values.get("DATABASE_URL"):
            return values

        # Construir la URL de conexión a partir de variables individuales
        # Esto es útil para entornos como Heroku que proporcionan DATABASE_URL como variable compuesta
        db_url = PostgresDsn.build(
            scheme="postgresql+asyncpg",
            username=values.get("POSTGRES_USER"),
            password=values.get("POSTGRES_PASSWORD"),
            host=values.get("POSTGRES_HOST", "localhost"),
            port=int(values.get("POSTGRES_PORT", 5432)),
            path=f"/{values.get('POSTGRES_DB', '')}",
        )
        values["DATABASE_URL"] = str(db_url)
        return values


@lru_cache
def get_settings() -> Settings:
    """Obtiene la configuración de la aplicación.

    Esta función está decorada con @lru_cache para evitar múltiples lecturas
    del archivo .env y mantener una única instancia de configuración.

    Returns:
        Settings: Instancia de configuración cargada desde las variables de entorno.
    """
    return Settings()


# Instancia de configuración para importación directa
settings = get_settings()
