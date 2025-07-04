import os
import sys
from logging.config import fileConfig

from alembic import context
from dotenv import load_dotenv
from sqlalchemy import engine_from_config, pool

# Añadir el directorio raíz al path para poder importar desde app
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

# Cargar variables de entorno desde .env
load_dotenv()

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Configurar la URL de la base de datos desde variables de entorno
section = config.config_ini_section
config.set_section_option(
    section, "POSTGRES_USER", os.getenv("POSTGRES_USER", "postgres")
)
config.set_section_option(
    section, "POSTGRES_PASSWORD", os.getenv("POSTGRES_PASSWORD", "postgres")
)
config.set_section_option(
    section, "POSTGRES_HOST", os.getenv("POSTGRES_HOST", "localhost")
)
config.set_section_option(section, "POSTGRES_PORT", os.getenv("POSTGRES_PORT", "5432"))
config.set_section_option(
    section, "POSTGRES_DB", os.getenv("POSTGRES_DB", "app_statica_db")
)

# add your model's MetaData object here
# for 'autogenerate' support
from app.common.database import Base

# Importar todos los modelos para que Alembic los detecte
from app.contacts.models import Contact, ContactGroup
from app.roles.models import Permission, Role
from app.users.models import User, VerificationToken

target_metadata = Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.
    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.
    Calls to context.execute() here emit the given string to the
    script output.
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode.
    In this scenario we need to create an Engine
    and associate a connection with the context.
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
