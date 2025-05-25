"""Script para crear un usuario administrador en la base de datos.

Este script debe ejecutarse dentro del contenedor Docker de la API.
"""

import asyncio
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

# Agregar el directorio raíz al PYTHONPATH
sys.path.append("/app")

from app.common.config import settings
from app.common.database import AsyncSessionLocal, Base
from app.common.security import get_password_hash


async def create_tables():
    """Crea todas las tablas de la base de datos si no existen."""
    DATABASE_URL = str(settings.DATABASE_URL)
    engine = create_async_engine(DATABASE_URL)
    print(f"[INFO] Creando tablas en {DATABASE_URL} si no existen...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    await engine.dispose()


async def create_admin() -> None:
    """Crea un usuario administrador en la base de datos."""
    print("Iniciando creación de usuario administrador...")

    # Crear superusuario
    admin_email = "admin@app-statica.com"
    admin_password = "Admin123*"

    # Abrir sesión de base de datos
    async with AsyncSessionLocal() as session:
        # Verificar si ya existe el usuario admin
        query = text("SELECT id, email FROM users WHERE email = :email")
        result = await session.execute(query, {"email": admin_email})
        admin_user = result.first()

        if not admin_user:
            print("Creando usuario administrador...")

            # Crear usuario
            query = text(
                """
            INSERT INTO users (email, hashed_password, first_name, last_name, language, timezone, is_superuser, is_active, is_verified, created_at, updated_at)
            VALUES (:email, :hashed_password, :first_name, :last_name, :language, :timezone, :is_superuser, :is_active, :is_verified, NOW(), NOW())
            RETURNING id
            """
            )

            values = {
                "email": admin_email,
                "hashed_password": get_password_hash(admin_password),
                "first_name": "Admin",
                "last_name": "User",
                "language": "es",  # o "en" si prefieres inglés
                "timezone": "America/Montevideo",
                "is_superuser": True,
                "is_active": True,
                "is_verified": True,
            }

            result = await session.execute(query, values)
            user_id = result.scalar_one()

            # Crear rol de administrador si no existe
            query = text("SELECT id FROM roles WHERE name = 'admin'")
            result = await session.execute(query)
            admin_role = result.scalar()

            if not admin_role:
                print("Creando rol de administrador...")

                # Crear rol
                query = text(
                    """
                INSERT INTO roles (name, description, is_active, is_system, created_at, updated_at)
                VALUES (:name, :description, :is_active, :is_system, NOW(), NOW())
                RETURNING id
                """
                )

                values = {
                    "name": "admin",
                    "description": "Administrador del sistema con todos los permisos",
                    "is_active": True,
                    "is_system": True,
                }

                result = await session.execute(query, values)
                role_id = result.scalar_one()

                # Asignar rol al usuario
                query = text(
                    """
                INSERT INTO user_roles (user_id, role_id, assigned_at, is_active)
                VALUES (:user_id, :role_id, NOW(), TRUE)
                """
                )

                await session.execute(query, {"user_id": user_id, "role_id": role_id})

            # Guardar los cambios
            await session.commit()
            print("\u2705 Usuario administrador creado con u00e9xito:")
            print(f"\u2705 Email: {admin_email}")
            print(f"\u2705 Contraseu00f1a: {admin_password}")
            print("\u2705 URL Swagger: http://localhost:8000/docs")
        else:
            print(
                f"\u26a0ufe0f El usuario administrador ya existe con ID: {admin_user.id}, email: {admin_user.email}"
            )


async def main() -> None:
    print("\n==== CREANDO USUARIO ADMINISTRADOR ====\n")
    await create_admin()
    print("\n==== PROCESO COMPLETADO ====\n")


if __name__ == "__main__":

    async def run_all() -> None:
        await create_tables()
        await main()

    asyncio.run(run_all())
