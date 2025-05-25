import asyncio
import sys
from pathlib import Path

# Agregar el directorio raíz al PYTHONPATH para importar correctamente los módulos
sys.path.append(str(Path(__file__).parent))

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.common.config import settings
from app.common.database import Base
from app.common.security import get_password_hash
from app.roles.models import Permission, Role, role_permissions
from app.users.models import User


async def init_db():
    # Configurar motor de base de datos
    DATABASE_URL = str(settings.DATABASE_URL)

    print(f"Connecting to {DATABASE_URL}")

    engine = create_async_engine(DATABASE_URL)

    # Crear tablas si no existen
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    # Crear sesión
    async_session_maker = sessionmaker(
        engine, class_=AsyncSession, expire_on_commit=False
    )

    # Crear usuario administrador
    async with async_session_maker() as session:
        # Verificar si ya existe el usuario admin
        admin_user = await session.get(User, 1)
        if not admin_user:
            print("Creando usuario administrador...")
            admin_user = User(
                email=settings.FIRST_SUPERUSER_EMAIL,
                hashed_password=get_password_hash(settings.FIRST_SUPERUSER_PASSWORD),
                full_name="Admin User",
                is_superuser=True,
                is_active=True,
                is_verified=True,
            )
            session.add(admin_user)

            # Crear rol de administrador si no existe
            admin_role = await session.get(Role, 1)
            if not admin_role:
                print("Creando rol de administrador...")
                admin_role = Role(
                    name="admin",
                    description="Administrador del sistema con todos los permisos",
                )
                session.add(admin_role)

                # Crear algunos permisos básicos
                permissions = [
                    Permission(code="users:read", name="Ver usuarios"),
                    Permission(code="users:create", name="Crear usuarios"),
                    Permission(code="users:update", name="Actualizar usuarios"),
                    Permission(code="users:delete", name="Eliminar usuarios"),
                    Permission(code="contacts:read", name="Ver contactos"),
                    Permission(code="contacts:create", name="Crear contactos"),
                    Permission(code="contacts:update", name="Actualizar contactos"),
                    Permission(code="contacts:delete", name="Eliminar contactos"),
                ]

                for perm in permissions:
                    session.add(perm)

                await session.flush()

                # Asignar todos los permisos al rol de administrador
                for perm in permissions:
                    # Insertar directamente en la tabla de asociación
                    await session.execute(
                        role_permissions.insert().values(
                            role_id=admin_role.id, permission_id=perm.id
                        )
                    )

            # Guardar los cambios
            await session.commit()
            print(
                f"\u2705 Usuario administrador creado con éxito: {settings.FIRST_SUPERUSER_EMAIL}"
            )
            print(f"\u2705 Contraseña: {settings.FIRST_SUPERUSER_PASSWORD}")
            print("\u2705 URL Swagger: http://localhost:8000/docs")
        else:
            print(f"⚠️ El usuario administrador ya existe: {admin_user.email}")


async def main():
    print("Inicializando base de datos...")
    await init_db()
    print("Proceso completado.")


if __name__ == "__main__":
    asyncio.run(main())
