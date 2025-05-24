"""
Punto de entrada principal de la aplicación FastAPI.

Este módulo configura e inicia la aplicación FastAPI con todos sus routers,
middlewares y dependencias necesarias.
"""
import logging
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.common.config import settings
from app.common.logging import setup_logging

# Configurar logging
setup_logging()
logger = logging.getLogger(__name__)

# Crear la aplicación FastAPI
app = FastAPI(
    title=settings.PROJECT_NAME,
    description="API para la gestión de contactos y usuarios",
    version=settings.VERSION,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configurar CORS
if settings.CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[str(origin) for origin in settings.CORS_ORIGINS],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Manejo de errores de validación
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError):
    logger.error(f"Error de validación: {exc.errors()}")
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"detail": exc.errors(), "body": exc.body},
    )

# Incluir routers
from app.auth.api import router as auth_router
from app.users.api import router as users_router
from app.contacts.api import router as contacts_router
from app.roles.api import router as roles_router

app.include_router(auth_router, prefix=f"{settings.API_V1_STR}/auth", tags=["auth"])
app.include_router(users_router, prefix=f"{settings.API_V1_STR}/users", tags=["users"])
app.include_router(contacts_router, prefix=f"{settings.API_V1_STR}/contacts", tags=["contacts"])
app.include_router(roles_router, prefix=f"{settings.API_V1_STR}/roles", tags=["roles"])

# Health check endpoint
@app.get("/health", tags=["health"])
async def health_check():
    return {"status": "healthy"}

# Evento de inicio
@app.on_event("startup")
async def startup_event():
    logger.info("Iniciando la aplicación...")
    # Aquí podrías inicializar conexiones a bases de datos, etc.

# Evento de apagado
@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Apagando la aplicación...")
    # Aquí podrías cerrar conexiones a bases de datos, etc.

# Para ejecutar con uvicorn directamente: uvicorn app.main:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )