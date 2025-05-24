"""Módulo para manejo de resultados funcionales usando el patrón Result.

Este módulo proporciona utilidades para trabajar con el tipo Result de la biblioteca 'returns',
implementando un enfoque funcional para el manejo de errores y efectos secundarios.
"""
from functools import wraps
from typing import Any, Callable, TypeVar, cast, overload

from returns.future import FutureResult, future_safe
from returns.io import IOResult, impure_safe
from returns.pipeline import is_successful
from returns.result import Failure, Result, Success

# Type variables for generic functions
_ValueType = TypeVar("_ValueType")
_ErrorType = TypeVar("_ErrorType")
_NewValueType = TypeVar("_NewValueType")
_NewErrorType = TypeVar("_NewErrorType")


def map_failure(
    result: Result[_ValueType, _ErrorType],
    mapper: Callable[[_ErrorType], _NewErrorType],
) -> Result[_ValueType, _NewErrorType]:
    """Mapea el error de un Result usando la función proporcionada.
    
    Args:
        result: El Result a mapear
        mapper: Función que transforma el error
        
    Returns:
        Un nuevo Result con el error transformado
    """
    if is_successful(result):
        return cast(Result[_ValueType, _NewErrorType], result)
    return Failure(mapper(cast(_ErrorType, result.failure())))


def to_async(
    func: Callable[..., Result[_ValueType, _ErrorType]]
) -> Callable[..., FutureResult[_ValueType, _ErrorType]]:
    """Convierte una función síncrona que devuelve Result en una asíncrona.
    
    Args:
        func: Función síncrona que devuelve un Result
        
    Returns:
        Función asíncrona que devuelve un FutureResult
    """
    @future_safe
    async def wrapper(*args: Any, **kwargs: Any) -> Result[_ValueType, _ErrorType]:
        return func(*args, **kwargs)
    
    return wrapper


def to_io(
    func: Callable[..., Result[_ValueType, _ErrorType]]
) -> Callable[..., IOResult[_ValueType, _ErrorType]]:
    """Convierte una función síncrona que devuelve Result en una que devuelve IOResult.
    
    Args:
        func: Función síncrona que devuelve un Result
        
    Returns:
        Función que devuelve un IOResult
    """
    @impure_safe
    def wrapper(*args: Any, **kwargs: Any) -> Result[_ValueType, _ErrorType]:
        return func(*args, **kwargs)
    
    return wrapper


def safe_try(
    func: Callable[..., _ValueType],
    error_handler: Callable[[Exception], _ErrorType]
) -> Callable[..., Result[_ValueType, _ErrorType]]:
    """Decodificador que convierte excepciones en resultados fallidos.
    
    Args:
        func: Función que puede lanzar excepciones
        error_handler: Manejador que convierte excepciones en errores tipados
        
    Returns:
        Función que devuelve un Result
    """
    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Result[_ValueType, _ErrorType]:
        try:
            return Success(func(*args, **kwargs))
        except Exception as e:
            return Failure(error_handler(e))
    
    return wrapper


# Sobrecarga para funciones sin argumentos
@overload
def async_try(
    func: Callable[[], _ValueType],
    error_handler: Callable[[Exception], _ErrorType]
) -> Callable[[], FutureResult[_ValueType, _ErrorType]]: ...

# Sobrecarga para funciones con argumentos
@overload
def async_try(
    func: Callable[..., _ValueType],
    error_handler: Callable[[Exception], _ErrorType]
) -> Callable[..., FutureResult[_ValueType, _ErrorType]]: ...

def async_try(
    func: Callable[..., _ValueType],
    error_handler: Callable[[Exception], _ErrorType]
):
    """Combina safe_try con to_async para operaciones asíncronas seguras.
    
    Args:
        func: Función que puede lanzar excepciones
        error_handler: Manejador que convierte excepciones en errores tipados
        
    Returns:
        Función asíncrona que devuelve un FutureResult
    """
    return to_async(safe_try(func, error_handler))


def unwrap_result(
    result: Result[_ValueType, _ErrorType],
    error_message: str = "Error al desempaquetar resultado"
) -> _ValueType:
    """Desempaqueta un Result, lanzando una excepción si es un fallo.
    
    Args:
        result: El Result a desempaquetar
        error_message: Mensaje de error personalizado
        
    Returns:
        El valor contenido en el Result
        
    Raises:
        ValueError: Si el Result es un fallo
    """
    if is_successful(result):
        return cast(_ValueType, result.unwrap())
    raise ValueError(f"{error_message}: {result.failure()}")


def unwrap_or_raise(
    result: Result[_ValueType, Exception],
) -> _ValueType:
    """Desempaqueta un Result, lanzando la excepción contenida si es un fallo.
    
    Args:
        result: El Result a desempaquetar
        
    Returns:
        El valor contenido en el Result
        
    Raises:
        Exception: La excepción contenida en el Result si es un fallo
    """
    if is_successful(result):
        return cast(_ValueType, result.unwrap())
    raise cast(Exception, result.failure())
