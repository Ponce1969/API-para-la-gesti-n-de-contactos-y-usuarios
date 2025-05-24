"""Módulo para manejo de resultados funcionales usando el patrón Result.

Este módulo proporciona utilidades para trabajar con el tipo Result de la biblioteca 'returns',
implementando un enfoque funcional para el manejo de errores y efectos secundarios.
"""

from __future__ import annotations

from functools import wraps
from typing import (
    Any,
    Awaitable,
    Callable,
    Coroutine,
    Generic,
    TypeVar,
    cast,
    overload,
)

from returns.future import FutureResult, FutureResultE, future_safe
from returns.io import IOFailure, IOResult, IOResultE, IOSuccess
from returns.maybe import Maybe, Nothing, Some
from returns.pipeline import is_successful
from returns.result import Failure, Result, Success

_ValueType = TypeVar("_ValueType", covariant=True)
_NewValueType = TypeVar("_NewValueType")
_ErrorType = TypeVar("_ErrorType", contravariant=True)
_NewErrorType = TypeVar("_NewErrorType")

# Re-export for easier imports
__all__ = [
    'Result',
    'Success',
    'Failure',
    'map_failure',
    'safe_try',
    'async_safe_try',
    'to_maybe',
    'to_ioresult',
    'from_ioresult',
    'from_ioresult_e',
    'get_or_raise',
    'get_or_default',
    'apply',
    'sequence',
]


def map_failure(
    result: Result[_ValueType, _ErrorType],
    mapper: Callable[[_ErrorType], _NewErrorType],
) -> Result[_ValueType, _NewErrorType]:
    """Mapea el error de un Result usando la función proporcionada.

    Args:
        result: El Result a mapear.
        mapper: Función que transforma el error.

    Returns:
        Un nuevo Result con el error mapeado.
    """
    if is_successful(result):
        return cast(Result[_ValueType, _NewErrorType], result)
    return Failure(mapper(cast(_ErrorType, result.failure())))


def safe_try(
    func: Callable[..., _ValueType], error_handler: Callable[[Exception], _ErrorType]
) -> Callable[..., Result[_ValueType, _ErrorType]]:
    """Envuelve una función que puede lanzar excepciones en un Result.

    Args:
        func: Función a envolver.
        error_handler: Manejador de excepciones que devuelve el tipo de error.

    Returns:
        Una función que devuelve un Result.
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Result[_ValueType, _ErrorType]:
        try:
            return Success(func(*args, **kwargs))
        except Exception as e:
            return Failure(error_handler(e))

    return wrapper


async def _async_wrapper(
    func: Callable[..., Awaitable[_ValueType]],
    error_handler: Callable[[Exception], _ErrorType],
    *args: Any,
    **kwargs: Any,
) -> FutureResult[_ValueType, _ErrorType]:
    try:
        result = await func(*args, **kwargs)
        return FutureResult.from_result(Success(result))
    except Exception as e:
        return FutureResult.from_result(Failure(error_handler(e)))


def async_safe_try(
    func: Callable[..., Awaitable[_ValueType]],
    error_handler: Callable[[Exception], _ErrorType],
) -> Callable[..., FutureResult[_ValueType, _ErrorType]]:
    """Versión asíncrona de safe_try que devuelve un FutureResult.

    Args:
        func: Función asíncrona a envolver.
        error_handler: Manejador de excepciones que devuelve el tipo de error.

    Returns:
        Una función asíncrona que devuelve un FutureResult.
    """

    @wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> FutureResult[_ValueType, _ErrorType]:
        return _async_wrapper(func, error_handler, *args, **kwargs)

    return wrapper


def to_maybe(result: Result[_ValueType, _ErrorType]) -> Maybe[_ValueType]:
    """Convierte un Result a un Maybe.

    Args:
        result: El Result a convertir.

    Returns:
        Un Maybe que contiene el valor si es Success, o Nothing si es Failure.
    """
    return Some(result.unwrap()) if is_successful(result) else Nothing


def to_ioresult(
    result: Result[_ValueType, _ErrorType],
) -> IOResult[_ValueType, _ErrorType]:
    """Convierte un Result a un IOResult.

    Args:
        result: El Result a convertir.

    Returns:
        Un IOResult equivalente al Result proporcionado.
    """
    if is_successful(result):
        return IOSuccess(cast(_ValueType, result.unwrap()))
    return IOFailure(cast(_ErrorType, result.failure()))


def from_ioresult(
    io_result: IOResult[_ValueType, _ErrorType],
) -> Result[_ValueType, _ErrorType]:
    """Convierte un IOResult a un Result.

    Args:
        io_result: El IOResult a convertir.

    Returns:
        Un Result equivalente al IOResult proporcionado.
    """
    if is_successful(io_result):
        return Success(cast(_ValueType, io_result.unwrap()))
    return Failure(cast(_ErrorType, io_result.failure()))


def from_ioresult_e(io_result: IOResultE[_ValueType]) -> Result[_ValueType, Exception]:
    """Convierte un IOResultE a un Result[ValueType, Exception].

    Args:
        io_result: El IOResultE a convertir.

    Returns:
        Un Result[ValueType, Exception] equivalente al IOResultE proporcionado.
    """
    if is_successful(io_result):
        return Success(cast(_ValueType, io_result.unwrap()))
    return Failure(cast(Exception, io_result.failure()))


def get_or_raise(result: Result[_ValueType, Exception]) -> _ValueType:
    """Obtiene el valor de un Result o lanza la excepción si es un Failure.

    Args:
        result: El Result del cual obtener el valor.

    Returns:
        El valor contenido en el Result si es Success.

    Raises:
        Exception: Si el Result es un Failure.
    """
    if is_successful(result):
        return cast(_ValueType, result.unwrap())
    raise cast(Exception, result.failure())


def get_or_default(
    result: Result[_ValueType, _ErrorType], default: _ValueType
) -> _ValueType:
    """Obtiene el valor de un Result o un valor por defecto si es un Failure.

    Args:
        result: El Result del cual obtener el valor.
        default: Valor por defecto a devolver si el Result es un Failure.

    Returns:
        El valor contenido en el Result si es Success, o el valor por defecto.
    """
    return cast(_ValueType, result.unwrap()) if is_successful(result) else default


def apply(
    func: Callable[..., _NewValueType],
    *args: Result[Any, _ErrorType],
) -> Result[_NewValueType, _ErrorType]:
    """Aplica una función a los valores contenidos en los Results.

    Args:
        func: Función a aplicar.
        *args: Argumentos para la función, cada uno envuelto en un Result.

    Returns:
        Un Result que contiene el resultado de aplicar la función si todos los argumentos
        son Success, o el primer error encontrado.
    """
    values: list[Any] = []
    for arg in args:
        if not is_successful(arg):
            return cast(Result[_NewValueType, _ErrorType], arg)
        values.append(arg.unwrap())
    return Success(func(*values))


def sequence(
    results: list[Result[_ValueType, _ErrorType]],
) -> Result[list[_ValueType], _ErrorType]:
    """Convierte una lista de Results en un Result de lista.

    Args:
        results: Lista de Results a secuenciar.

    Returns:
        Un Result que contiene una lista de valores si todos son Success,
        o el primer error encontrado.
    """
    values: list[_ValueType] = []
    for result in results:
        if not is_successful(result):
            return cast(Result[list[_ValueType], _ErrorType], result)
        values.append(cast(_ValueType, result.unwrap()))
    return Success(values)
