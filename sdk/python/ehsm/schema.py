from typing import Type, Any
from marshmallow import Schema, fields
from dataclasses import dataclass


def ehsm_response(schema: Type[Schema]):
    """
    ehsm_response is a class decorator, wraps a `Schema` into response from eHSM server

    Usage::

        >>> @ehsm_response
        ... class SimpleResponse(Schema):
        ...     app_id = fields.Str()
        >>> { code: int, message: str, result: { app_id: str } }
    """
    class EHSMResponse(Schema):
        code = fields.Int()
        message = fields.Str()
        result = fields.Nested(schema)
    # set the name
    EHSMResponse.__name__ = schema.__name__
    return EHSMResponse


class EHSMResponseSchema(Schema):
    code = fields.Int()
    message = fields.Str()
    result: Any
    
    
