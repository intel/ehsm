from typing import Callable, Type, Any, Optional
from click import Parameter, Context
from enum import Enum
import click
import functools

from ehsm.exceptions import CredentialMissingException


def with_credential_missing_handler(func: Callable):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except CredentialMissingException:
            click.echo(
                "Credentials needed, please specified --appid and --apikey", err=True
            )

    return wrapper


# EnumChoice implementation from click project's PR
# Reference: https://github.com/pallets/click/pull/2210/files/0f8868a763d3d37e7a5aa0b871ee5b2824e658f3#diff-dcb534e6a7591b92836537d4655ddbd2f18e3b293c3420144c30a9ca08f65c4eR339
class EnumChoice(click.Choice):
    def __init__(self, enum_type: Type[Enum], case_sensitive: bool = True):
        super().__init__(
            choices=[element.name for element in enum_type],
            case_sensitive=case_sensitive,
        )
        self.enum_type = enum_type

    def convert(
        self, value: Any, param: Optional[Parameter], ctx: Optional[Context]
    ) -> Any:
        value = super().convert(value=value, param=param, ctx=ctx)
        if value is None:
            return None
        return self.enum_type[value]
