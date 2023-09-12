from typing import Callable
import click
import functools

from ehsm.exceptions import CredentialMissingException


def with_credential_missing_handler(func):
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        try:
            func(*args, **kwargs)
        except CredentialMissingException:
            click.echo(
                "Credentials needed, please specified --appid and --apikey", err=True
            )

    return wrapper
