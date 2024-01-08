import click

from ehsm.api import Client
from ehsm.cli import options
from ehsm.cli.base import ehsm_cli, with_client
from ehsm.cli.utils import with_credential_missing_handler


__all__ = [
    "get_version",
    "enroll",
    "list_key",
    "delete_key",
    "delete_all_key",
    "enable_key",
    "disable_key",
]


@ehsm_cli.command()
@with_client
def get_version(client: Client):
    version = client.get_version()
    click.echo(f"Git SHA: \t{version.git_sha}")
    click.echo(f"Version: \t{version.version}")


@ehsm_cli.command()
@with_client
def enroll(client: Client):
    appid, apikey = client.enroll()
    click.echo(f"App ID: \t{appid}")
    click.echo(f"API key:\t{apikey}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
def list_key(client: Client):
    keys = client.list_key().list
    if len(keys) == 0:
        click.echo("No keys found.")
        return
    # echo keys
    click.echo(f"Found {len(keys)}")
    click.echo("=" * 30)
    for key, index in enumerate(keys):
        click.echo(f"{index}\t{key}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid(help="ID of the CMK you want to delete")
def delete_key(client: Client, keyid: str):
    resp = client.delete_key(keyid)
    click.echo(resp.response.message)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
def delete_all_key(client: Client):
    resp = client.delete_all_key()
    click.echo(resp.response.message)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
def enable_key(client: Client, keyid: str):
    resp = client.enable_key(keyid)
    click.echo(resp.response.message)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
def disable_key(client: Client, keyid: str):
    resp = client.disable_key(keyid)
    click.echo(resp.response.message)
