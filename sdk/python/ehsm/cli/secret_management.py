import click
from typing import Optional

from ehsm.api import Client
from ehsm.cli import options
from ehsm.cli.base import ehsm_cli, with_client
from ehsm.cli.utils import with_credential_missing_handler


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
@options.secret_data()
@options.encryption_key_id()
@options.description()
@options.rotation_interval()
def creaet_secret(
    client: Client,
    secret_name: str,
    secret_data: str,
    encryption_key_id: Optional[str],
    description: Optional[str],
    rotation_interval: Optional[str],
):
    resp = client.create_secret(
        secret_name,
        secret_data,
        encryption_key_id,
        description,
        rotation_interval,
    )
    click.echo(resp.response.message)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
@options.description()
def update_secret_description(
    client: Client, secret_name: str, description: Optional[str]
):
    resp = client.update_secret_description(secret_name, description)
    click.echo(resp.response.message)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
@options.secret_data()
def put_secret_value(client: Client, secret_name: str, secret_data: str):
    resp = client.put_secret_value(secret_name, secret_data)
    click.echo(resp.response.message)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
def list_secret_version_id(client: Client, secret_name: str):
    resp = client.list_secret_version_ids(secret_name)
    click.echo(f"secret name\t{resp.secret_name}")
    click.echo(f"total count\t{resp.total_count}")
    click.echo("-" * 30)
    click.echo("version id \t create time")
    for version in resp.version_ids:
        click.echo(f"{version.version_id} \t {version.create_time}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name(required=False)
def list_secrets(client: Client, secret_name: Optional[str]):
    resp = client.list_secrets(secret_name)
    click.echo(f"total count\t{resp.total_count}")
    click.echo("-" * 30)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
def describe_secret(client: Client, secret_name: str):
    resp = client.describe_secret(secret_name)
    click.echo(f"secret name\t{resp.secret_name}")
    click.echo(f"description\t{resp.description}")
    click.echo(f"create time\t{resp.create_time}")
    click.echo(f"planned delete time\t{resp.planned_delete_time}")
    click.echo(f"rational interval\t{resp.rational_interval}")
    click.echo(f"last rotation date\t{resp.last_rotation_date}")
    click.echo(f"next rotation date\t{resp.next_rotation_date}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
@options.recovery_period()
@options.force_delete()
def delete_secret(
    client: Client,
    secret_name: str,
    recovery_period: Optional[int],
    force_delete: Optional[bool],
):
    resp = client.delete_secret(secret_name, recovery_period, force_delete)
    click.echo(resp.response.message)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
@options.version_id()
def get_secret_value(client: Client, secret_name: str, version_id: Optional[int]):
    resp = client.get_secret_value(secret_name, version_id)
    click.echo(f"secret name\t{resp.secret_name}")
    click.echo(f"secret data\t{resp.secret_data}")
    click.echo(f"version id\t{resp.version_id}")
    click.echo(f"create time\t{resp.create_time}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.secret_name()
def restore_secret(client: Client, secret_name: str):
    resp = client.restore_secret(secret_name)
    click.echo(resp.response.message)
