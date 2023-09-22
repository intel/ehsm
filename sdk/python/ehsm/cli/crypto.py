import click

from ehsm.api import Client
from ehsm.api.enums import *
from ehsm.cli import options
from ehsm.cli.base import ehsm_cli, with_client
from ehsm.cli.utils import with_credential_missing_handler, EnumChoice


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyspec()
@options.origin()
@options.keyusage()
def create_key(client: Client, keyspec: KeySpec, origin: Origin, keyusage: KeyUsage):
    resp = client.create_key(keyspec, origin, keyusage).result
    click.echo(f"key id\t{resp.keyid}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@options.plaintext()
def encrypt(client: Client, aad: str, keyid: str, plaintext: str):
    resp = client.encrypt(aad, keyid, plaintext).result
    click.echo("Ciphertext")
    click.echo("=" * 30)
    click.echo(resp.ciphertext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@options.ciphertext()
def decrypt(client: Client, aad: str, keyid: str, ciphertext: str):
    resp = client.decrypt(aad, keyid, ciphertext).result
    click.echo("Plaintext")
    click.echo("=" * 30)
    click.echo(resp.plaintext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.plaintext()
@options.padding_mode()
def asymm_encrypt(
    client: Client, keyid: str, plaintext: str, padding_mode: PaddingMode
):
    resp = client.asymm_encrypt(keyid, plaintext, padding_mode).result
    click.echo("Ciphertext")
    click.echo("=" * 30)
    click.echo(resp.ciphertext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.ciphertext()
@options.padding_mode()
def asymm_decrypt(
    client: Client, keyid: str, ciphertext: str, padding_mode: PaddingMode
):
    resp = client.asymm_decrypt(keyid, ciphertext, padding_mode).result
    click.echo("Plaintext")
    click.echo("=" * 30)
    click.echo(resp.plaintext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.padding_mode()
@options.digest_mode()
@options.message_type()
@options.plaintext("--message", help="A base64 string to be sign")
def sign(
    client: Client,
    keyid: str,
    padding_mode: PaddingMode,
    digest_mode: DigestMode,
    message_type: MessageType,
    message: str,
):
    resp = client.sign(keyid, padding_mode, digest_mode, message_type, message).result
    click.echo("Signature")
    click.echo("=" * 30)
    click.echo(resp.signature)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.padding_mode()
@options.digest_mode()
@options.message_type()
@options.ciphertext("--message", help="A base64 string to be verified")
def verify(
    client: Client,
    keyid: str,
    padding_mode: PaddingMode,
    digest_mode: DigestMode,
    message_type: MessageType,
    message: str,
):
    resp = client.verify(keyid, padding_mode, digest_mode, message_type, message).result
    click.echo(f"Result:\t{resp.result}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@options.keylen()
def generate_data_key(client: Client, aad: str, keyid: str, keylen: int):
    resp = client.generate_data_key(aad, keyid, keylen).result
    click.echo(f"Plaintext:")
    click.echo("=" * 30)
    click.echo(resp.plaintext)
    click.echo("=" * 30)
    click.echo(f"Ciphertext:")
    click.echo("=" * 30)
    click.echo(resp.ciphertext)
    click.echo("=" * 30)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@options.keylen()
def generate_data_key_without_plaintext(
    client: Client, aad: str, keyid: str, keylen: int
):
    resp = client.generate_data_key_without_plaintext(aad, keyid, keylen).result
    click.echo(f"Ciphertext:")
    click.echo("=" * 30)
    click.echo(resp.ciphertext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@click.option(
    "--old-data-key",
    type=str,
    required=True,
    help="The ciphertext of the datakey wrapped by the cmk in BASE64 string",
)
@options.keyid(
    "--ukeyid", help="The unique keyid of the asymmetric CMK which used to export"
)
@options.padding_mode()
def export_data_key(client: Client, aad:str, keyid: str, old_data_key: str, ukeyid: str, padding_mode: PaddingMode):
    resp = client.export_data_key(aad, keyid, old_data_key, keyid, padding_mode).result
    click.echo('New Data Key')
    click.echo('=' * 30)
    click.echo(resp.newdatakey)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
def get_public_key(client: Client, keyid: str):
    resp = client.get_public_key(keyid).result
    click.echo('New Data Key')
    click.echo('=' * 30)
    click.echo(resp.pubkey)
