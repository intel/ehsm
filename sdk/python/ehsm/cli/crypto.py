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
    result = client.create_key(keyspec, origin, keyusage)
    click.echo(f"key id\t{result.keyid}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@options.plaintext()
def encrypt(client: Client, aad: str, keyid: str, plaintext: str):
    result = client.encrypt(aad, keyid, plaintext)
    click.echo("Ciphertext")
    click.echo("=" * 30)
    click.echo(result.ciphertext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@options.ciphertext()
def decrypt(client: Client, aad: str, keyid: str, ciphertext: str):
    result = client.decrypt(aad, keyid, ciphertext)
    click.echo("Plaintext")
    click.echo("=" * 30)
    click.echo(result.plaintext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.plaintext()
@options.padding_mode()
def asymm_encrypt(
    client: Client, keyid: str, plaintext: str, padding_mode: PaddingMode
):
    result = client.asymm_encrypt(keyid, plaintext, padding_mode)
    click.echo("Ciphertext")
    click.echo("=" * 30)
    click.echo(result.ciphertext)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.ciphertext()
@options.padding_mode()
def asymm_decrypt(
    client: Client, keyid: str, ciphertext: str, padding_mode: PaddingMode
):
    result = client.asymm_decrypt(keyid, ciphertext, padding_mode)
    click.echo("Plaintext")
    click.echo("=" * 30)
    click.echo(result.plaintext)


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
    result = client.sign(keyid, padding_mode, digest_mode, message_type, message)
    click.echo("Signature")
    click.echo("=" * 30)
    click.echo(result.signature)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.padding_mode()
@options.digest_mode()
@options.message_type()
@options.signature()
@options.ciphertext("--message", help="A base64 string to be verified")
def verify(
    client: Client,
    keyid: str,
    padding_mode: PaddingMode,
    digest_mode: DigestMode,
    message_type: MessageType,
    message: str,
    signature: str,
):
    result = client.verify(
        keyid, padding_mode, digest_mode, message_type, message, signature
    )
    click.echo(f"Result:\t{result.result}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.aad()
@options.keyid()
@options.keylen()
def generate_data_key(client: Client, aad: str, keyid: str, keylen: int):
    result = client.generate_data_key(aad, keyid, keylen)
    click.echo(f"Plaintext:")
    click.echo("=" * 30)
    click.echo(result.plaintext)
    click.echo("=" * 30)
    click.echo(f"Ciphertext:")
    click.echo("=" * 30)
    click.echo(result.ciphertext)
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
    result = client.generate_data_key_without_plaintext(aad, keyid, keylen)
    click.echo(f"Ciphertext:")
    click.echo("=" * 30)
    click.echo(result.ciphertext)


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
def export_data_key(
    client: Client,
    aad: str,
    keyid: str,
    old_data_key: str,
    ukeyid: str,
    padding_mode: PaddingMode,
):
    result = client.export_data_key(aad, keyid, old_data_key, ukeyid, padding_mode)
    click.echo("New Data Key")
    click.echo("=" * 30)
    click.echo(result.newdatakey)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
def get_public_key(client: Client, keyid: str):
    result = client.get_public_key(keyid)
    click.echo("New Data Key")
    click.echo("=" * 30)
    click.echo(result.pubkey)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.key_material()
@options.padding_mode()
@options.importToken()
def import_key_material(
    client: Client,
    keyid: str,
    key_material: str,
    padding_mode: PaddingMode,
    importToken: str,
):
    result = client.import_key_material(keyid, key_material, padding_mode, importToken)
    click.echo("Import Result")
    click.echo("=" * 30)
    click.echo(result)


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@options.keyid()
@options.keyspec()
def get_parameters_for_import(client: Client, keyid: str, keyspec: KeySpec):
    result = client.get_parameters_for_import(keyid, keyspec)
    click.echo("pubkey")
    click.echo("=" * 30)
    click.echo(result.pubkey)
    click.echo("=" * 30)
    click.echo("importToken")
    click.echo("=" * 30)
    click.echo(result.importToken)
