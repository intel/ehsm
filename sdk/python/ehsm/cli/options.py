from functools import partial
import click

from ehsm.api.enums import *
from ehsm.cli.utils import EnumChoice

# Key Management Options

keyid = partial(
    click.option, "--keyid", type=str, required=True, help="A unique keyid of the cmk"
)
keylen = partial(
    click.option,
    "--keylen",
    type=int,
    required=True,
    help="Specifies the length of the plaintext, length is 0~1024 bytes.",
)

# Crypto

keyspec = partial(
    click.option,
    "--keyspec",
    type=EnumChoice(KeySpec),
    required=True,
    help="The keyspec the user want to create, EH_HMAC is not supported at present, and will be supported later",
)

origin = partial(
    click.option,
    "--origin",
    type=EnumChoice(Origin),
    required=True,
    help="The source about the cmk comes from, currently it only support the type of EH_INTERNAL_KEY",
)

keyusage = partial(
    click.option,
    "--keyusage",
    type=EnumChoice(KeyUsage),
    required=True,
    help="Record the usage range of the cmk",
)

padding_mode = partial(
    click.option,
    "--padding-mode",
    type=EnumChoice(PaddingMode),
    required=True,
    help="The padding mode",
)

digest_mode = partial(
    click.option,
    "--digest-mode",
    type=EnumChoice(DigestMode),
    required=True,
    help="The digest mode",
)

message_type = partial(
    click.option,
    "--message-type",
    type=EnumChoice(MessageType),
    required=True,
    help="The message type",
)

aad = partial(
    click.option,
    "--aad",
    type=str,
    default="",
    help="A base64 string indicates some extra datas input by the user, which could help to to ensure data integrity, and not be included in the cipherblobs",
)

plaintext = partial(
    click.option,
    "--plaintext",
    "--data",
    type=str,
    required=True,
    help="The datas of the plaintext which in based64 encoding",
)

ciphertext = partial(
    click.option,
    "--ciphertext",
    "--data",
    type=str,
    required=True,
    help="The datas of the ciphertext which in based64 encoding",
)

# Secret Management

secret_name = partial(
    click.option,
    "--secret-name",
    type=str,
    required=True,
    help="The name of the secret",
)

secret_data = partial(
    click.option,
    "--secret-data",
    type=str,
    required=True,
    help="Stores the secret value of a new version into a secret object",
)

description = partial(
    click.option,
    "--description",
    "--desc",
    type=str,
    help="Description of the secret",
)

encryption_key_id = partial(
    click.option,
    "--encryption-key-id",
    "--encryption-keyid",
    type=str,
    help="The ID of the CMK that is used to encrypt the secret value",
)

rotation_interval = partial(
    click.option,
    "--rotation-interval",
    type=str,
    help="The interval for automatic rotation. format: integer[unit], unit can be d (day), h (hour), m (minute), or s (second), default=30d",
)

version_id = partial(
    click.option,
    "--version-id",
    type=int,
    help="The version number of the secret value",
)

recovery_period = partial(
    click.option,
    "--recovery-period",
    type=int,
    default=30,
    help="The recovery period of the secret, if you do not forcibly delete it, the unit is day",
)

force_delete = partial(
    click.option,
    "--force-delete",
    is_flag=True,
    help="Whether to forcibly delete the secret. If this parameter is specified, the secret cannot be recovered",
)
