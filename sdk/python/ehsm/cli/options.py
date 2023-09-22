from functools import partial
import click

from ehsm.api.enums import *
from ehsm.cli.utils import EnumChoice

# Key Management Options

keyid = partial(click.option, '--keyid', type=str, required=True, help="A unique keyid of the cmk")
keylen = partial(click.option, '--keylen', type=int, required=True, help="Specifies the length of the plaintext, length is 0~1024 bytes.")

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
    '--padding-mode',
    type=EnumChoice(PaddingMode),
    required=True,
    help='The padding mode',
)

digest_mode = partial(
    click.option,
    '--digest-mode',
    type=EnumChoice(DigestMode),
    required=True,
    help='The digest mode',
)

message_type = partial(
    click.option,
    '--message-type',
    type=EnumChoice(MessageType),
    required=True,
    help='The message type'
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
    '--plaintext',
    '--data',
    type=str,
    required=True,
    help='The datas of the plaintext which in based64 encoding'
)

ciphertext = partial(
    click.option,
    '--ciphertext',
    '--data',
    type=str,
    required=True,
    help='The datas of the ciphertext which in based64 encoding'
)
