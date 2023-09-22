from functools import partial
import click

# Key Management Options

option_keyid = partial(click.option, type=str, required=True, help='A unique keyid of the cmk')

# Crypto