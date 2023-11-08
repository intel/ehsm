import click

from ehsm.api import Client
from ehsm.cli.base import ehsm_cli, with_client
from ehsm.cli.utils import with_credential_missing_handler


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@click.option(
    "--challenge", type=str, required=True, help="A challenge in BASE64 string"
)
def generate_quote(client: Client, challenge: str):
    quote = client.generate_quote(challenge)
    click.echo(f"challenge\t{quote.challenge}")
    click.echo(f"quote\t{quote.quote}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@click.option(
    "--quote", type=str, required=True, help="A valid DCAP quote in BASE64 string"
)
@click.option(
    "--nonce", type=str, required=True, help="A nonce in random string (<64B)"
)
@click.option("--policy-id", type=str, required=True, help="quote policy ID")
def verify_quote(client: Client, quote: str, nonce: str, policy_id: str):
    result = client.verify_quote(quote, nonce, policy_id)
    click.echo(f"result\t{result.result}")
    click.echo(f"nonce\t{result.nonce}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@click.option(
    "--mr-enclave",
    type=str,
    required=True,
    help="stores the hash value of the enclave measurement",
)
@click.option(
    "--mr-signer",
    type=str,
    required=True,
    help="stores the hash value of the enclave author’s public key",
)
def upload_quote_policy(client: Client, mr_enclave: str, mr_signer: str):
    policy_id = client.upload_quote_policy(mr_enclave, mr_signer)
    click.echo(f"policy_id\t{policy_id}")


@ehsm_cli.command()
@with_client
@with_credential_missing_handler
@click.option("--policy-id", type=str, required=True, help="a policy ID")
def get_quote_policy(client: Client, policy_id: str):
    policy = client.get_quote_policy(policy_id)
    click.echo(f"policy_id\t{policy.policy_id}")
    click.echo(f"mr_enclave\t{policy.mr_enclave}")
    click.echo(f"mr_signer\t{policy.mr_signer}")
