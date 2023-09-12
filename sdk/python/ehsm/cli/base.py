import click

from ehsm.api import Client

with_client = click.make_pass_decorator(Client)


@click.group()
@click.option(
    "--url",
    type=str,
    envvar="EHSM_SERVER_URL",
    required=True,
    help="URL of EHSM web service",
)
@click.option(
    "--appid",
    envvar="EHSM_APPID",
    type=str,
    default="",
    help="Identifier of an user, can be acquired from `ehsm enroll` command",
)
@click.option(
    "--apikey",
    envvar="EHSM_APIKEY",
    type=str,
    default="",
    help="Secret key of an user, can be acquired from `ehsm enroll` command",
)
@click.option(
    "--insecure",
    envvar="EHSM_INSECURE",
    type=bool,
    is_flag=True,
    help="Certification verification will be skipped if this option is specified",
)
@click.pass_context
def ehsm_cli(ctx, url, appid, apikey, insecure):
    """EHSM cli is command line interface for EHSM KMS Service RESTful API."""
    ctx.obj = Client(url, appid=appid, apikey=apikey, allow_insecure=insecure)
