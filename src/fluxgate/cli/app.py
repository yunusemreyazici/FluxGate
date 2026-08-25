"""FluxGate command-line assembly."""

import logging
from typing import Annotated

import typer

from fluxgate.cli.client import client_app
from fluxgate.cli.config import config_app
from fluxgate.cli.core import core_app
from fluxgate.cli.doctor import doctor_command
from fluxgate.cli.profile import profile_app
from fluxgate.cli.status import status_command, version_command
from fluxgate.cli.system import system_app

app = typer.Typer(help="Modular multi-transport connectivity server manager.", no_args_is_help=True)
app.add_typer(core_app, name="core")
app.add_typer(client_app, name="client")
app.add_typer(profile_app, name="profile")
app.add_typer(config_app, name="config")
app.add_typer(system_app, name="system")
app.command("version")(version_command)
app.command("status")(status_command)
app.command("doctor")(doctor_command)


@app.callback()
def main(
    verbose: Annotated[int, typer.Option("-v", count=True, help="Increase log verbosity.")] = 0,
) -> None:
    level = logging.WARNING if verbose == 0 else logging.INFO if verbose == 1 else logging.DEBUG
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")


if __name__ == "__main__":
    app()
