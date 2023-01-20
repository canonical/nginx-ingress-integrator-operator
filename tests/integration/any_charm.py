# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

"""This code snippet is used to be loaded into any-charm which is used for integration tests."""
import os
import pathlib
import signal
import subprocess

from any_charm_base import AnyCharmBase
from ingress import IngressRequires


class AnyCharm(AnyCharmBase):
    """Execute a simple web-server charm to test the ingress-proxy relation.

    Attrs:
        ingress: The attribute that mimics a real ingress relation.
    """

    def __init__(self, *args, **kwargs):
        """Init function for the class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
            kwargs: Variable list of positional keyword arguments passed to the parent constructor.
        """
        super().__init__(*args, **kwargs)
        self.ingress = IngressRequires(
            self,
            {"service-hostname": "any", "service-name": self.app.name, "service-port": 8080},
        )

    def update_ingress(self, ingress_config):
        """Update Ingress config.

        Args:
            ingress_config: New Ingress configuration to be applied.
        """
        self.ingress.update_config(ingress_config)

    @staticmethod
    def start_server(port: int = 8080):
        """Start an HTTP server daemon.

        Args:
            port: The port where the server is connected.

        Returns:
            The port where the server is connected.
        """
        www_dir = pathlib.Path("/tmp/www")
        www_dir.mkdir(exist_ok=True)
        ok_file = www_dir / "ok"
        ok_file.write_text("ok")
        # We create a pid file to avoid concurrent executions of the http server
        pid_file = pathlib.Path("/tmp/any.pid")
        if pid_file.exists():
            os.kill(int(pid_file.read_text()), signal.SIGKILL)
            pid_file.unlink()
        p = subprocess.Popen(
            ["python3", "-m", "http.server", "-d", www_dir, str(port)],
            start_new_session=True,
        )
        pid_file.write_text(str(p.pid))
        return port
