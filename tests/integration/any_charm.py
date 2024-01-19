# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=import-error,consider-using-with

"""This code snippet is used to be loaded into any-charm which is used for integration tests."""
import os
import pathlib
import signal
import subprocess
from typing import Dict

from any_charm_base import AnyCharmBase
from ingress import IngressRequires

INGRESS_CONFIG_ENVVAR = "ANYCHARM_INGRESS_CONFIG"
SVC_HOSTNAME = "service-hostname"
SVC_NAME = "service-name"
SVC_PORT = "service-port"


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
            self.ingress_config(),
        )

    def update_ingress(self, ingress_config):
        """Update Ingress config.

        Args:
            ingress_config: New Ingress configuration to be applied.
        """
        self.ingress.update_config(ingress_config)

    def update_nginx_route(self, nginx_route_config):
        """Update Ingress config.

        Args:
            nginx_route_config: New Ingress configuration to be applied.
        """
        self.nginx_route.update_config(nginx_route_config)

    def _has_required_fields(self, rel: Dict) -> bool:
        """Check for required fields in relation.

        Args:
            rel: relation to check

        Returns:
            Returns true if all fields exist
        """
        return all(key in rel for key in (SVC_HOSTNAME, SVC_NAME, SVC_PORT))

    def _has_app_data(self) -> bool:
        """Check for app in relation data.

        Returns:
            Returns true if app data exist
        """
        return self.app in self.model.relations["ingress"][0].data

    def _has_ingress_relation(self) -> bool:
        """Check for ingress relation.

        Returns:
            Returns true if ingress relation exist
        """
        return "ingress" in self.model.relations and len(self.model.relations["ingress"]) > 0

    def ingress_config(self) -> Dict:
        """Get ingress config from relation or default.

        Returns:
            The ingress config to be used
        """
        if self._has_ingress_relation() and self._has_app_data():
            rel = self.model.relations["ingress"][0].data[self.app]
            if self._has_required_fields(rel):
                return {
                    SVC_HOSTNAME: rel[SVC_HOSTNAME],
                    SVC_NAME: rel[SVC_NAME],
                    SVC_PORT: rel[SVC_PORT],
                }
        return {SVC_HOSTNAME: "any", SVC_NAME: self.app.name, SVC_PORT: 8080}

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
            os.kill(int(pid_file.read_text(encoding="utf8")), signal.SIGKILL)
            pid_file.unlink()
        proc_http = subprocess.Popen(
            ["python3", "-m", "http.server", "-d", www_dir, str(port)],
            start_new_session=True,
        )
        pid_file.write_text(str(proc_http.pid), encoding="utf8")
        return port
