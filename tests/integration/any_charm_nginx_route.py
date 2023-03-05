# Copyright 2023 Canonical Ltd.
# See LICENSE file for licensing details.

# pylint: disable=import-error,consider-using-with,duplicate-code

"""This code snippet is used to be loaded into any-charm which is used for integration tests."""
import json
import os
import pathlib
import signal
import subprocess
from typing import Dict

from any_charm_base import AnyCharmBase  # type: ignore[import]
from nginx_route import require_nginx_route  # type: ignore[import]


class AnyCharm(AnyCharmBase):
    """Execute a simple web-server charm to test the nginx-route relation."""

    def __init__(self, *args, **kwargs):
        """Init function for the class.

        Args:
            args: Variable list of positional arguments passed to the parent constructor.
            kwargs: Variable list of positional keyword arguments passed to the parent constructor.
        """
        super().__init__(*args, **kwargs)
        require_nginx_route(
            charm=self,
            **self.nginx_route_config()
        )

    @staticmethod
    def nginx_route_config() -> Dict:
        """Get the nginx-route configuration from a JSON file on disk.

        Returns:
            The nginx-route config to be used
        """
        src_path = pathlib.Path(os.path.abspath(os.path.split(__file__)[0]))
        return json.loads((src_path / "nginx_route_config.json").read_text(encoding="utf-8"))

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
        log_file_object = pathlib.Path("/tmp/any.log").open("wb+")
        proc_http = subprocess.Popen(
            ["python3", "-m", "http.server", "-d", www_dir, str(port)],
            start_new_session=True,
            stdout=log_file_object,
            stderr=log_file_object,
        )
        pid_file.write_text(str(proc_http.pid), encoding="utf8")
        return port
