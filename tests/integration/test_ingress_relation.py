# Copyright 2025 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for ingress relation."""

import asyncio
import json
import pathlib
import textwrap

import pytest
import requests
from juju.model import Model


def make_any_charm_source(strip_prefix: bool = False) -> str:
    """Generate the source code for the any-charm with ingress relation.

    Args:
        strip_prefix: Whether to strip the prefix from the URL path.

    Return:
        str: The source code of the any-charm.
    """
    file_path_expr = 'www_dir / "testing-any" / "ok"' if not strip_prefix else 'www_dir / "ok"'

    return textwrap.dedent(
        f"""\
        import pathlib
        import subprocess
        import os
        import signal
        import ops
        from any_charm_base import AnyCharmBase
        from ingress import IngressPerAppRequirer

        class AnyCharm(AnyCharmBase):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, **kwargs)
                self.ingress = IngressPerAppRequirer(self, port=8080, strip_prefix={strip_prefix})
                self.framework.observe(
                    self.on.ingress_relation_changed, self._on_ingress_relation_changed
                )

            def start_server(self):
                www_dir = pathlib.Path("/tmp/www")
                www_dir.mkdir(exist_ok=True)

                file_path = {file_path_expr}
                file_path.parent.mkdir(exist_ok=True)
                file_path.write_text(str(self.ingress.url))

                pid_file = pathlib.Path("/tmp/any.pid")
                if pid_file.exists():
                    try:
                        os.kill(int(pid_file.read_text(encoding="utf8")), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    pid_file.unlink()

                proc_http = subprocess.Popen(
                    ["python3", "-m", "http.server", "-d", www_dir, "8080"],
                    start_new_session=True,
                )
                pid_file.write_text(str(proc_http.pid), encoding="utf8")

            def _on_ingress_relation_changed(self, event):
                self.unit.status = ops.ActiveStatus()
        """
    )


@pytest.mark.parametrize("strip_prefix", [False, True])
async def test_ingress_relation(
    model: Model, deploy_any_charm, run_action, build_and_deploy_ingress, strip_prefix: bool
):
    """Test the ingress relation with both strip_prefix settings.

    Deploy ingress and any-charm, run HTTP test, and clean up.
    """
    src_overwrite = {
        "ingress.py": pathlib.Path("lib/charms/traefik_k8s/v2/ingress.py").read_text(
            encoding="utf-8"
        ),
        "any_charm.py": make_any_charm_source(strip_prefix=strip_prefix),
    }

    _, ingress = await asyncio.gather(
        deploy_any_charm(json.dumps(src_overwrite)),
        build_and_deploy_ingress(),
    )

    await ingress.set_config({"service-hostname": "any"})
    await model.wait_for_idle()
    await model.add_relation("any:ingress", "ingress:ingress")
    await model.wait_for_idle(status="active")

    await run_action("any", "rpc", method="start_server")

    response = requests.get(
        f"http://127.0.0.1/{model.name}-any/ok", headers={"Host": "any"}, timeout=5
    )

    expected_text = (
        f"http://any/{model.name}-any"
        if not strip_prefix
        else f"http://any/{model.name}-any(/|$)(.*)"
    )
    assert response.status_code == 200
    assert response.text == expected_text

    await model.remove_application("any")
    await model.remove_application("ingress")
    await model.block_until(
        lambda: "any" not in model.applications and "ingress" not in model.applications
    )
