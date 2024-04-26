# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Integration test for ingress relation."""

import asyncio
import json
import pathlib
import textwrap

import requests
from juju.model import Model


async def test_ingress_relation(
    model: Model, deploy_any_charm, run_action, build_and_deploy_ingress
):
    """
    assert: None
    action: Build and deploy nginx-ingress-integrator charm, also deploy and relate an any-charm
        application with ingress relation for test purposes.
    assert: HTTP request should be forwarded to the application.
    """
    any_charm_py = textwrap.dedent(
        f"""\
    import pathlib
    import subprocess
    from any_charm_base import AnyCharmBase
    from ingress import IngressPerAppRequirer
    class AnyCharm(AnyCharmBase):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            self.ingress = IngressPerAppRequirer(self, port=8080)
        def start_server(self):
            www_dir = pathlib.Path("/tmp/www")
            www_dir.mkdir(exist_ok=True)
            file_path = www_dir / "{model.name}-any" / "ok"
            file_path.parent.mkdir(exist_ok=True)
            # if self.ingress.relation is not None:
            #     file_path.write_text(self.ingress.relation.data.get("ingress"))
            # else:
            #     file_path.write_text("error")

            # for all keys in the relation data, write them to a file
            for key, value in self.ingress.relation.data.items():
                # file_path.write_text(""+str(key))
                if value is not None:
                    file_path.write_text("(key: "+str(key)+", value: "+str(value)+")")
            


            proc_http = subprocess.Popen(
                ["python3", "-m", "http.server", "-d", www_dir, "8080"],
                start_new_session=True,
            )
    """
    )

    src_overwrite = {
        "ingress.py": pathlib.Path("lib/charms/traefik_k8s/v2/ingress.py").read_text(
            encoding="utf-8"
        ),
        "any_charm.py": any_charm_py,
    }

    _, ingress = await asyncio.gather(
        deploy_any_charm(json.dumps(src_overwrite)),
        build_and_deploy_ingress(),
    )
    await ingress.set_config({"service-hostname": "any"})
    await model.wait_for_idle()
    await model.add_relation("any:ingress", "ingress:ingress")
    await model.wait_for_idle()
    await run_action("any", "rpc", method="start_server")

    response = requests.get(
        f"http://127.0.0.1/{model.name}-any/ok", headers={"Host": "any"}, timeout=5
    )
    assert response.text == "any"
    assert response.status_code == 200
