import asyncio
import json
import textwrap

import juju.model
import pytest_asyncio
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
            file_path.write_text("ok")
            proc_http = subprocess.Popen(
                ["python3", "-m", "http.server", "-d", www_dir, "8080"],
                start_new_session=True,
            )
    """
    )

    src_overwrite = {
        "ingress.py": open("tests/integration/lib/ingress").read(),
        "any_charm.py": any_charm_py,
    }

    _, ingress = await asyncio.gather(
        deploy_any_charm(json.dumps(src_overwrite)),
        build_and_deploy_ingress(),
    )
    await ingress.set_config({"service-hostname": "any"})
    await model.wait_for_idle()
    await run_action("any", "rpc", method="start_server")
    await model.add_relation(f"any:ingress", "ingress:ingress")
    await model.wait_for_idle()
    response = requests.get(
        f"http://127.0.0.1/{model.name}-any/ok", headers={"Host": "any"}, timeout=5
    )
    assert response.text == "ok"
    assert response.status_code == 200
