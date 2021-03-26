# Ingress Operator

## Description

This charm is intended to provide an ingress for sidecar charms using the
Operator Framework until such time as Juju can expose the relevant primitives
to enable charms to configure an ingress natively via Juju (e.g. with TLS as
required, with session affinity as required, allowing for upload of a given
size, etc.).

## Usage

This charm needs to be built locally as charmhub.io can't yet host charms with
"bases" in `metadata.yaml`. Once that's been added, deployment instructions
will be updated, but for now, see the "Running the charm locally" section
below.

## Running the charm locally

To build the charm, run `charmcraft build`.

You'll need version 1.14 or later of Go (`go version` will confirm your current version), and a custom version of the Juju 2.9 branch, as below:

```
git clone -b 2.9 https://github.com/juju/juju
cd juju
make install
make microk8s-operator-update  # to make the microk8s image and push to Docker
export PATH="/home/${USER}/go/bin:$PATH"
juju bootstrap microk8s --no-gui
juju add-model ingress-test
```
The `kube-config` config option should be set to the contents of your
kubernetes client configuration. If you're using microk8s you can get
this via `microk8s config`, and you'd then deploy the charm as follows:
```
juju deploy ./ingress.charm --resource placeholder-image='google/pause' --config kube-config="$(microk8s config)"
```
To create an ingress for your service, you'd then add a relation to a charm
that supports the `ingress` relation. As an example:
```
juju deploy ./gunicorn.charm --resource gunicorn-image='gunicorncharmers/gunicorn-app:edge'
juju relate ingress:ingress gunicorn:ingress
```
This will create an K8s ingress called `gunicorn-ingress` and a K8s service
called `gunicorn-service`. The gunicorn charm in question implements the
relation as follows, as a trivial example:
```
# In __init__:
self.framework.observe(self.on['ingress'].relation_changed, self._on_ingress_changed)

def _on_ingress_changed(self, event: ops.framework.EventBase) -> None:
    """Handle the ingress relation changed event."""
    event.relation.data[self.unit]["service-hostname"] = self.config["external_hostname"]
    event.relation.data[self.unit]["service-name"] = self.model.name
    event.relation.data[self.unit]["service-port"] = "80"
```

Alternatively, you can configure the same ingress via Juju config options, to
avoid needing to modify the charm you're deploying it alongside. As an example:
```
juju config ingress service-name=gunicorn service-port=80 service-hostname=foo.internal
```

## Testing

Simply run `make test`.
