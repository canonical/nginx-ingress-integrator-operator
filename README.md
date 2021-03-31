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

You'll need version to be using Juju [version 2.9-rc8](https://discourse.charmhub.io/t/juju-2-9-rc8-release-notes/4394/) or later.

Once https://bugs.launchpad.net/juju/+bug/1920102 has been addressed, this
charm will be able to use the credentials provided in cluster. However, for
now, you will need to provide this charm with credentials to be able to talk
to the K8s API directly. This is done via the `kube-config` config option,
which should be set to the contents of your kubernetes client configuration.
If you're using microk8s you can get this via `microk8s config`. As an example
you could deploy this charm as follows:
```
juju deploy ./ingress.charm --resource placeholder-image='google/pause' --config kube-config="$(microk8s config)"
```
To create an ingress for your service, you'd then add a relation to a charm
that supports the `ingress` relation. As an example:
```
juju deploy ./gunicorn.charm --resource gunicorn-image='gunicorncharmers/gunicorn-app:edge'
juju relate ingress gunicorn
```
This will create an K8s ingress called `gunicorn-ingress` and a K8s service
called `gunicorn-service`. The gunicorn charm in question, which can be found
https://code.launchpad.net/~mthaddon/charm-k8s-gunicorn/+git/charm-k8s-gunicorn/+ref/pebble
implements the relation as follows, as a trivial example:
```
# In __init__:
self.framework.observe(self.on['ingress'].relation_changed, self._on_ingress_changed)

# And the _on_ingress_changed method.
def _on_ingress_changed(self, event: ops.framework.EventBase) -> None:
    """Handle the ingress relation changed event."""
    if self.unit.is_leader():
        event.relation.data[self.app]["service-hostname"] = self.config["external_hostname"]
        event.relation.data[self.app]["service-name"] = self.app.name
        event.relation.data[self.app]["service-port"] = "80"
```
All of the config items in `config.yaml` with the exception of `kube-config` can
be set via the relation, e.g. `tls-secret-name` or `max-body-size`.

Alternatively, you can configure the same ingress via Juju config options, to
avoid needing to modify the charm you're deploying it alongside. As an example:
```
juju config ingress service-name=gunicorn service-port=80 service-hostname=foo.internal
```
Finally, if the charm you're relating to implements the ingress relation, you
can still override the configuration of the ingress using Juju config. Using
the above example, where your charm sets the `service-port` as "80" in the
relation, you could override this by doing the following:
```
juju deploy ./ingress.charm --resource placeholder-image='google/pause' --config kube-config="$(microk8s config)"
juju deploy ./gunicorn.charm --resource gunicorn-image='gunicorncharmers/gunicorn-app:edge'
juju relate ingress gunicorn
juju config ingress service-port=8080
```
In this case, the charm will use the `service-hostname` and `service-name` as
sent by the relation, but will use a `service-port` of 8080.

## Testing

Simply run `make test`.
