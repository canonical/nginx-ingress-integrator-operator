# Nginx Ingress Integrator

## Description

This charm is intended to provide an nginx ingress for sidecar charms using the
Operator Framework until such time as Juju can expose the relevant primitives
to enable charms to configure an ingress natively via Juju (e.g. with TLS as
required, with session affinity as required, allowing for upload of a given
size, etc.).

## Usage

You'll need version to be using Juju [version 2.9.0](https://discourse.charmhub.io/t/juju-2-9-0-release-notes/4525) or later.

As an example, you could deploy this charm as follows (we're using the name
"ingress" in this model for brevity):
```
juju deploy nginx-ingress-integrator ingress
```
To create an ingress for your service, you'd then add a relation to a charm
that supports the `ingress` relation. As an example:
```
juju deploy hello-kubecon
juju relate ingress hello-kubecon
```
This will create an K8s ingress called `hello-kubecon-ingress` and a K8s service
called `hello-kubecon-service`.

The nginx-ingress-integrator charm includes a library to make implementing the
ingress relation as easy as possible for charm authors. As a trivial example,
you can implement this relation by running `charmcraft fetch-lib charms.nginx_ingress_ingress_integrator.v0.ingress`
and then adding the following to `src/charm.py` (assuming your charm has a
config option of `external_hostname`):
```
from charms.nginx_ingress_integrator.v0.ingress import IngressRequires

# In __init__:
self.ingress = IngressRequires(self, {"service-hostname": self.config["external_hostname"],
                                      "service-name": self.app.name,
                                      "service-port": 80})

# In config-changed handler
self.ingress.update_config({"service_hostname": self.config["external_hostname"]})
```
Any charm implementing this relation will also need to add the following to
`metadata.yaml`:
```
requires:
  ingress:
    interface: ingress
```
All of the config items in `config.yaml` with the exception of `ingress-class` can
be set via the relation, e.g. `tls-secret-name` or `max-body-size`.
`ingress-class` is a run-time option used to tell Kubernetes which ingress
controller to target, in the case where your cluster has multiple ingress
controllers.

Alternatively, you can configure the same ingress via Juju config options, to
avoid needing to modify the charm you're deploying it alongside. As an example:
```
juju config ingress service-name=hello-kubecon service-port=80 service-hostname=foo.internal
```
Finally, if the charm you're relating to implements the ingress relation, you
can still override the configuration of the ingress using Juju config. Using
the above example, where your charm sets the `service-port` as "80" in the
relation, you could override this by doing the following:
```
juju deploy nginx-ingress-integrator ingress
juju deploy hello-kubecon
juju relate ingress hello-kubecon
juju config ingress service-port=8080
```
In this case, the charm will use the `service-hostname` and `service-name` as
sent by the relation, but will use a `service-port` of 8080.

## Testing

Simply run `make test`.

---

For more details, [see here](https://charmhub.io/nginx-ingress-integrator/docs).
