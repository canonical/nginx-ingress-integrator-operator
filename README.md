# Nginx Ingress Integrator Operator

A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators) deploying and managing external access to HTTP/HTTPS services in a
Kubernetes cluster via an Nginx Ingress resource. This charm requires the Kubernetes cluster in question to have an
[Nginx Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) already deployed into it. The Nginx Integrator
Operator is a workload-less charm that allows other charms to configure an Nginx Ingress resource.

This charm simplifies exposing services running inside a Kubernetes cluster to
external clients. It offers TLS termination as well as easy configuration of a
number of advanced features including rate limiting, restricting access to
specific client IP source ranges, and OWASP ModSecurity Core Rule Set (CRS).

As such, the charm makes it easy for charm developers to provide external
access to their HTTP workloads in Kubernetes by easy integration offered via
[the charm's ingress library](https://charmhub.io/nginx-ingress-integrator/libraries/ingress).

For DevOps and SRE teams, providing ingress for charms that support a relation
to this charm will be possible via a simple `juju relate` command.

## Get started

Refer to the [tutorial](https://charmhub.io/nginx-ingress-integrator/docs/getting-started) for more details on getting started.

### Basic operations

#### Secure an Ingress with TLS
Refer to [How to secure an Ingress with TLS](https://charmhub.io/nginx-ingress-integrator/docs/secure-an-ingress-with-tls) for step-by-step instructions.

#### Add the Ingress relation
Refer to [How to add the Ingress relation](https://charmhub.io/nginx-ingress-integrator/docs/add-the-ingress-relation) for step-by-step instructions.


## Integrations

- [ingress](https://charmhub.io/nginx-ingress-integrator/integrations#ingress): Ingress interface that allows to
  provide an Ingress for the charms supporting this interface. Charms can get an Ingress using the `ingress` or the
  `nginx-route` interfaces. Prefer `ingress` if you want to use generic features.
- [nginx-route](https://charmhub.io/nginx-ingress-integrator/integrations#nginx-route): Ingress interface that allows to
  provide an Ingress for the charms supporting this interface. Charms can get an Ingress using the `ingress` or the
  `nginx-route` interfaces. Prefer `nginx-route` if you want to use Nginx specific features.
- [certificates](https://charmhub.io/nginx-ingress-integrator/integrations#certificates): Requires `tls-certificates`
  interface that facilitates the use of a TLS certificate.

Refer to [Integrations](https://charmhub.io/nginx-ingress-integrator/integrations/) for more information
about integrations.

## Learn more
* [Read more](https://charmhub.io/nginx-ingress-integrator)
* [Troubleshooting](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)

## Project and community
* [Issues](https://github.com/canonical/nginx-ingress-integrator-operator/issues)
* [Contributing](https://charmhub.io/nginx-ingress-integrator/docs/contribute)
* [Matrix](https://matrix.to/#/#charmhub-charmdev:ubuntu.com)
