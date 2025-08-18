# How to add the Nginx-route relation

The `nginx-route` relation is preferred over the `ingress` relation if you want to use nginx-specific features, such as owasp-modsecurity-crs. If you need
something more generic then please follow the [ingress relation](https://charmhub.io/nginx-ingress-integrator/docs/add-the-ingress-relation) tutorial instead.

## Add the `nginx-route` relation to your charm code

First download the [`nginx-route` charm library](https://charmhub.io/nginx-ingress-integrator/libraries/nginx_route)
by running:

```
charmcraft fetch-lib charms.nginx_ingress_integrator.v0.nginx_route
```

The nginx-route charm library is downloaded to `lib/charms/nginx_ingress_integrator/v0/nginx_route.py`.

Next update `src/charm.py` by importing `require_nginx_route` from the 
nginx-route charm library.

```
from charms.nginx_ingress_integrator.v0.nginx_route import require_nginx_route
```

Then add the following to the end of your charm's `__init__` method:

```
require_nginx_route(
    charm=self,
    service_hostname=self.config["external-hostname"] or self.app.name,
    service_name=self.app.name,
    service_port=8080 # assuming your app listens in port 8080
)
```

## Update your charm metadata

In this above example, a new configuration option of `external-hostname`
was used to configure ingress. Update `config.yaml` to add this
configuration option.

```
  external-hostname:
    description: |
      The external hostname to use. Will default to the name of the deployed
      application.
    default: ""
    type: string
```

Now add the relation definition to `metadata.yaml`. Add the following to the end of that file:

```
requires:
  nginx-route:
    interface: nginx-route
```

## Verify the relation

Rebuild your charm and run a charm upgrade.

```
charmcraft pack
juju refresh my-charm --path=./my-charm_ubuntu-22.04-amd64.charm
```

Now deploy the Nginx Ingress Integrator and relate to your 
charm using the `nginx-route` relation:

```
juju deploy nginx-ingress-integrator --trust
juju relate nginx-ingress-integrator my-charm:nginx-route
```
