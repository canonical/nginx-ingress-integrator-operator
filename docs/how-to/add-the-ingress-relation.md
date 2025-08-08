# How to add ingress

The `ingress` relation is preferred over the `nginx-route` relation if you want to use generic features. If you need
something nginx-specific such as owasp-modsecurity-crs, then please follow the [nginx-route relation](https://charmhub.io/nginx-ingress-integrator/docs/add-the-nginx-route-relation) tutorial instead.

## Add the ingress to your charm code

First download the [ingress charm library](https://charmhub.io/nginx-ingress-integrator/libraries/ingress)
by running:

```
charmcraft fetch-lib charms.nginx_ingress_integrator.v0.ingress
```

The ingress charm library is downloaded to `lib/charms/nginx_ingress_integrator/v0/ingress.py`. 

Next update `src/charm.py` by importing `IngressRequires` from the 
ingress charm library.

```
# Add this just after `import logging`.
from charms.nginx_ingress_integrator.v0.ingress import IngressRequires
```

Finally, add the following to the end of your charm's `__init__` method:

```
self.ingress = IngressRequires(self, {"service-hostname": self.config["external-hostname"] or self.app.name,
                                      "service-name": self.app.name,
                                      "service-port": 80})
self.ingress.update_config({"service-hostname": self.config["external-hostname"] or self.app.name})
```

## Update your charm metadata for ingress relation

In this above example, a new configuration option of `external-hostname`
was used to configuring ingress. Let's update `config.yaml` to add this
configuration option.

```
  external-hostname:
    description: |
      The external hostname to use. Will default to the name of the deployed
      application.
    default: ""
    type: string
```

Now we just need to add the relation definition to `metadata.yaml`. Add the following to the end of that file:

```
requires:
  ingress:
    interface: ingress
```

## Verify the ingress relation

Rebuild your charm and run a charm upgrade.

```
charmcraft pack
juju refresh my-charm --path=./my-charm_ubuntu-22.04-amd64.charm
```

And now we can deploy the Nginx Ingress Integrator and relate to your 
charm using ingress relation:

```
juju deploy nginx-ingress-integrator --trust
juju relate nginx-ingress-integrator my-charm
```
