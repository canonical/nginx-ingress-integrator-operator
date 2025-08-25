A [Juju](https://juju.is/) [charm](https://documentation.ubuntu.com/juju/3.6/reference/charm/) deploying and managing external access to HTTP/HTTPS services in a Kubernetes cluster via an Nginx Ingress resource. This requires the Kubernetes cluster in question to have an [Nginx Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) already deployed into it.

This charm simplifies exposing services running inside a Kubernetes cluster to external clients. It offers TLS termination as well as easy configuration of a number of advanced features including rate limiting, restricting access to specific client IP source ranges, and OWASP ModSecurity Core Rule Set (CRS).

As such, the charm makes it easy for charm developers to provide external access to their HTTP workloads in Kubernetes by easy integration offered via [the charm's `nginx_route` library](https://charmhub.io/nginx-ingress-integrator/libraries/nginx_route).

For DevOps and SRE teams, providing ingress for charms that support a relation to this charm will be possible via a simple `juju relate` command.

## Contributing to this documentation

Documentation is an important part of this project, and we take the same open-source approach to the documentation as the code. As such, we welcome community contributions, suggestions and constructive feedback on our documentation. Our documentation is hosted on the [Charmhub forum](https://discourse.charmhub.io/t/nginx-ingress-integrator-docs-index/4511) to enable easy collaboration. Please use the "Help us improve this documentation" links on each documentation page to either directly change something you see that's wrong, ask a question, or make a suggestion about a potential change via the comments section.

If there's a particular area of documentation that you'd like to see that's missing, please [file a bug](https://github.com/canonical/nginx-ingress-integrator-operator/issues).

## In this documentation

| | |
|--|--|
|  [Tutorials](https://charmhub.io/nginx-ingress-integrator/docs/getting-started)</br>  Get started - a hands-on introduction to using the Charmed NGINX Integrator operator for new users </br> |  [How-to guides](https://charmhub.io/nginx-ingress-integrator/docs/secure-an-ingress-with-tls) </br> Step-by-step guides covering key operations and common tasks |
| [Reference](https://charmhub.io/nginx-ingress-integrator/actions) </br> Technical information - specifications, APIs, architecture | [Explanation](https://charmhub.io/nginx-ingress-integrator/docs/architecture) </br> Concepts - discussion and clarification of key topics  |

# Contents

1. [Tutorial]()
  1. [Getting started](tutorial.md)
1. [How-to](how-to)
  1. [Secure an Ingress with TLS](how-to/secure-an-ingress-with-tls.md)
  1. [Add the Ingress relation to a charm](how-to/add-the-ingress-relation.md)
  1. [Add the Nginx-route relation to a charm](how-to/add-the-nginx-route-relation.md)
  1. [Contribute](how-to/contribute.md)
  1. [Support multiple relations](how-to/support-multiple-relations.md)
1. [Reference](reference)
  1. [Actions](https://charmhub.io/nginx-ingress-integrator/actions)
  1. [Configurations](https://charmhub.io/nginx-ingress-integrator/configurations)
  1. [Integrations](reference/Integrations.md)
  1. [Libraries](https://charmhub.io/nginx-ingress-integrator/libraries/ingress)
1. [Explanation](explanation)
  1. [Architecture](explanation/architecture.md)
  1. [What is Ingress?](explanation/what-is-ingress.md)
  1. [Roadmap](explanation/roadmap.md)
