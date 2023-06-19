A [Juju](https://juju.is/) [charm](https://juju.is/docs/olm/charmed-operators) deploying and managing external access to HTTP/HTTPS services in a Kubernetes cluster via an Nginx Ingress resource. This requires the Kubernetes cluster in question to have an [Nginx Ingress Controller](https://docs.nginx.com/nginx-ingress-controller/) already deployed into it.

This charm simplifies exposing services running inside a Kubernetes cluster to external clients. It offers TLS termination as well as easy configuration of a number of advanced features including rate limiting, restricting access to specific client IP source ranges, and OWASP ModSecurity Core Rule Set (CRS).

As such, the charm makes it easy for charm developers to provide external access to their HTTP workloads in Kubernetes by easy integration offered via [the charm's nginx_route library](https://charmhub.io/nginx-ingress-integrator/libraries/nginx_route).

For DevOps and SRE teams, providing ingress for charms that support a relation to this charm will be possible via a simple `juju relate` command.


# Navigation

| Level | Path     | Navlink                         |
| ----- | -------- | ------------------------------- |
| 1 | Tutorial | [Tutorial]() |
| 2 | getting-started | [Getting started](/t/nginx-ingress-integrator-docs-tutorial-getting-started/7697)
| 1 | how-to | [How to]() |
| 2 | secure-an-ingress-with-tls | [Secure an Ingress with TLS](https://discourse.charmhub.io/t/nginx-ingress-integrator-docs-how-to-secure-ingress-with-tls/10301) |
| 2 | add-the-ingress-relation | [Add the Ingress relation to a charm](/t/nginx-ingress-integrator-docs-tutorial-adding-relation-to-a-charm/7434) |
| 2 | contribute | [Contribute](/t/nginx-ingress-integrator-docs-contributing-hacking/4512)  |
| 2 | support-multiple-relations | [Support multiple relations](/t/nginx-ingress-integrator-docs-multiple-relations/5725) |
| 1 | Reference | [Reference]() |
| 2 | Actions | [Actions](https://charmhub.io/nginx-ingress-integrator/actions) |
| 2 | Configurations | [Configurations](https://charmhub.io/nginx-ingress-integrator/configure) |
| 2 | Integrations | [Integrations](/t/nginx-ingress-integrator-docs-reference-integrations/7756) |
| 2 | Libraries | [Libraries](https://charmhub.io/nginx-ingress-integrator/libraries/ingress) |
| 1 | Explanation | [Explanation]() |
| 2 | architecture | [Architecture](/t/nginx-ingress-integrator-docs-charm-architecture/7391) |
| 2 | what-is-ingress | [What is Ingress?](/t/nginx-ingress-integrator-docs-ingress-explanation/7392) | 
|  | roadmap | [Roadmap](/t/nginx-ingress-integrator-docs-roadmap/7432) |


# Redirects

[details=Mapping table]
| Path | Location |
| ---- | -------- |
[/details]


# Redirects

[details=Mapping table]
| Path | Location |
| ---- | -------- |
[/details]