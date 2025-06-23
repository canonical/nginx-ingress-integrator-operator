# Security in NGINX Ingress Integrator charm

This document describes the security design of the NGINX Ingress Integrator charm.
The charm manages an [NGINX web server](https://nginx.org/) as an ingress proxy.
This document will detail the risks and good practices of operating the charm.

## Machine-in-the-middle attack

This type of attack refers to an attacker intercepting messages and pretending to be the intended recipient of the message.
For example, if an user tries to access `ubuntu.com`, an attacker might intercept the packets and pretend to be `ubuntu.com`, and trick the user into reveal their password.
The way to prevent this would be using TLS certificates to validate the identity of the recipient.

As an ingress proxy, clients would be sending requests to the charm.
Encrypting these requests would help to prevent any machine-in-the-middle attack.
This can be achieved by giving a TLS certificate to the charm, configuring it to accept HTTPS request over the unencrypted HTTP request.
See [how to secure an Ingress with TLS](https://charmhub.io/nginx-ingress-integrator/docs/secure-an-ingress-with-tls) for how to achieve this.

### Good practices

- Use TLS certificates to encrypt traffic.

## Denial-of-service (DoS) attack

This type of attack refers to attackers overloading a service by issuing many requests in a short period of time.
Attackers hope to exhaust the service's resources, e.g., memory and CPU cycles.

The common way to deal with this type of attack is by limiting the number of requests per IP address.
While it does not prevent all forms of DoS attacks, it is generally an effective mitigation strategy.

The charm offers configuration to set a rate-limit by IP address, and an allow list to exempt IP addresses from the rate-limit.
The allow list is meant for trusted IP addresses, and might issue lots of requests.

### Good practices

- Set a reasonable rate limit via the [`limit-rps` charm configuration](https://charmhub.io/nginx-ingress-integrator/configurations#limit-rps).
- Use the allow list if needed via the [`limit-whitelist` charm configuration](https://charmhub.io/nginx-ingress-integrator/configurations#limit-whitelist)
