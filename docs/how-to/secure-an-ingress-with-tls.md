# How to secure an Ingress with TLS.

## Requirements

You will need:

* A laptop or desktop running Ubuntu (or you can use a VM).

* [Juju and MicroK8s](https://documentation.ubuntu.com/juju/3.6/tutorial/?_gl=1*1k9pnjc*_gcl_au*MzEwMDk5MzM1LjE3NTk3Mjk0NTc.#set-up-juju) installed. We'll also want to make sure the ingress add-on is enabled, which we can do by running `microk8s enable ingress`.

* [Charmcraft](https://juju.is/docs/sdk/install-charmcraft) installed.

* A working `nginx-ingress-integrator` deployment.

* OpenSSL installed.

## Creating the TLS secret

For the sake of simplicity you'll create a self-signed SSL certificate for the tutorial, but feel free to add SSL

certificates of other types.

For the creation of the Certificate Authority key execute:

```

openSSL genrsa -out ca.key 2048

```

And for the creation of the certificate itself:

```

openssl req -x509 -new -nodes -days 365 -key ca.key -out ca.crt -subj "/CN=exampledomain.com"

```

With the CA key and cert created, create the actual Kubernetes secret with:

```

microk8s kubectl create secret tls my-tls-secret --key ca.key --cert ca.crt

```

After the secret creation you can check the secret by running:

```

microk8s kubectl get secrets/my-tls-secret

microk8s kubectl describe secrets/my-tls-secret

```

At last, relate the `nginx-ingress-integrator` charm with the MicroK8s TLS secret by setting the config option:

```

juju config nginx-ingress-integrator tls-secret-name="my-tls-secret"

```

Now your NGINX Ingress integrator is secured with TLS.
