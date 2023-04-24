# How to secure an Ingress with TLS.

## Requirements

You will need:
* A laptop or desktop running Ubuntu (or you can use a VM).
* [Juju and Microk8s](https://juju.is/docs/olm/microk8s) installed. We'll also want to make sure the ingress add-on is enabled, which we can do by running `microk8s enable ingress`.
* [Charmcraft](https://juju.is/docs/sdk/install-charmcraft) installed.
* A working Nginx-ingress-integrator deployment.
* Openssl installed.

## Creating the TLS secret

For the sake of simplicity you'll create a self-signed SSL certificate for the tutorial, but feel free to add SSL
certs of other types. 
For the creation of the Certificate Authority key you'll execute:
```
OpenSSL genrsa -out ca.key 2048
```
And for the creation of the cert itself:
```
openssl req -x509 -new -nodes -days 365 -key ca.key -out ca.crt -subj "/CN=exampledomain.com"
```
With the CA key and cert created, you'll proceed to create the actual Kubernetes secret with:
```
microk8s kubectl create secret tls my-tls-secret --key ca.key --cert ca.crt
```
After the secret creation you can check and describe the secret with the following commands:
```
microk8s kubectl get secrets/my-tls-secret
microk8s kubectl describe secrets/my-tls-secret
```
At last, now relate the nginx-ingress-integrator charm with the microk8s TLS secret by the config option:
```
juju config nginx-ingress-integrator tls-secret-name="my-tls-secret"
```
Now your NGINX Ingress integrator is secured with TLS.
