(tutorial_tutorial)=

<!-- vale Canonical.007-Headings-sentence-case = NO -->

# Deploy the Nginx ingress integrator charm for the first time

<!-- vale Canonical.007-Headings-sentence-case = YES -->

The `nginx-ingress-integrator` charm helps other charms configure Nginx
ingress in Kubernetes clusters. This tutorial will walk you through each
step of deploying the `nginx-ingress-integrator` charm to provide 
ingress for the WordPress web application, which is provided by the
`wordpress-k8s` charm.

## What you'll do

- Deploy the `wordpress-k8s` charm
- Deploy the `nginx-ingress-integrator` charm
- Relate the `nginx-ingress-integrator` charm with the `wordpress-k8s` charm
- Test the ingress it creates.
- Configure the hostname for host-based routing

<!-- SPREAD SKIP -->

## What you'll need

- A working station, e.g., a laptop, with AMD64 architecture.
- Juju 3 installed. For more information about how to install Juju, see {ref}`Get started with Juju <juju:tutorial>`.
- Juju bootstrapped to a MicroK8s controller: `juju bootstrap microk8s tutorial-controller`

````{tip}
You can use Multipass to create an isolated environment by running:
```bash
multipass launch 24.04 --name charm-tutorial-vm --cpus 4 --memory 8G --disk 50G
```
To work inside the Multipass VM run the following command:
```bash
multipass shell charm-tutorial-vm
```
````

This tutorial requires the following software to be installed on your working station
(either locally or in the Multipass VM):

- Juju 3
- MicroK8s 1.33

Use [Concierge](https://github.com/canonical/concierge) to set up Juju and MicroK8s:

```
sudo snap install --classic concierge
sudo concierge prepare -p microk8s
```

This first command installs Concierge, and the second command uses Concierge to install
and configure Juju and MicroK8s.

For this tutorial, Juju must be bootstrapped to a MicroK8s controller. Concierge should
complete this step for you, and you can verify by checking for `msg="Bootstrapped Juju" provider=microk8s`
in the terminal output and by running `juju controllers`.

If Concierge did not perform the bootstrap, run:

```
juju bootstrap microk8s tutorial-controller
```

<!-- SPREAD SKIP END -->

## Set up the environment

To manage resources effectively and to separate this tutorial's workload from
your usual work, create a new model in the MicroK8s controller using the following command:

```bash
juju add-model nginx-ingress-tutorial
```

You will also need to install Nginx ingress in the Kubernetes cluster.
This can be achieved by enable the ingress plugin in MicroK8s using the
following command.

```bash
sudo microk8s enable ingress
```

<!-- vale Canonical.007-Headings-sentence-case = NO -->

## Deploy WordPress K8s charm

<!-- vale Canonical.007-Headings-sentence-case = YES -->

Nginx ingress integrator provides ingress to other charms. In this 
tutorial, we will use the WordPress charm as the backend application to
demonstrate the Nginx ingress integrator charm's capability to configure
ingress.

Deployment of WordPress requires a relational database. The integration with the
`mysql` {ref}`interface <juju:relation>` is required by the `wordpress-k8s`
charm and hence, [`mysql-k8s`](https://charmhub.io/mysql-k8s) charm will be used.

Start off by deploying the WordPress charm. By default it will deploy the latest stable release of
the `wordpress-k8s` charm.

```bash
juju deploy wordpress-k8s
```

Now deploy the `mysql-k8s` charm and integrate it with the `wordpress-k8s` charm.

```bash
juju deploy mysql-k8s --trust
juju integrate wordpress-k8s mysql-k8s:database
```

The `database` interface is required since the `mysql-k8s` charm provides multiple compatible interfaces.

Run `juju status` to see the current status of the deployment. The output should be similar to the following:

```{terminal}
juju status

Model                   Controller          Cloud/Region        Version  SLA          Timestamp
nginx-ingress-tutorial  microk8s-localhost  microk8s/localhost  3.6.8    unsupported  11:25:46Z

App            Version                  Status  Scale  Charm          Channel        Rev  Address        Exposed  Message
mysql-k8s      8.0.41-0ubuntu0.22.04.1  active      1  mysql-k8s      8.0/stable     255  10.152.183.65  no       
wordpress-k8s  6.8.1                    active      1  wordpress-k8s  latest/stable  144  10.152.183.71  no       

Unit              Workload  Agent  Address      Ports  Message
mysql-k8s/0*      active    idle   10.1.43.140         Primary
wordpress-k8s/0*  active    idle   10.1.43.138         
```

The deployment finishes when the status shows "Active" for both the WordPress and MySQL charms.

<!-- vale Canonical.007-Headings-sentence-case = NO -->

## Deploy the Nginx ingress integrator

<!-- vale Canonical.007-Headings-sentence-case = YES -->

The following commands deploy the `nginx-ingress-integrator` charm and
integrate it with the `wordpress-k8s` charm. `--trust` is needed because
the `nginx-ingress-integrator` charm requires elevated permission to 
create ingress-related resources in Kubernetes clusters.

```bash
juju deploy nginx-ingress-integrator --trust
juju integrate wordpress-k8s nginx-ingress-integrator
```

Run `juju status` to see the current status of the deployment. The 
output should be similar to the following:

```{terminal}
juju status

Model                   Controller          Cloud/Region        Version  SLA          Timestamp
nginx-ingress-tutorial  microk8s-localhost  microk8s/localhost  3.6.8    unsupported  11:27:23Z

App                       Version                  Status   Scale  Charm                     Channel        Rev  Address         Exposed  Message
mysql-k8s                 8.0.41-0ubuntu0.22.04.1  active       1  mysql-k8s                 8.0/stable     255  10.152.183.65   no       
nginx-ingress-integrator  24.2.0                   waiting      1  nginx-ingress-integrator  latest/stable  153  10.152.183.202  no       installing agent
wordpress-k8s             6.8.1                    active       1  wordpress-k8s             latest/stable  144  10.152.183.71   no       

Unit                         Workload  Agent  Address      Ports  Message
mysql-k8s/0*                 active    idle   10.1.43.140         Primary
nginx-ingress-integrator/0*  active    idle   10.1.43.141         Ingress IP(s): 127.0.0.1
wordpress-k8s/0*             active    idle   10.1.43.138         
```

The deployment finishes when the status shows
"Ingress IP(s): 127.0.0.1" on `nginx-ingress-integrator`. The IP 
addresses may differ based on your Kubernetes cluster setup.

## Test the ingress

You can use `curl`, a command-line HTTP client, to access the deployed 
WordPress instances via the Kubernetes ingress created by the 
`nginx-ingress-integrator`. In the following example, the ingress 
address is `127.0.0.1`, but it may vary based on your Kubernetes cluster
setup. If unknown, you can find the ingress address in the 
`nginx-ingress-integrator` charm status message.

```bash
curl -H "Host: wordpress-k8s" http://127.0.0.1
```

The output should be the HTML code of the WordPress front page, 
indicating that the request was successfully forwarded to WordPress by
the ingress created by `nginx-ingress-integrator`.

## Configure the ingress hostname

Now let's use the `service-hostname` configuration of the
`nginx-ingress-integrator` charm to change the hostname used for
[host-based routing](https://kubernetes.github.io/ingress-nginx/user-guide/basic-usage/).

Now update the `service-hostname` configuration to a new value:

```bash
juju config nginx-ingress-integrator service-hostname=wordpress.test
```

Wait until everything is active and idle by monitoring `juju status`. Now, if you use the original
default hostname to access the WordPress service behind the ingress, it
will return a 404 Not Found response.

```{terminal}
curl -H "Host: wordpress-k8s" http://127.0.0.1

<html>
<head><title>404 Not Found</title></head>
<body>
<center><h1>404 Not Found</h1></center>
<hr><center>nginx</center>
</body>
</html>
```

But if you use the new hostname (`wordpress.test`) we just set, you can
access WordPress without any problem:

```bash
curl -H "Host: wordpress.test" http://127.0.0.1
```

## Clean up the environment 

Congratulations! You've completed the Nginx
ingress integrator tutorial. You can clean up your environment by 
following this guide:
{ref}`Tear down your test environment <juju:tear-things-down>`