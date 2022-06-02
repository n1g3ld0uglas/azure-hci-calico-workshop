# Calico OSS Workshop for Microsoft Azure HCI (Hyper-Converged Infrastructure)

Open PowerShell as Administrator and run the following command to check the available versions of Kubernetes that are currently available:
```
# Show available Kubernetes versions
Get-AksHciKubernetesVersion
```

In the output, you'll see a number of available versions across both Windows and Linux:


<img width="499" alt="Screenshot 2022-06-02 at 14 00 42" src="https://user-images.githubusercontent.com/82048393/171635067-d5f371b0-69ee-48a5-87a3-d225510ced58.png">


You can then run the following command to create and deploy a new Kubernetes cluster: <br/>
(This command will deploy a new Kubernetes cluster named akshciclus001 with the below options)
```
New-AksHciCluster -Name akshciclus001 -nodePoolName linuxnodepool -controlPlaneNodeCount 1 -nodeCount 1 -osType linux
```

<img width="1108" alt="Screenshot 2022-06-02 at 14 01 02" src="https://user-images.githubusercontent.com/82048393/171635099-29838052-7985-45fd-a731-d4817d645406.png">


- A single Control Plane node (VM) <br/>
- A single Load Balancer VM <br/>
- A single Node Pool called linuxnodepool, containing a single Linux worker node (VM) <br/>  <br/>

In my case, I will be deleting and recreating clusters regularly <br/>
To delete an existing managed Kubernetes cluster, run this command:
```
Remove-AksHciCluster -name akshciclus001
```

This is fine for evaluation purposes to begin with. <br/>
There are a number of optional parameters that you can add here if you wish: <br/>
<br/>

``` -kubernetesVersion ``` - by default, the deployment will use the latest, but you can specify a version <br/>
``` -controlPlaneVmSize ``` - Size of the control plane VM. Default is Standard_A2_v2  <br/>
``` -loadBalancerVmSize ``` - Size of your load balancer VM. Default is Standard_A2_V2 <br/>
``` -nodeVmSize ``` - Size of your worker node VM. Default is Standard_K8S3_v  <br/>

The deployment of this Kubernetes workload cluster should take a few minutes, and once complete, should present information about the deployment. <br/> However you can verify the details by running the following command:

```
Get-AksHciNodePool -clusterName akshciclus001
```

<img width="554" alt="Screenshot 2022-06-02 at 14 02 48" src="https://user-images.githubusercontent.com/82048393/171635326-93ffde9b-5ddf-40a3-8f7c-b59408a09ebc.png">

To retrieve the kubeconfig file for the akshciclus001 cluster, you'll need to run the following command. <br/>
Again, this is run in an administrative PowerShell. You can then accept the prompt when prompted:
```
Get-AksHciCredential -Name akshciclus001 -Confirm:$false
dir $env:USERPROFILE\.kube
```

<img width="637" alt="Screenshot 2022-06-02 at 14 07 01" src="https://user-images.githubusercontent.com/82048393/171636108-1bb079a8-c245-41b2-bd27-103757308d42.png">

The default output of this command is to create the kubeconfig file in ```%USERPROFILE%\.kube.``` folder, and will name the file config. <br/>
This config file will overwrite the previous kubeconfig file retrieved earlier. <br/>
You can also specify a custom location by using ```-configPath c:\myfiles\kubeconfig``` 



## Integrate with Azure Arc

```
# Login to Azure
Connect-AzAccount

# Integrate your target cluster with Azure Arc
Enable-AksHciArcConnection -name akshciclus001
```

<img width="812" alt="Screenshot 2022-06-02 at 14 20 22" src="https://user-images.githubusercontent.com/82048393/171638708-75bf23ce-0695-41fa-a7d7-ec92c4b204fa.png">

Confirm all nodes are in ```READY``` status. <br/>
At this point I swapped over to command prompt:

```
kubectl get nodes -o wide
```

## Creating a visible web application

Next, from the same command prompt shell, run the following command to deploy the application directly from GitHub:
```
kubectl apply -f https://raw.githubusercontent.com/Azure/aks-hci/main/eval/yaml/azure-vote.yaml
```



<img width="1290" alt="Screenshot 2022-06-02 at 14 26 03" src="https://user-images.githubusercontent.com/82048393/171639838-4f772c24-803c-4073-b1c4-972c5cdd815e.png">

Next, run the following command to monitor the progress of the deployment (using the --watch argument):
```
kubectl get service azure-vote-front --watch
```

<img width="1290" alt="Screenshot 2022-06-02 at 14 27 23" src="https://user-images.githubusercontent.com/82048393/171640006-07b0e8f0-3512-44da-ac14-a31a93ba2ae9.png">


In our case, you can see that the service has been allocated the ```192.168.0.152``` IP address. <br/>
At this point, you should then be able to open Microsoft Edge and accepting default settings <br/> 
Navigate to that IP address. (Note, it may take a few moments to start)

<img width="1248" alt="Screenshot 2022-06-02 at 14 31 31" src="https://user-images.githubusercontent.com/82048393/171640843-c28fd6b4-c88d-492e-aba8-6b1288d22e73.png">

Find additional information about the nodes your pods are running on and the pod IP's
```
kubectl get pods -n default -o wide
```

Since pods in Kubernetes are ephemeral, we will build policy around their labels:

```
kubectl get pods -n default --show-labels
```

<img width="1028" alt="Screenshot 2022-06-02 at 15 05 57" src="https://user-images.githubusercontent.com/82048393/171648544-7b35dcdd-6f58-4e05-9163-64ac4ae646c8.png">



## Getting started with Calico


Currently, the default networking option in Microsoft Azure HCI is to use Calico in an overlay networking mode. <br/>
The IPAM plugin can be queried on the default Installation resource:

```
kubectl get installation default -o go-template --template {{.spec.cni.ipam.type}}
```

```
kubectl exec -ti -n kube-system calicoctl -- /calicoctl get ippools --allow-version-mismatch
```

If your cluster is using Calico IPAM, the above command should return a result of ```Calico```.
This might not work in Azure HCI since the install is managed by Microsoft. Please run this command:

```
kubectl get pods -A | findstr calico
```
<img width="734" alt="Screenshot 2022-06-02 at 14 38 11" src="https://user-images.githubusercontent.com/82048393/171642084-5b9520db-7395-4dc3-8afb-1fef0a739cef.png">

Block traffic for the test voting application we just created:

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/azure-hci-calico-workshop/main/block-azure-vote-front.yaml
```



## Install Calicoctl
We will follow the official docs for installing the ```calicoctl``` utility: <br/>
https://projectcalico.docs.tigera.io/maintenance/clis/calicoctl/install <br/>
<br/>

```
cd $env:USERPROFILE\.kube
```
Use the following command to download the ```calicoctl``` binary.
```
Invoke-WebRequest -Uri "https://github.com/projectcalico/calico/releases/download/v3.23.1/calicoctl-windows-amd64.exe" -OutFile "calicoctl.exe"
```

Verify the plugin works.
```
calicoctl help
```

<br/>
<br/>
<br/>

## Install a test application (Storefront)

We provided a deployment file for creating your test application
```
kubectl apply -f https://installer.calicocloud.io/storefront-demo.yaml
```

Confirm your test application is running:
```
kubectl get pods -n storefront
```

<img width="962" alt="Screenshot 2022-05-06 at 11 27 10" src="https://user-images.githubusercontent.com/82048393/167114891-87fed43a-87bd-4bd8-a67e-d3f8f4d55f82.png">

Due to the ephemeral nature of Kubernetes, the IP address of a pod is not long lived. <br/>
As a result, it makes more sense for us to target pods based on a consistent label schema (not based on IP address):

<img width="935" height="340" alt="Screenshot 2022-05-06 at 11 52 01" src="https://user-images.githubusercontent.com/82048393/167118571-fda5c06e-224e-4a16-a0c0-e22ec82e3697.png">

To see the label schema associated with your storefront pods, run the below command:
```
kubectl get pods -n storefront --show-labels
```


# Network Policies

As a best practice, we will implement a zone-based architecture via Calico's Networking & Security Policies <br/>
Using a zone-based firewall approach allows us to apply the said security policies to the security zones instead of the pods <br/>
Then, the labelled pods are set as members of the different zones - if they are not in a correct zone, the packets will be dropped.

![container-firewall](https://user-images.githubusercontent.com/82048393/167121017-0e9a68c9-0c50-4063-b211-cfb3c843f866.png)


#### Demilitarized Zone (DMZ) Policy

The following example allows ```Ingress``` traffic from the public internet CIDR net ```18.0.0.0/16``` <br/>
All other Ingress-related traffic will be ```Denied``` - this includes traffic sent to the DMZ from pods within the cluster. <br/>
<br/>
It's important to note that the ```DMZ``` labelled pods can ```Egress``` out to the pods within the ```Trusted``` zone, or if it has a label of ```app=logging``` <br/>
All other outbound traffic from ```DMZ``` zone will be dropped as part of this zero-trust initiative.

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/rancher-desktop-calico-policies/main/dmz.yaml
```
<img width="1135" alt="Screenshot 2022-05-06 at 11 49 04" src="https://user-images.githubusercontent.com/82048393/167117911-83a788bf-c0d5-4433-abd9-dcea98eac8d5.png">

#### Trusted Zone Policy

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/rancher-desktop-calico-policies/main/trusted.yaml
```

<img width="1167" alt="Screenshot 2022-05-06 at 11 59 23" src="https://user-images.githubusercontent.com/82048393/167119339-b4fbd596-11c9-4e94-b368-b593293bf056.png">

#### Restricted Zone Policy

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/rancher-desktop-calico-policies/main/restricted.yaml
```

<img width="1179" alt="Screenshot 2022-05-06 at 12 01 28" src="https://user-images.githubusercontent.com/82048393/167119567-8a967705-f45f-465a-8680-a598f4610b3b.png">

#### Default-Deny Policy

And finally, to absolutely ensure zero-trust workload security is implemented for the storefront namespace, we create a default-deny policy <br/>
Default deny policy ensures pods without policy (or incorrect policy) are not allowed traffic until appropriate network policy is defined. <br/>
https://projectcalico.docs.tigera.io/security/kubernetes-default-deny


```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/rancher-desktop-calico-policies/main/default-deny.yaml
```

<img width="1186" alt="Screenshot 2022-05-06 at 12 06 18" src="https://user-images.githubusercontent.com/82048393/167120572-d87298cb-7024-4765-a2e9-1c823b0ce1a5.png">


#### Fix issue with denied packets in zone-based architecture

Our zero-trust policies are designed to only allow traffic between pods based on label schema <br/>
However, we never factored-in those coredns pods into our security pods. This we can whitelist in the security tier:

```
kubectl apply -f https://raw.githubusercontent.com/n1g3ld0uglas/rancher-desktop-calico-policies/main/allow-kubedns.yaml
```

<img width="1200" alt="Screenshot 2022-05-06 at 12 55 54" src="https://user-images.githubusercontent.com/82048393/167127294-c7acaf7d-df23-46ac-bde1-c5ecd679200b.png">

Confirm your Global Network Policy was actually created within the security tier. <br/>
Again, you can see how the allowed traffic for this newly-created policy in the web UI:
```
kubectl get globalnetworkpolicies -l projectcalico.org/tier=security
```

![Screenshot 2022-05-06 at 12 58 57](https://user-images.githubusercontent.com/82048393/167127472-f2c8e8ed-21fc-4408-bc96-b15ede2db20c.png)

<br/>
<br/>
<br/>

# Encrypt in-cluster pod traffic:

When this feature is enabled, Calico automatically creates and manages WireGuard tunnels between nodes <br/>
https://projectcalico.docs.tigera.io/security/encrypt-cluster-pod-traffic#before-you-begin <br/> 
<br/>
This offers transport-level security for on-the-wire, in-cluster pod traffic. <br/>
WireGuard provides formally verified secure and performant tunnels without any specialized hardware. <br/>
<br/>
For a deep dive in to WireGuard implementation, see this whitepaper: <br/>
https://www.wireguard.com/papers/wireguard.pdf <br/>
<br/>
WireGuard is included in Linux ```5.6+ kernels```, and has been backported to earlier Linux kernels in some Linux distributions. <br/>
AKS cluster nodes run Ubuntu with a kernel that has WireGuard installed already, so there is no manual installation required. 

```
kubectl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
```

### Disable WireGuard for a cluster
To disable WireGuard on all nodes modify the default Felix configuration. For example:
```
./calicoctl patch felixconfiguration default --type='merge' -p '{"spec":{"wireguardEnabled":false}}'
```

### Disable WireGuard for an individual node
To disable WireGuard on a specific node with WireGuard installed, modify the node-specific Felix configuration <br/>
e.g: to turn off encryption for pod traffic on node my-node, use the following command:

```
cat <<EOF | kubectl apply -f -
apiVersion: projectcalico.org/v3
kind: FelixConfiguration
metadata:
  name: node.my-node
spec:
  logSeverityScreen: Info
  reportingInterval: 0s
  wireguardEnabled: false
EOF
```

With the above command, Calico will not encrypt any of the pod traffic to or from node my-node. <br/>
To enable encryption for pod traffic on node my-node again:
```
./calicoctl patch felixconfiguration node.my-node --type='merge' -p '{"spec":{"wireguardEnabled":true}}'
```

### Verify configuration
To verify that the nodes are configured for WireGuard encryption, check the node status set by Felix using calicoctl

```
   ./calicoctl get node <NODE-NAME> -o yaml
   ...
   status:
     ...
     wireguardPublicKey: jlkVyQYooZYzI2wFfNhSZez5eWh44yfq1wKVjLvSXgY=
     ...
```

# IPAM:

### Scenario 1: Migrate from one IP pool to another

Pods are assigned IP addresses from IP pools that you configure in Calico. <br/>
As the number of pods increase, you may need to increase the number of addresses available for pods to use. <br/>

Or, you may need to move pods from a CIDR that was used by mistake. <br/>
Calico lets you migrate from one IP pool to another one on a running cluster without network disruption <br/>
https://projectcalico.docs.tigera.io/networking/migrate-pools <br/>

Let’s run calicoctl with the below command to to see the IP pool, default-ipv4-ippool
```
./calicoctl get ippool -o wide
```

The output should look like this:

```
NAME                  CIDR            NAT    IPIPMODE   VXLANMODE   DISABLED   DISABLEBGPEXPORT   SELECTOR   
default-ipv4-ippool   10.244.0.0/16   true   Never      Always      false      false              all()
```

When we run the below command, we see that a pod is created using the default range (10.244.34.130/32).
```
./calicoctl get wep --all-namespaces
```

```
NAMESPACE          WORKLOAD                                   NODE                                NETWORKS           INTERFACE         
calico-apiserver   calico-apiserver-6b48b9894b-d627h          aks-nodepool1-38669398-vmss000003   10.244.34.130/32   cali14f7d51e2c6   
calico-apiserver   calico-apiserver-6b48b9894b-hwxlx          aks-nodepool1-38669398-vmss000003   10.244.34.129/32   calib74e2fd2d16   
calico-system      calico-kube-controllers-77f96d9656-gd7hm   aks-nodepool1-38669398-vmss000003   10.244.34.133/32   caliea196ffe544   
kube-system        coredns-69c47794-86db7                     aks-nodepool1-38669398-vmss000003   10.244.34.132/32   calie0a5573f330   
kube-system        coredns-69c47794-wmvrj                     aks-nodepool1-38669398-vmss000003   10.244.34.135/32   cali3db72ae2319   
kube-system        coredns-autoscaler-7d56cd888-t4cvr         aks-nodepool1-38669398-vmss000003   10.244.34.134/32   cali15e5361407d   
kube-system        metrics-server-64b66fbbc8-6n2zm            aks-nodepool1-38669398-vmss000003   10.244.34.131/32   cali51656fecf55 
```

Let’s get started changing this pod to the new IP pool (10.0.0.0/16). <br/>
We add a new ```IPPool``` resource with the CIDR range, 10.0.0.0/16.

```
kubectl create -f - <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: new-pool
spec:
  cidr: 10.0.0.0/16
  ipipMode: Always
  natOutgoing: true
EOF  
```  

Let’s verify the new IP pool was created correctly. <br/>
It should reference the new CIDR range, ```10.0.0.0/16```.

```
./calicoctl get ippool -o wide
```

```
NAME                  CIDR            NAT    IPIPMODE   VXLANMODE   DISABLED   DISABLEBGPEXPORT   SELECTOR   
default-ipv4-ippool   10.244.0.0/16   true   Never      Always      false      false              all()      
new-pool              10.0.0.0/16     true   Always     Never       false      false              all()
```

Disable the old IP pool - ```default-ipv4-ippool``` <br/>
Firstly, let's list the existing IP pool definition.

```
./calicoctl get ippool -o yaml > pools.yaml
```

```
cat pools.yaml
```

```
apiVersion: projectcalico.org/v3
items:
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    creationTimestamp: "2022-05-13T13:01:46Z"
    name: default-ipv4-ippool
    resourceVersion: "2370"
    uid: 5a5d4a43-8993-4390-ba1f-ff7c0dc45c5f
  spec:
    allowedUses:
    - Workload
    - Tunnel
    blockSize: 26
    cidr: 10.244.0.0/16
    ipipMode: Never
    natOutgoing: true
    nodeSelector: all()
    vxlanMode: Always
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    creationTimestamp: "2022-05-13T15:36:40Z"
    managedFields:
    - apiVersion: projectcalico.org/v3
      fieldsType: FieldsV1
      fieldsV1:
        f:spec:
          f:cidr: {}
          f:ipipMode: {}
          f:natOutgoing: {}
      manager: kubectl-create
      operation: Update
      time: "2022-05-13T15:36:40Z"
    name: new-pool
    resourceVersion: "19819"
    uid: 3fa257a0-9c6d-4394-95c7-22e7176717b4
  spec:
    allowedUses:
    - Workload
    - Tunnel
    blockSize: 26
    cidr: 10.0.0.0/16
    ipipMode: Always
    natOutgoing: true
    nodeSelector: all()
    vxlanMode: Never
kind: IPPoolList
metadata:
  resourceVersion: "20996"
```

Disable this IP pool by setting: ```disabled: true``` <br/>
Add this one line after the ```natOutgoing: true``` field.
```
vi pools.yaml
```

Apply the changes. <br/>
Remember, disabling a pool only affects new IP allocations; networking for existing pods is not affected.

```
./calicoctl apply -f pools.yaml
```

Output should look similar to the below example. <br/>
Verify the changes with the same ```./calicoctl get``` command

```
Successfully applied 2 'IPPool' resource(s)
```

```
./calicoctl get ippool -o wide
```

```
NAME                  CIDR            NAT    IPIPMODE   VXLANMODE   DISABLED   DISABLEBGPEXPORT   SELECTOR   
default-ipv4-ippool   10.244.0.0/16   true   Never      Always      true       false              all()      
new-pool              10.0.0.0/16     true   Always     Never       false      false              all()
```

Next, we delete all of the existing pods from the old IP pool. <br/>
If you have multiple pods, you would trigger a deletion for all pods in the cluster.

```
kubectl delete pod -n kube-system <example-coredns-pod>
```

Verify that new pods get an address from the new IP pool. <br/>
Create a test namespace and nginx pod to go in that namespace.

```
kubectl create ns ippool-test
```

```
kubectl -n ippool-test create deployment nginx --image nginx
```

Verify that the new pod gets an IP address from the new range. <br/>
Once you have completed this, cleanup the ```ippool-test``` namespace.

```
kubectl -n ippool-test get pods -l app=nginx -o wide
```

```
kubectl delete ns ippool-test
```

Now that you’ve verified that pods are getting IPs from the new range, you can safely delete the old pool. <br/>
We can now proceed to our next configuration test.

```
./calicoctl delete pool default-ipv4-ippool
```

<br/>
<br/>
<br/>

### Scenario 2: Change IP pool block size
https://projectcalico.docs.tigera.io/networking/change-block-size <br/>
By default, Calico uses an IPAM block size of 64 addresses – /26 for IPv4, and /122 for IPv6. <br/>
However, the block size can be changed depending on the IP pool address family. <br/>
<br/>
IPv4: 20-32, inclusive
IPv6: 116-128, inclusive
You can have only one default IP pool for per protocol in your installation manifest. <br/>
In this example, there is one IP pool for IPv4 (/26), and one IP pool for IPv6 (/122) <br/>

```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
  pec:
   # Configures Calico networking.
   calicoNetwork:
     # Note: The ipPools section cannot be modified post-install.
    ipPools:
    - blockSize: 26
      cidr: 10.48.0.0/21
      encapsulation: VXLAN
      natOutgoing: Enabled
      nodeSelector: all()
    - blockSize: 122
      cidr: 2001::00/64 
      encapsulation: None 
      natOutgoing: Enabled 
      nodeSelector: all()
```

However, the following is ```INVALID``` because it has two IP pools for IPv4.
```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
  spec:
   # Configures Calico networking.
   calicoNetwork:
     # Note: The ipPools section cannot be modified post-install.
    ipPools:
    - blockSize: 26
      cidr: 10.48.0.0/21
      encapsulation: VXLAN
      natOutgoing: Enabled
      nodeSelector: all()
    - blockSize: 31
      cidr: 10.48.8.0/21
      encapsulation: VXLAN
      natOutgoing: Enabled
      nodeSelector: all()
```

#### Expand or shrink IP pool block sizes
By default, the Calico IPAM block size for an IP pool is /26. <br/>
To expand from the default size /26, lower the blockSize (for example, /24). <br/>
To shrink the blockSize from the default /26, raise the number (for example, /28).


#### Best practice: change IP pool block size before installation
We now know the ```blockSize``` field cannot be edited directly after Calico installation. <br/>
It is best to change the IP pool block size before installation to minimize disruptions to pod connectivity.

#### Create a temporary IP pool
We add a new IPPool with the CIDR range, ```10.0.0.0/16```.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: temporary-pool
spec:
  cidr: 10.0.0.0/16
  ipipMode: Always
  natOutgoing: true
```

Apply the changes.
```
./calicoctl apply -f temporary-pool.yaml
```

Let’s verify the temporary IP pool.
```
./calicoctl get ippool -o wide
```
```
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     false
temporary-pool        10.0.0.0/16      true   Always     false
```

#### Disable the existing IP pool
Disable allocations in the default pool.
```
./calicoctl patch ippool default-ipv4-ippool -p '{"spec": {"disabled": true}}'
```

Verify the changes.
```
./calicoctl get ippool -o wide
```
```
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     true
temporary-pool        10.0.0.0/16      true   Always     false
```

## Delete pods from the existing IP pool
In our example, coredns is our test pod scenario <br/> 
For multiple pods you would trigger a deletion for all pods in the cluster.
```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```

Restart all pods with just one command. <br/>
```WARNING!``` The following command is disruptive and may take several minutes depending on the number of pods deployed.

```
kubectl delete pod -A --all
```

#### Delete the existing IP pool
Now that you’ve verified that pods are getting IPs from the new range, you can safely delete the existing pool.
```
./calicoctl delete ippool default-ipv4-ippool
```

#### Create a new IP pool with the desired block size

In this step, we update the IPPool with the new block size of ```(/28)```.
Once the changes are configured, apply the file ``` kubectl apply -f```.

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: default-ipv4-ippool
spec:
  blockSize: 28
  cidr: 192.0.0.0/16
  ipipMode: Always
  natOutgoing: true
```

```
./calicoctl apply -f pool.yaml
```

#### Disable the temporary IP pool
```
./calicoctl patch ippool temporary-pool -p '{"spec": {"disabled": true}}'
```

####  Delete pods from the temporary IP pool
In our example, coredns is our only pod <br/> 
For multiple pods you would trigger a deletion for all pods in the cluster.
```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```

```WARNING!``` The following command is disruptive and may take several minutes depending on the number of pods deployed.
```
kubectl delete pod -A --all
```

Validate your pods and block size are correct by running the following commands:
```
kubectl get pods --all-namespaces -o wide
./calicoctl ipam show --show-blocks
```

####   Delete the temporary IP pool
Clean up the IP pools by deleting the temporary IP pool. <br/>
Your cluster should now be in the original state you left it in.
```
./calicoctl delete pool temporary-pool
```


<br/>
<br/>
<br/>


## Calico Certified Courses
For more configuration scenarios, users can sign-up for the certified Calico Operator (for Azure) course:
```
[https://academy.tigera.io/course/certified-calico-operator-level-1/](https://www.tigera.io/lp/calico-academy-completion-azure/)
```

<br/>
<br/>
<br/>
