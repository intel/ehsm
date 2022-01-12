# eHSM Kubernetes
Welcome to eHSM Kubernetes!
## How to use the eHSM Kubernetes
***
### Preparation
***
You must have at least three computers,a master-node server,one or more work-node servers and an NFS server.It is recommended to install centos8.2 or above.

### System initialization
***
#### Step 1 Install dependencies
```Shell
# yum install -y conntrack ntpdate ntp ipvsadm ipset jq iptables sysstat libseccomp vim net-tools
```
#### Step 2 Enable SELINUX
```Shell
# swapoff -a && sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
# setenforce 0 && sed -i 's/^SELINUX=.*/SELINUX=disabled/' /etc/selinux/config
```
#### Step 3 Set kernel parameters for kubernetes
```Shell
# vim /etc/sysctl.d/kubernetes.conf

net.bridge.bridge-nf-call-iptables=1
net.bridge.bridge-nf-call-ip6tables=1
vm.swappiness=0
vm.overcommit_memory=1
vm.panic_on_oom=0
net.ipv6.conf.all.disable_ipv6=1

# sysctl -p /etc/sysctl.d/kubernetes.conf
```
### Kubernetes installation
***
#### Step 1 Preparation of ipvs
```Shell
# modprobe br_netfilter
# vim /etc/sysconfig/modules/ipvs.modules

modprobe -- ip_vs 
modprobe -- ip_vs_rr 
modprobe -- ip_vs_wrr 
modprobe -- ip_vs_sh
modprobe -- nf_conntrack

# chmod 755 /etc/sysconfig/modules/ipvs.modules && bash /etc/sysconfig/modules/ipvs.modules && lsmod | grep -e ip_vs -e nf_conntrack
```
#### Step 2 Docker installation
```Shell
# curl https://download.docker.com/linux/centos/docker-ce.repo -o /etc/yum.repos.d/docker-ce.repo
# yum install https://download.docker.com/linux/fedora/30/x86_64/stable/Packages/containerd.io-1.2.6-3.3.fc30.x86_64.rpm
# dnf -y  install docker-ce  docker-ce-cli --nobest
# systemctl start docker
# mkdir /etc/docker
# vim /etc/docker/daemon.json

{
    "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn/"],
    "exec-opts": ["native.cgroupdriver=systemd"],
    "log-driver": "json-file",
    "log-opts": {
        "max-size": "100m"
    }
}

# mkdir -p /etc/systemd/system/docker.service.d
# systemctl daemon-reload && systemctl restart docker && systemctl enable --now docker
```
#### Step 3 kubeadm installation
```Shell
# vim /etc/yum.repos.d/kubernetes.repo

[kubernetes]
name=Kubernetes
baseurl=https://mirrors.aliyun.com/kubernetes/yum/repos/kubernetes-el7-x86_64/
enable=1
gpgcheck=0
exclude=kubelet kubeadm kubectl

# yum -y install kubeadm-1.19.0 kubectl-1.19.0 kubelet-1.19.0 --disableexcludes=kubernetes

# systemctl enable kubelet.service
```
#### Step 4 Import required Kubernetes cluster images for installation

    Download kubeadm-basic.images.tar.gz and docker load.

#### Step 5 Initialize master-node
```Shell
# kubeadm config print init-defaults > kubeadm-config.yaml
# vim kubeadm-config.yaml


localAPIEndpoint:
  advertiseAddress: 1.2.3.4 --> change to <master-node's IP>

kubernetesVersion: v1.19.0

networking:
  dnsDomain: cluster.local
  podSubnet: "10.244.0.0/16"
  serviceSubnet: 10.96.0.0/12

---
apiVersion: kubeproxy.config.k8s.io/v1alpha1
kind: KubeProxyConfiguration
featureGates:
  SupportIPVSProxyMode: true
mode: ipvs

# kubeadm init --config=kubeadm-config.yaml | tee kubeadm-init.log

# mkdir -p $HOME/.kube
# sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
# sudo chown $(id -u):$(id -g) $HOME/.kube/config
# kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml

```

#### Step 6 Add work-node
Check kubedm initialization log Find the <font color='red'> [kubeadm join] </font>command and run it on the work-node.

### NFS Server installation
***
#### Step 1 Create NFS server
```Shell
# yum install -y nfs-common nfs-utils rpcbind 
# mkdir /nfs_ehsm_db
# chmod 777 /nfs_ehsm_db
# chown nfsnobody /nfs_ehsm_db
# vim /etc/exports

/nfs_ehsm_db *(rw,no_root_squash,no_all_squash,sync) 

# systemctl start rpcbind && systemctl enable rpcbind
# systemctl start nfs && systemctl enable nfs
```

#### Step 2 Configure other servers
Execute command on each kubernetes node
```Shell
# yum install -y nfs-utils rpcbind 
```

### Install the sgx SDK
***
Execute command on each kubernetes work-node
```Shell
# yum update
# yum install dkms
# wget https://download.01.org/intel-sgx/sgx-dcap/1.12.1/linux/distro/centos8.2-server/sgx_linux_x64_driver_1.41.bin
# chmod 777 sgx_linux_x64_driver_1.41.bin
# sh -c 'echo yes | ./sgx_linux_x64_driver_1.41.bin'

```

### Start Kubernetes
***
#### Step 1 create namespace
```Shell
# kubectl create namespace intel-ehsm
```
#### Step 2 create pv
```Shell
# kubectl apply -f ehsm-pv.yaml
```
#### Step 3 create secret and configmap
```Shell
# kubectl apply -f ehsm-secret.yaml -n intel-ehsm
# kubectl apply -f ehsm-configmap.yaml -n intel-ehsm
```
#### Step 4 create database
```Shell
# kubectl apply -f ehsm-db.yaml  -n intel-ehsm
```
#### Step 5 create ehsm-kms
```Shell
# kubectl apply -f ehsm-kms.yaml -n intel-ehsm
```


