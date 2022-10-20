# K8S cluster environment setup guide

Welcome to see the guide about the K8S cluster environment.

---

## Preparation

You must have at least three computers,a master-node server,one or more work-node servers and an NFS server.It is recommended to install Ubuntu 20.* or above.

---

## System initialization
- In order to install kubernetes, you need to install some dependencies on the system and modify some system settings, Please perform step 1 to step 4 on each kubernetes node.
    ### Step 1 Install dependencies
    ```Shell
    $ apt update
    $ apt install -y wget conntrack net-tools ntpdate ntp ipvsadm ipset vim jq iptables sysstat
    ```

    ### Step 2 Disable swapoff
    ```Shell
    # Temporarily close swapoff
    $ swapoff -a 

    # Permanently close swapoff
    $ sed -i '/ swap / s/^\(.*\)$/#\1/g' /etc/fstab
    ```

    ### Step 3 Set kernel parameters for kubernetes
    ```Shell
    $ vim /etc/sysctl.d/kubernetes.conf

    vm.swappiness=0
    vm.overcommit_memory=1
    vm.panic_on_oom=0
    net.bridge.bridge-nf-call-iptables=1
    net.bridge.bridge-nf-call-ip6tables=1
    net.ipv6.conf.all.disable_ipv6=1

    $ sysctl -p /etc/sysctl.d/kubernetes.conf
    ```

    #### Step 4 Preparation of ipvs
    ```Shell
    $ modprobe br_netfilter
    $ vim /etc/systemd/network/ipvs.modules

    modprobe -- ip_vs 
    modprobe -- ip_vs_rr 
    modprobe -- ip_vs_wrr 
    modprobe -- ip_vs_sh
    modprobe -- nf_conntrack

    $ chmod 755 /etc/systemd/network/ipvs.modules && bash /etc/systemd/network/ipvs.modules && lsmod | grep -e ip_vs -e nf_conntrack
    ```

---

## Kubernetes installation
- After the kubernetes node server initialization is completed, we start to install kubernetes. First, you need to execute step 1 to step 3 on each kubernetes node server to complete the preparations for kubernetes initialization, then execute step 4 on the master-node server to initialize, and execute step 5 on each work-node to join the work-node to the master-server. So far, the kubernetes has been installed, If you want to support SGX Device Plugin for Kubernetes, you can perform step 6.

    ### Step 1 Docker installation
    ```Shell
    $ curl -fsSL https://get.docker.com | bash -s docker --mirror Aliyun
    $ mkdir /etc/docker
    $ vim /etc/docker/daemon.json

    {
        "registry-mirrors": ["https://docker.mirrors.ustc.edu.cn/"],
        "exec-opts": ["native.cgroupdriver=systemd"],
        "log-driver": "json-file",
        "log-opts": {
            "max-size": "100m"
        }
    }

    $ mkdir -p /etc/systemd/system/docker.service.d

    $ systemctl daemon-reload && systemctl restart docker && systemctl enable docker
    ```

    ### Step 2 kubeadm installation
    ```Shell
    $ apt-get update && apt-get install -y apt-transport-https

    $ curl https://mirrors.aliyun.com/kubernetes/apt/doc/apt-key.gpg | apt-key add - 

    $ cat <<EOF >/etc/apt/sources.list.d/kubernetes.list
    deb https://mirrors.aliyun.com/kubernetes/apt/ kubernetes-xenial main
    EOF

    $ apt-get update

    $ apt-get -y install kubeadm=1.23.5-00 kubectl=1.23.5-00 kubelet=1.23.5-00

    $ systemctl enable kubelet.service
    ```

    ### Step 3 Import required Kubernetes cluster images for installation
    Download kubeadm-basic.images.tar.gz and docker load. You can use the following command to view the image you need to import.
    ```Shell
    $ kubeadm config images list --kubernetes-version v1.23.5
    ```

    ### Step 4 Initialize master-node
    ```Shell
    # Create an initialization yaml file
    $ kubeadm config print init-defaults > kubeadm-config.yaml

    # Edit yaml file and modify the following contents
    $ vim kubeadm-config.yaml

    # Change 1.2.3.4 to your master-node's IP
    localAPIEndpoint:
      advertiseAddress: 1.2.3.4

    # Change node to your master-node's hostname
    nodeRegistration:
      name: node


    # Check the version is your kubeadm version.
    kubernetesVersion: v1.23.5

    # Add podSubnet settings.
    networking:
    dnsDomain: cluster.local
    # The 10.244.0.0/16 is Flannel default network segment.
    podSubnet: "10.244.0.0/16"
    serviceSubnet: 10.96.0.0/12

    # Add setting for change proxy mode to ipvs.
    ---
    apiVersion: kubeproxy.config.k8s.io/v1alpha1
    kind: KubeProxyConfiguration
    featureGates:
      SupportIPVSProxyMode: true
    mode: ipvs

    # Start initialize and save log to kubeadm-init.log
    $ kubeadm init --config=kubeadm-config.yaml | tee kubeadm-init.log

    # You can find the following commands in kubeadm-init.log and execute them.
    $ mkdir -p $HOME/.kube
    $ sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
    $ sudo chown $(id -u):$(id -g) $HOME/.kube/config

    # flannel installation
    $ kubectl apply -f https://raw.githubusercontent.com/coreos/flannel/master/Documentation/kube-flannel.yml

    ```

    ### Step 5 Join work-node to master-node
    You can find the <font color='red'> [kubeadm join] </font> command in kubeadm-init.log and execute it on the work-node.
    ```Shell
    $ kubeadm join 1.2.3.4:6443 --token xxxxxxx.xxxxxxxxxxxxxxxxxxx \
    --discovery-token-ca-cert-hash sha256:xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx 
    ```

    ### Step 6 Deploy the Intel SGX Device Plugin for Kubernetes
    Here we would want to deploy the plugin as a DaemonSet, so pull the source code. 
    ```Shell
    $ git clone https://github.com/intel/intel-device-plugins-for-kubernetes.git
    ```
    In the working directory, compile with
    ```Shell\
    $ make intel-sgx-plugin
    $ make intel-sgx-initcontainer
    ```
    Deploy the DaemonSet with
    ```Shell
    $ kubectl apply -k deployments/sgx_plugin/overlays/epc-register/
    ```
    Verify with (replace the <node name> with your own node name)
    ```Shell
    $ kubectl describe node <node name> | grep sgx.intel.com
    ```