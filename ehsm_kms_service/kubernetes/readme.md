Step 1 Installing the NFS Server

    1. NFS server
    
        yum install -y nfs-common nfs-utils rpcbind
        mkdir /intel-ehsm-db
        chmod 777 /intel-ehsm-db
        chown nfsnobody /intel-ehsm-db
        
        cat > /etc/exports <<EOF 
        /intel-ehsm-db *(rw,no_root_squash,no_all_squash,sync) 
        EOF
        
        systemctl start rpcbind & systemctl enable rpcbind
        systemctl start nfs & systemctl enable nfs
        
    2. All Kubernetes node
    
        yum -y install nfs-utils recbind
    
    
Step 2 deploy Kubernetes

    ### kubectl apply namespace in order

        kubectl get namespace
        kubectl create namespace intel-ehsm
        
    ### kubectl apply commands in order

        kubectl apply -f ehsm-pv.yaml -n intel-ehsm
        kubectl apply -f ehsm-secret.yaml -n intel-ehsm
        kubectl apply -f ehsm-configmap.yaml -n intel-ehsm
        
        kubectl apply -f ehsm-db.yaml  -n intel-ehsm
            ### sub commands create database and user
                kubectl exec mongodb-0  -n intel-ehsm -it  -- /bin/sh
                mongo
                use admin
                db.auth("admin","password")
                use ehsmdb
                db.createUser(
                     {
                       user: "ehsm",
                       pwd: "password",
                       roles: ["readWrite"]
                     }
                )
                db.auth("ehsm","password")
                
        kubectl apply -f ehsm-kms.yaml -n intel-ehsm
        
    
    ### kubectl get commands

        kubectl get pv -n intel-ehsm
        kubectl get pvc -n intel-ehsm
        kubectl get sts -n intel-ehsm
        kubectl get pod -n intel-ehsm
        kubectl get pod -o wide -n intel-ehsm
        kubectl get deployment -n intel-ehsm
        kubectl get svc -n intel-ehsm
        kubectl get secret -n intel-ehsm
        kubectl get all -n intel-ehsm
    
    ### kubectl describe commands
    
        kubectl describe cm mongodb -n intel-ehsm
        kubectl describe svc mongodb -n intel-ehsm
        kubectl describe pod intel-ehsm-deployment-xxxxxx-xxx -n intel-ehsm
    
    ### kubectl exec commands
    
        kubectl exec mongodb-0  -n intel-ehsm -it  -- /bin/sh
        kubectl exec -it intel-ehsm-deployment-xxxxxx-xxx -n intel-ehsm -- /bin/sh
    
    ### kubectl network commands
        ipvsadm -Ln




    