### NFS Server installation
***
#### Step 1 Create NFS server
```Shell
# Installing NFS related packages
$ apt-get install nfs-kernel-server nfs-common

# Create a path for sharing
$ mkdir /nfs_ehsm_db

# Modify permissions
$ chmod 777 /nfs_ehsm_db
$ chown nfsnobody /nfs_ehsm_db
$ vim /etc/exports

/nfs_ehsm_db *(rw,no_root_squash,no_all_squash,sync) 

# Restart nfs service
$ /etc/init.d/rpcbind restart
$ /etc/init.d/nfs-kernel-server restart
```

#### Step 2 Configure other servers
Execute command on each kubernetes node
```Shell
# apt-get install nfs-common
```