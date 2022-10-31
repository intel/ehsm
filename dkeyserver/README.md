- If you need to synchronize the domain key between the host machine (the machine that has the domain key) and the backup machine (the machine that requests the domain key from the host machine), then you can compile first.
```bash
make
```
- In this way, the directory ehsm/out/ will be generated, and in this directory, there will be the following files
```bash
ehsm-core 
ehsm-dkeycache 
ehsm-dkeyserver 
ehsm-kms_enroll_app 
lib
```
- Enter the folder ehsm-dkeyserver, there will be the following file ehsm-dkeyserver
 ```bash
 libenclave-ehsm-dkeyserver.signed.so 
 libenclave-ehsm-dkeyserver.so
 ```
- On the host side, execute
```bash
./ehsm-dkeyserver
```
- on the backup machine, execute
```bash
./ehsm-dkeyserver -i 10.23.100.2 -p 8888
```
- -i is followed by the ip address of the host (10.23.100.2 is used here as an example), -p is the port number of the host, the default is 8888.
- If the following message is displayed
```bash
INFO [App/ra_getkey.cpp(454) -> start_getkey]: Successfully received the DomainKey from deploy server.
```
- It means that the domain key is successfully obtained on the backup machine. By default, the domain key is stored in the directory /etc/dkey.bin in encrypted form.
- It is worth mentioning that when the /etc/dkey.bin file already exists, when the backup machine continues to request the domain key from the host, the original dkey.bin file will be replaced by the new dkey.bin file and the following information is output on the screen
```bash
file already exist, substitute by new file
```
