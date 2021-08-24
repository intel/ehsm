------------------------
Purpose of DeployApp
------------------------
This App is using as a deploy service via INET SOCKET, to estabilish the trust secure
channel with Provisioning App based on the SGX remote attestation and EC-DH key exchange
protocols, also it will create the DomainKey per Provisioning App request after the trust
channel has been estabished successfully.


------------------------------------
How to Build/Execute the Sample Code
------------------------------------
1. Install Intel(R) SGX SDK for Linux* OS
2. Make sure your environment is set:
    $ source ${sgx-sdk-install-path}/environment
3. Build the project with the prepared Makefile:
    a. Hardware Mode, Debug build:
        $ make
    c. Hardware Mode, Release build:
        $ make SGX_DEBUG=0
    d. Simulation Mode, Debug build:
        $ make SGX_MODE=SIM
    f. Simulation Mode, Release build:
        $ make SGX_MODE=SIM SGX_DEBUG=0
4. Execute the binary directly:
    $ ./deploysrv
5. Remember to "make clean" before switching build mode
