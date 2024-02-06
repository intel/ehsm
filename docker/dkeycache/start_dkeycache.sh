#!/bin sh
echo '# PCCS server address' > /etc/sgx_default_qcnl.conf
echo 'PCCS_URL='${PCCS_URL}'/sgx/certification/v4/' >> /etc/sgx_default_qcnl.conf
echo '# To accept insecure HTTPS certificate, set this option to FALSE' >> /etc/sgx_default_qcnl.conf
echo 'USE_SECURE_CERT=FALSE' >> /etc/sgx_default_qcnl.conf

sh -c "/home/ehsm/out/ehsm-dkeycache/ehsm-dkeycache -i ${DKEYSERVER_IP} -p ${DKEYSERVER_PORT}"