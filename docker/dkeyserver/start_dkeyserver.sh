#!/bin sh
echo '# PCCS server address' > /etc/sgx_default_qcnl.conf
echo 'PCCS_URL='${PCCS_URL}'/sgx/certification/v4/' >> /etc/sgx_default_qcnl.conf
echo '# To accept insecure HTTPS certificate, set this option to FALSE' >> /etc/sgx_default_qcnl.conf
echo 'USE_SECURE_CERT=FALSE' >> /etc/sgx_default_qcnl.conf

start_cmd="/home/ehsm/out/ehsm-dkeyserver/ehsm-dkeyserver -r ${DKEYSERVER_ROLE}"
if [ ${TARGET_IP} ]; then
   start_cmd="/home/ehsm/out/ehsm-dkeyserver/ehsm-dkeyserver -r ${DKEYSERVER_ROLE}  -i ${TARGET_IP} -p ${TARGET_PORT}"
elif [ ${TARGET_URL} ]; then
   start_cmd="/home/ehsm/out/ehsm-dkeyserver/ehsm-dkeyserver -r ${DKEYSERVER_ROLE}  -u ${TARGET_URL} -p ${TARGET_PORT}"
fi
echo $start_cmd
sh -c "$start_cmd"