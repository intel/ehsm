ARG IMAGE_NAME_EHSM_BASE
ARG EHSM_VERSION_STR

FROM ${DOCKER_REPO}${DOCKER_REPO:+/}$IMAGE_NAME_EHSM_BASE:$EHSM_VERSION_STR

COPY start_dkeyserver.sh /home/
RUN chmod 744 /home/start_dkeyserver.sh 

# image port
EXPOSE 8888

# run ehsm-dkeyserver
WORKDIR /home/ehsm/out/ehsm-dkeyserver
CMD ["sh", "/home/start_dkeyserver.sh"]