ARG IMAGE_NAME_EHSM_BASE
ARG EHSM_VERSION_STR

FROM ${DOCKER_REPO}${DOCKER_REPO:+/}$IMAGE_NAME_EHSM_BASE:$EHSM_VERSION_STR

COPY start_dkeycache.sh /home/
RUN chmod 744 /home/start_dkeycache.sh

# run ehsm-dkeycache
WORKDIR /home/ehsm/out/ehsm-dkeycache
#CMD ["./ehsm-dkeycache", "-i", "$DKEYSERVER_IP", "-p", "$DKEYSERVER_PORT"]
ENTRYPOINT ["sh","/home/start_dkeycache.sh"]