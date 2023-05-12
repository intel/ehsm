ARG IMAGE_NAME_EHSM_BASE
ARG EHSM_VERSION_STR
ARG NODE_VERSION=v18.16.0

FROM $IMAGE_NAME_EHSM_BASE:$EHSM_VERSION_STR

COPY start_ehsm-kms.sh /home/
RUN chmod 744 /home/start_ehsm-kms.sh

# Install node & npm packages
RUN wget https://nodejs.org/dist/${NODE_VERSION}/node-${NODE_VERSION}-linux-x64.tar.xz \
    && tar xf node-${NODE_VERSION}-linux-x64.tar.xz \
    && rm -rf node-${NODE_VERSION}-linux-x64.tar.xz \
    && mv node-${NODE_VERSION}-linux-x64/ /usr/local/nodejs \
    && ln -s /usr/local/nodejs/bin/node /usr/local/bin \
    && ln -s /usr/local/nodejs/bin/npm /usr/local/bin


# Install ehsm-service dependence packages
WORKDIR /home/ehsm/ehsm_kms_service
RUN cp /home/ehsm/out/ehsm-core/libehsmprovider.so . \
    && cp /home/ehsm/out/ehsm-core/libenclave-ehsm-core.signed.so .
RUN npm install

# image port
EXPOSE 9000

# run ehsm_kms_service
CMD ["sh", "/home/start_ehsm-kms.sh"]
