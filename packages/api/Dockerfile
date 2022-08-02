FROM node:erbium-alpine

RUN apk add bash vim curl wireguard-tools
ENV WG_PEERS=''

WORKDIR /usr/src/app

# Override the base log level (info).
ENV NPM_CONFIG_LOGLEVEL warn

# Install npm dependencies first (so they may be cached if dependencies don't change)
COPY package.json package.json
COPY packages/api/package.json packages/api/package.json
COPY yarn.lock yarn.lock
RUN yarn install --production

# Copy package source
COPY --from=mosip-build packages/api/build packages/api/build

EXPOSE 4545
WORKDIR /usr/src/app/packages/api

CMD ["/bin/bash","-c","for wg_peer in ${WG_PEERS/,/\n}; do wg-quick up $wg_peer; done; yarn start:prod"]
