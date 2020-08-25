# This dockerfile only installs dependencies and build all packages
# It is used by each packages Dockerfile to copy out build artifacts
FROM node:erbium

# Make sure version variable is set
ARG VERSION
RUN test -n "$VERSION"

# Override the base log level (info).
ENV NPM_CONFIG_LOGLEVEL warn

# install dependencies first so they may be cached if there are no package.json changes
COPY package.json .
COPY yarn.lock .
COPY lerna.json .
COPY packages/api/package.json packages/api/package.json
RUN yarn install

COPY . .
ENV VERSION "$VERSION"
RUN yarn build
