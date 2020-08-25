set -e

echo "$DOCKER_PASSWORD" | docker login -u "$DOCKER_USERNAME" --password-stdin
./node_modules/.bin/ts-node rebuild-only-changed-images.ts
yarn global add wait-on
yarn dev:secrets:gen
docker swarm init
yarn build:image && docker-compose --verbose -p mosip -f docker-compose.yml && echo "wait-on http://localhost:3000" && wait-on -l http://localhost:3000
yarn install
# yarn db:backup:restore
yarn e2e --record false