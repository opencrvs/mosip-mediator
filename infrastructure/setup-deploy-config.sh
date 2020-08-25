set -e
echo
echo "Setting up deployment config for $1 - `date --iso-8601=ns`"

# Set hostname in traefik config
sed -i "s/{{hostname}}/$1/g" /tmp/compose/infrastructure/traefik.toml

# Set hostname in compose file
sed -i "s/{{hostname}}/$1/g" /tmp/compose/docker-compose.deploy.yml

echo "DONE - `date --iso-8601=ns`"
echo