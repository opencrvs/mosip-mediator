#! /bin/sh
set -e

print_usage_and_exit () {
    echo 'Usage: ./deploy.sh HOST ENV VERSION'
    echo "  ENV can be 'production' or 'development'"
    echo '  HOST is the server to deploy to'
    echo "  VERSION can be any docker image tag or 'latest'"
    exit 1
}

if [ -z "$1" ] ; then
    echo 'Error: Argument ENV is required in postition 1.'
    print_usage_and_exit
fi

if [ -z "$2" ] ; then
    echo 'Error: Argument HOST is required in postition 2.'
    print_usage_and_exit
fi

if [ -z "$3" ] ; then
    echo 'Error: Argument VERSION is required in postition 3.'
    print_usage_and_exit
fi

ENV=$1
HOST=$2
VERSION=$3
SSH_USER=${SSH_USER:-root}
SSH_HOST=${SSH_HOST:-$HOST}
LOG_LOCATION=${LOG_LOCATION:-/var/log}

echo
echo "Deploying version $VERSION to $SSH_HOST..."
echo

mkdir -p /tmp/compose/infrastructure

# Copy all infrastructure files to the server
rsync -rP docker-compose* infrastructure $SSH_USER@$SSH_HOST:/tmp/compose/

# Override configuration files
rsync -rP /tmp/compose/infrastructure $SSH_USER@$SSH_HOST:/tmp/compose

# Prepare docker-compose.deploy.yml and rotate secrets etc
if [[ "$ENV" = "development" ]]; then
    ssh $SSH_USER@$SSH_HOST '/tmp/compose/infrastructure/rotate-secrets.sh /tmp/compose/docker-compose.deploy.yml | tee -a '$LOG_LOCATION'/rotate-secrets.log'
else
    ssh $SSH_USER@$SSH_HOST '/tmp/compose/infrastructure/rotate-secrets.sh /tmp/compose/docker-compose.deploy.yml /tmp/compose/docker-compose.prod-deploy.yml | tee -a '$LOG_LOCATION'/rotate-secrets.log'
fi
# Setup configuration files and compose file for the deployment domain
ssh $SSH_USER@$SSH_HOST '/tmp/compose/infrastructure/setup-deploy-config.sh '$HOST' | tee -a '$LOG_LOCATION'/setup-deploy-config.log'

# Setup log rotation
ssh $SSH_USER@$SSH_HOST 'mv /tmp/compose/infrastructure/logrotate.conf /etc/'

# Deploy the stack onto the swarm
if [[ "$ENV" = "development" ]]; then
ssh $SSH_USER@$SSH_HOST 'cd /tmp/compose && VERSION='$VERSION' docker stack deploy -c docker-compose.yml -c docker-compose.deploy.yml --with-registry-auth mosip'
else
ssh $SSH_USER@$SSH_HOST 'cd /tmp/compose && VERSION='$VERSION' docker stack deploy -c docker-compose.yml -c docker-compose.deploy.yml -c docker-compose.prod-deploy.yml --with-registry-auth mosip'
fi

