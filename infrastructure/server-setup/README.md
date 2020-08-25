# mosip server setup

This folder contains script to setup a new set of servers

Ansible is required to run the server setup. This should be installed on your local machine. Also ensure that you have ssh access with the root user to all the server that you are trying to configure.

Add your users GIT SSH keys to all nodes

```
curl https://github.com/<git-user>.keys >> ~/.ssh/authorized_keys
```

Ensure the manager node can ssh into worker nodes (Required for automated backups)

SSH into manager node and create ssh key. Press Enter for defaults and no passphrase

```
ssh-keygen
```

Print the key for copying:

```
cat ~/.ssh/id_rsa.pub
```

Copy the key and SSH into worker nodes to add manager key into node authorised keys, and repeat for all workers

```
echo "<manager-node-public-key>" >> ~/.ssh/authorized_keys
```

Run the Ansible playbook configuration script from your client computer (You must have Ansible installed, a Dockerhub account

```
ansible-playbook -i <inventory_file> playbook.yml -e "dockerhub_username=your_username dockerhub_password=your_password"
```

Replace <inventory_file> with the correct inventory file and use `-K` option if you need supply an ssh password (add ansible_password to inventory for each node). These files contain the list of servers which are to be configured. Use the `-b` option if your servers require sudo to perform the ansible tasks. If you are setting up a new set of servers, you will need to create a new file.

Before the deployment can be done a few secrets need to be manually added to the docker swarm:

ssh into the leader manager and run the following, replacing the values with the actual secrets:

```sh
# For AgileCRM
printf "Insert the value for AGILE_CRM_PASSWORD here" | docker secret create AGILE_CRM_PASSWORD -
printf "Insert the value for AGILE_CRM_URL here" | docker secret create AGILE_CRM_URL -
printf "Insert the value for AGILE_CRM_USER here" | docker secret create AGILE_CRM_USER -


# For WhatsApp
printf "Insert the value for WHATSAPP_ACCOUNT_SID here" | docker secret create WHATSAPP_ACCOUNT_SID -
printf "Insert the value for WHATSAPP_AUTH_TOKEN here" | docker secret create WHATSAPP_AUTH_TOKEN -
printf "Insert the value for WHATSAPP_SENDER_ID here" | docker secret create WHATSAPP_SENDER_ID -
```

After creating the secrets make sure the commands are removed from the shell history

Also, if you can't ssh into the manager as root you will need to add your ssh user to be able to run docker commands:

```
sudo groupadd docker
sudo usermod -aG docker $USER
```

Note: the Ansible script will install the UFW firewall, however, Docker manages it's own iptables. This means that even if there are UFW rules to block certain ports these will be overridden for ports where Docker is publishing a container port. Ensure only the necessary ports are published via the docker-compose files. Only the necessary ports are published by default, however, you may want to check this when doing security audits.

Synthetic records will need to be created, enabling SSL and permanently directing the following subdomains for the Traefik SSL cert to be succcessfully generated:

auth.<your_domain>
gateway.<your_domain>
client.<your_domain>

Now, in the package.json file in the root folder of the repository, amend the deployment script appropriately:

```
"deploy": "SSH_USER=<<your_ssh_username>> SSH_HOST=<<your_swarm_manager_node_ip>> bash deploy.sh",
```

Then, run the deployment like so:

```
yarn deploy <<insert host domain e.g.: sombabien.com>> <<insert version e.g.: latest>>
```

Version can be any git commit hash, git tag, dockerhub tag or 'latest'

## Enabling encryption

For production servers we offer the ability to setup an encrypted /data folder for the docker containers to use. This allows us to support encryption at rest. To do this run the ansible script with these extra variables. Note, if the server is already setup the docker stack must be stopped and ALL DATA WILL BE LOST when switching to an ecrypted folder. It is useful to set this up from the beginning.

```
ansible-playbook -i <inventory_file> playbook.yml -e "dockerhub_username=your_username dockerhub_password=your_password encrypt_passphrase=<a_strong_passphrase> encrypt_data=True"
```
