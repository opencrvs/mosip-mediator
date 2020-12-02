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
