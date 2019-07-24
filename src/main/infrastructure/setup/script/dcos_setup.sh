#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
RUN_TERRAFORM=true
UPDATE_ZONE_REGION=false
DO_NOT_UPDATE_SWAP=true
MASTERS_SWAP=24576
AGENTS_SWAP=24576
CONFIGURE_DOCKER=false
RESTART_AGENTS=false
RESTART_AGENTS_HARD=false
STOP_BOOTSTRAP=true

# For each parameter.
while :; do
	case ${1} in
		
		# Debug parameter.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;
			
		# If DCOS terraform should run.
		--skip-terraform)
			RUN_TERRAFORM=false
			;;
			
		# If swap should not be updated.
		--update-swap)
			DO_NOT_UPDATE_SWAP=false
			;;

		# If docker should be configured.
		--configure-docker)
			CONFIGURE_DOCKER=true
			;;

		# If zone and region should be updated.
		--update-zone-region)
			UPDATE_ZONE_REGION=true
			;;

		# If agents should restart.
		--restart-agents)
			RESTART_AGENTS=true
			;;

		# If agents should restart.
		--restart-agents-hard)
			RESTART_AGENTS=true
			RESTART_AGENTS_HARD=true
			;;
			
		# Keep bootstrap parameter.
		--keep-bootstrap)
			STOP_BOOTSTRAP=false
			;;

		# No more options.
		*)
			break

	esac 
	shift
done

# Using unavaialble variables should fail the script.
set -o nounset

# Enables interruption signal handling.
trap - INT TERM

# Print parameters if on debug mode.
${DEBUG} && echo "Running 'dcos_setup'"
${DEBUG} && echo "UPDATE_ZONE_REGION=${UPDATE_ZONE_REGION}"
${DEBUG} && echo "DO_NOT_UPDATE_SWAP=${DO_NOT_UPDATE_SWAP}"
${DEBUG} && echo "CONFIGURE_DOCKER=${CONFIGURE_DOCKER}"
${DEBUG} && echo "MASTERS_SWAP=${MASTERS_SWAP}"
${DEBUG} && echo "AGENTS_SWAP=${AGENTS_SWAP}"
${DEBUG} && echo "RESTART_AGENTS=${RESTART_AGENTS}"
${DEBUG} && echo "RESTART_AGENTS_HARD=${RESTART_AGENTS_HARD}"
${DEBUG} && echo "STOP_BOOTSTRAP=${STOP_BOOTSTRAP}"

# Adds the AWS key.
${DEBUG} && echo "Adding AWS SSH key"
mkdir -p ~/.ssh
cp /project/aws_dcos_cluster_key ~/.ssh/aws_dcos_cluster_key
cp /project/aws_dcos_cluster_key.pub ~/.ssh/aws_dcos_cluster_key.pub
eval `ssh-agent -s` && \
ssh-add ~/.ssh/aws_dcos_cluster_key

# Puts the AWS basic config available to the scripts.
${DEBUG} && echo "Exporting AWS config variables"
. /project/aws_basic_config.properties
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_DEFAULT_REGION

. /project/dcos_cli.properties

# If terraform should run.
if ${RUN_TERRAFORM}
then

	# Starts the bootstrap.
	${DEBUG} && echo "Stopping bootstrap instance"
	${DEBUG} && echo "BOOTSTRAP_INSTANCE=${BOOTSTRAP_INSTANCE}"
	aws ec2 start-instances --region ${AWS_DEFAULT_REGION} --instance-ids ${BOOTSTRAP_INSTANCE} || true

	# Executes the terraform script.
	${DEBUG} && echo "terraform init
	terraform plan -out=create_dcos_cluster.out
	terraform apply create_dcos_cluster.out"
	terraform init
	terraform plan -out=create_dcos_cluster.out
	terraform apply -no-color create_dcos_cluster.out | tee /project/dcos_setup.log

	# Gets the cluster config.
	${DEBUG} && echo "Updating DCOS config variables"
	CLUSTER_ADDRESS=`cat /project/dcos_setup.log | \
		grep "cluster-address = " | \
		sed "s/cluster-address = //"`
	PUBLIC_ADDRESS=`cat /project/dcos_setup.log | \
		grep "public-agents-loadbalancer = " | \
		sed "s/public-agents-loadbalancer = //"`
	AGENT_INSTANCES=`sed -n -e '/private-agents-instances = \[/,/\]/p' dcos_setup.log | 
		sed -e 's/private-agents-instances = \[//' -e 's/\]//'`
	AGENT_INSTANCES="${AGENT_INSTANCES},
	`sed -n -e '/public-agents-instances = \[/,/\]/p' dcos_setup.log | 
		sed -e 's/public-agents-instances = \[//' -e 's/\]//'`"
	AGENT_INSTANCES=`echo ${AGENT_INSTANCES} | sed -e 's/ //g'`	
	AGENT_INSTANCES=`echo ${AGENT_INSTANCES} | sed -e 's/,/\\,/g'`	
	MASTERS_IPS=`sed -n -e '/masters-ips = \[/,/\]/p' dcos_setup.log | 
		sed -e 's/masters-ips = \[//' -e 's/\]//' `
	MASTERS_IPS=`echo ${MASTERS_IPS} | sed -e 's/ //g'`	
	MASTERS_IPS=`echo ${MASTERS_IPS} | sed -e 's/,/\\,/g'`	
	BOOTSTRAP_INSTANCE=`cat /project/dcos_setup.log | \
		grep "bootstrap-instance = " | \
		sed "s/bootstrap-instance = //"`
	
	# If the cluster address cannot be retrieved.
	if [ -z "${CLUSTER_ADDRESS}" ] || \
	[ -z "${PUBLIC_ADDRESS}" ] || \
	[ -z "${BOOTSTRAP_INSTANCE}" ] 
	then
		# Exits.
		exit "Error creating cluster"
	fi

	# Updates the cluster config.
	sed -i "s/CLUSTER_ADDRESS=.*/CLUSTER_ADDRESS=${CLUSTER_ADDRESS}/" /project/dcos_cli.properties
	sed -i "s/PUBLIC_ADDRESS=.*/PUBLIC_ADDRESS=${PUBLIC_ADDRESS}/" /project/dcos_cli.properties
	sed -i "s/AGENT_INSTANCES=.*/AGENT_INSTANCES=${AGENT_INSTANCES}/" /project/dcos_cli.properties
	sed -i "s/MASTERS_IPS=.*/MASTERS_IPS=${MASTERS_IPS}/" /project/dcos_cli.properties
	sed -i "s/BOOTSTRAP_INSTANCE=.*/BOOTSTRAP_INSTANCE=${BOOTSTRAP_INSTANCE}/" /project/dcos_cli.properties

fi

# For each agent instance.
${DEBUG} && echo "AGENT_INSTANCES=${AGENT_INSTANCES}"
AGENT_INSTANCES=`echo ${AGENT_INSTANCES} | sed -e "s/,/\n/g"`
for AGENT_INSTANCE in ${AGENT_INSTANCES}
do

	${DEBUG} && echo "AGENT_INSTANCE=${AGENT_INSTANCE}"
	AGENT_INSTANCE_AZ=`aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
	--query 'Reservations[0].Instances[0].Placement.AvailabilityZone'`
	AGENT_INSTANCE_AZ=${AGENT_INSTANCE_AZ//\"}
	${DEBUG} && echo "AGENT_INSTANCE_AZ=${AGENT_INSTANCE_AZ}"
	AGENT_IP=`aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
	--query 'Reservations[0].Instances[0].PublicIpAddress'`
	AGENT_IP=${AGENT_IP//\"}
	${DEBUG} && echo "AGENT_IP=${AGENT_IP}"
	
	# If the agent is public.
	PUBLIC_AGENT=false
	if ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
		centos@${AGENT_IP} \
		"sudo systemctl list-unit-files | grep dcos-mesos-slave-public"
	then
		PUBLIC_AGENT=true
	fi

	# Configures the swap.
	${DEBUG} && echo "Configuring swap for agent ${AGENT_IP}"
	${DO_NOT_UPDATE_SWAP} || \
	ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
	centos@${AGENT_IP} \
	"( ( swapon -s | grep \"/swapfile\" ) ) || \
		( \
			sudo swapoff -v /swapfile || true && \
			sudo rm -f /swapfile && \
			sudo dd if=/dev/zero of=/swapfile count=${AGENTS_SWAP} bs=1MiB && \
			sudo chmod 600 /swapfile && \
			sudo mkswap /swapfile && \
			sudo swapon /swapfile && \
			( \
				( ${DEBUG} && sudo cat /etc/fstab ) &&
				( sudo cat /etc/fstab | grep /swapfile ) || \
				( echo \"/swapfile swap swap sw 0 0\" | sudo tee -a /etc/fstab ) \
			)
		)"
	
	# If docker should be configured.
	if ${CONFIGURE_DOCKER}
	then
	
		# Configures the docker as non-root.
		${DEBUG} && echo "Configuring Docker as non-root for agent ${AGENT_IP}"
		ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key centos@${AGENT_IP} \
		'sudo usermod -aG docker $USER || true'
	
		# Puts the DCOS properties into context.
		. /project/dcos_cli.properties
		
		# Logs docker in the repository.
		${DEBUG} && echo "Logging docker in the repository."
		ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} \
			"rm -f /home/centos/.docker/config.json && \
				docker login -u ${DOCKER_USER} -p ${DOCKER_PASSWORD} ${DOCKER_REPOSITORY} && \
				cd ~ && tar -czf private-docker.tar.gz .docker && \
				sudo mv private-docker.tar.gz /etc/ && \
				rm -f /home/centos/.docker/config.json"
	
	fi
	
	# If zone and region should be updated.
	if ${UPDATE_ZONE_REGION}
	then
	
		# Mesos agent configuration file.
		AGENT_CONFIGURATION_FILE="/var/lib/dcos/mesos-slave-common"
#		ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
#			centos@${AGENT_IP} sudo rm -f ${AGENT_CONFIGURATION_FILE}
		# If the mesos configuration file does not exist.
		${DEBUG} && echo "sudo [ ! -f ${AGENT_CONFIGURATION_FILE} ]"
		if ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} sudo [ ! -f ${AGENT_CONFIGURATION_FILE} ]
		then
			# Creates the configuration file.
			${DEBUG} && echo "sudo touch ${AGENT_CONFIGURATION_FILE}"
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} sudo touch ${AGENT_CONFIGURATION_FILE}
		fi
		
		# Mesos attributes.
		MESOS_ATTRIBUTES="region:${AWS_DEFAULT_REGION};zone:${AGENT_INSTANCE_AZ}"
		if ${PUBLIC_AGENT}
		then
			MESOS_ATTRIBUTES="${MESOS_ATTRIBUTES};public_ip:true"
		fi
		
		# If the mesos attributes are already set.
		${DEBUG} && echo "sudo cat ${AGENT_CONFIGURATION_FILE} | grep \"MESOS_ATTRIBUTES\""
		if ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} "sudo cat ${AGENT_CONFIGURATION_FILE} | grep \"MESOS_ATTRIBUTES\""
		then
			# Sets the region and zone for the agent.
			${DEBUG} && echo "sudo sed -i \
				\"s/MESOS_ATTRIBUTES=.*/MESOS_ATTRIBUTES=${MESOS_ATTRIBUTES}/\" \
				${AGENT_CONFIGURATION_FILE}"
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} "sudo sed -i \
				\"s/MESOS_ATTRIBUTES=.*/MESOS_ATTRIBUTES=${MESOS_ATTRIBUTES}/\" \
				${AGENT_CONFIGURATION_FILE}"
		# If the mesos attributes are not already set.
		else
			# Sets the region and zone for the agent.
			${DEBUG} && echo "echo \"MESOS_ATTRIBUTES=${MESOS_ATTRIBUTES}\" | \
				sudo tee -a ${AGENT_CONFIGURATION_FILE}"
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} "echo \"MESOS_ATTRIBUTES=${MESOS_ATTRIBUTES}\" | \
				sudo tee -a ${AGENT_CONFIGURATION_FILE}"
		fi
		
		${DEBUG} && echo "echo \"cat ${AGENT_CONFIGURATION_FILE}"
		ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} "cat ${AGENT_CONFIGURATION_FILE}"
			
	fi

	# If AWS URL is still not blocked.
	${DEBUG} && echo "ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
		centos@${AGENT_IP} \
		\"sudo iptables -C OUTPUT -d 169.254.169.254 -p tcp -m multiport --dports 80,443 -j DROP || false\""
	if ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
		centos@${AGENT_IP} \
		"sudo iptables -C OUTPUT -d 169.254.169.254 -p tcp -m multiport --dports 80,443 -j DROP || false"
	then
		# Blocks the AWS URL.
		${DEBUG} && echo "ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} \
			\"sudo iptables -A OUTPUT -d 169.254.169.254 -p tcp -m multiport --dports 80,443 -j DROP\""
		ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} \
			"sudo iptables -A OUTPUT -d 169.254.169.254 -p tcp -m multiport --dports 80,443 -j DROP"
	fi

	# Reload agent configuration.
	${DEBUG} && echo "ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
		centos@${AGENT_IP} \"sudo systemctl daemon-reload && \
		sudo rm -f /var/lib/mesos/slave/meta/slaves/latest\""
	ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
		centos@${AGENT_IP} \
		"sudo systemctl daemon-reload && \
		sudo rm -f /var/lib/mesos/slave/meta/slaves/latest && \
		sudo systemctl daemon-reload"
	
	# If agents should restart.
	if ${RESTART_AGENTS}
	then
	
		# Agent service.
		AGENT_SERVICE="dcos-mesos-slave"
		if ${PUBLIC_AGENT}
		then
			AGENT_SERVICE="dcos-mesos-slave-public"
		fi
		
		# Restarts the agent.
		if ${RESTART_AGENTS_HARD}
		then
			${DEBUG} && echo "ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} sudo systemctl restart dcos-mesos-slave"
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} \
				sudo reboot || true
		else 
			${DEBUG} && echo "ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} sudo systemctl restart dcos-mesos-slave"
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} \
				sudo systemctl restart ${AGENT_SERVICE}
		fi
		
	fi

done

# For each master instance.
${DEBUG} && echo "MASTERS_IPS=${MASTERS_IPS}"
MASTERS_IPS=`echo ${MASTERS_IPS} | sed -e "s/,/\n/g"`
for MASTER_IP in ${MASTERS_IPS}
do

	${DEBUG} && echo "MASTER_IP=${MASTER_IP}"
	
	# Configures the swap.
	${DEBUG} && echo "Configuring swap for master ${MASTER_IP}"
	${DO_NOT_UPDATE_SWAP} || \
	ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
	centos@${MASTER_IP} \
	"( ( swapon -s | grep \"/swapfile\" ) ) || \
		( \
			sudo swapoff -v /swapfile || true && \
			sudo rm -f /swapfile && \
			sudo dd if=/dev/zero of=/swapfile count=${MASTERS_SWAP} bs=1MiB && \
			sudo chmod 600 /swapfile && \
			sudo mkswap /swapfile && \
			sudo swapon /swapfile && \
			( \
				( ${DEBUG} && sudo cat /etc/fstab ) &&
				( sudo cat /etc/fstab | grep /swapfile ) || \
				( echo \"/swapfile swap swap sw 0 0\" | sudo tee -a /etc/fstab ) \
			) \
		)"
		
	# If docker should be configured.
	if ${CONFIGURE_DOCKER}
	then
	
		# Configures the docker as non-root.
		${DEBUG} && echo "Configuring Docker as non-root for master ${MASTER_IP}"
		ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key centos@${MASTER_IP} \
		'sudo usermod -aG docker $USER || true'
	
		# Puts the DCOS properties into context.
		. /project/dcos_cli.properties
		
		# Logs docker in the repository.
		${DEBUG} && echo "Logging docker in the repository."
		ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${MASTER_IP} \
			"rm -f /home/centos/.docker/config.json && \
				docker login -u ${DOCKER_USER} -p ${DOCKER_PASSWORD} ${DOCKER_REPOSITORY} && \
				cd ~ && tar -czf private-docker.tar.gz .docker && \
				sudo mv private-docker.tar.gz /etc/ && \
				rm -f /home/centos/.docker/config.json"
	
	fi
		
done

# Stops the bootstrap.
if ${STOP_BOOTSTRAP}
then
	${DEBUG} && echo "Stopping bootstrap instance"
	BOOTSTRAP_INSTANCE=`cat /project/dcos_setup.log | \
		grep "bootstrap-instance = " | \
		sed "s/bootstrap-instance = //"`
	${DEBUG} && echo "BOOTSTRAP_INSTANCE=${BOOTSTRAP_INSTANCE}"
	aws ec2 stop-instances --region ${AWS_DEFAULT_REGION} --instance-ids ${BOOTSTRAP_INSTANCE}
else 
	${DEBUG} && echo "Bootstrap instance not stopped"
fi


