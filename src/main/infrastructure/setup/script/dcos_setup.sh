#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default parameters.
DEBUG=false
DEBUG_OPT=
RUN_TERRAFORM=true
CPU_HARD_LIMIT=false
UPDATE_ZONE_REGION=false
UPDATE_MESOS_ATTRIBUTES_FROM_TAGS=false
DO_NOT_UPDATE_SWAP=true
MASTERS_SWAP=0
AGENTS_SWAP=0
CONFIGURE_NVME_MAPPING=false
CONFIGURE_ULIMIT=false
CONFIGURE_SYSCTL=false
CONFIGURE_PROMETHEUS=false
CONFIGURE_DOCKER=false
CONFIGURE_AGENTS=true
CONFIGURE_MASTERS=true
RESTART_AGENTS=false
RESTART_AGENTS_HARD=false
STOP_BOOTSTRAP=true
YUM_NOT_UPDATE=true
INIT=false
UPGRADE=
PLAN=false
UPDATE=false
APPLY=false
DESTROY=false
DESTROY_CONFIRM=false
UPDATE_GROUP_TAG="Update-mesos-attributes"
PLACEMENT_PREFIX="placement-"
HUGE_PAGES_PERCENTAGE=0

# For each parameter.
while :; do
	case ${1} in
		
		# Debug parameter.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			TF_LOG=DEBUG
			export TF_LOG
			;;
			
		# If DCOS terraform should run.
		--skip-terraform)
			RUN_TERRAFORM=false
			;;
			
		# If CPU hard limit should be used.
		--cpu-hard-limit)
			CPU_HARD_LIMIT=true
			;;
			
		# If masters configuration should be skiped.
		--skip-masters)
			CONFIGURE_MASTERS=false
			;;
			
		# If agents configuration should be skiped.
		--skip-agents)
			CONFIGURE_AGENTS=false
			;;
			
		# If swap should not be updated.
		--update-swap)
			DO_NOT_UPDATE_SWAP=false
			;;
	
		# Masters swap.
		--masters-swap)
			MASTERS_SWAP=${2}
			shift
			;;

		# Agents swap.
		--agents-swap)
			AGENTS_SWAP=${2}
			shift
			;;

		# Huge pages.			
		--huge-pages)
			HUGE_PAGES_PERCENTAGE=${2}
			shift
			;;

		# If docker should be configured.
		--configure-docker)
			CONFIGURE_DOCKER=true
			;;

		# If Prometheus should be configured.
		--configure-prometheus)
			CONFIGURE_PROMETHEUS=true
			;;

		# If NVME config should be configured
		--configure-nvme)
			CONFIGURE_NVME_MAPPING=true
			;;

		# If ulimit should be configured.
		--configure-ulimit)
			CONFIGURE_ULIMIT=true
			;;

		# If sysctl should be configured.
		--configure-sysctl)
			CONFIGURE_SYSCTL=true
			;;

		# If zone and region should be updated.
		--update-zone-region)
			UPDATE_ZONE_REGION=true
			;;
			
		# If mesos attributes should be updated.
		--update-mesos-attributes)
			UPDATE_MESOS_ATTRIBUTES_FROM_TAGS=true
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
			
		# Yum update.
		--yum-update)
			YUM_NOT_UPDATE=false
			;;

		# Init terraform.
		--init)
			INIT=true
			;;

		# Upgrade terraform.
		--upgrade)
			UPGRADE=-upgrade
			;;

		# Plan terraform.
		--plan)
			PLAN=true
			;;

		# Update cluster.
		--update)
			UPDATE=true
			;;

		# Apply cluster.
		--apply)
			APPLY=true
			;;

		# Destroy cluster.
		--destroy)
			DESTROY=true
			;;

		# Destroy cluster.
		--destroy-confirm)
			DESTROY_CONFIRM=true
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
${DEBUG} && echo "RUN_TERRAFORM=${RUN_TERRAFORM}"
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

# If the cluster should be destroyed.
if ${DESTROY_CONFIRM} && ${DESTROY}
then

	# Destroys the cluster.
	${DEBUG} && ${INIT} && echo "terraform init ${UPGRADE}"
	${INIT} && terraform init ${UPGRADE}
	${DEBUG} && echo "Destroying cluster"
	terraform destroy -auto-approve
	exit

fi

# If terraform should run.
if ${RUN_TERRAFORM}
then

	# Starts the bootstrap.
	${DEBUG} && echo "Stopping bootstrap instance"
	${DEBUG} && echo "BOOTSTRAP_INSTANCE=${BOOTSTRAP_INSTANCE}"
	aws ec2 start-instances --region ${AWS_DEFAULT_REGION} --instance-ids ${BOOTSTRAP_INSTANCE} || true

	# Executes the terraform script.
	${DEBUG} && ${INIT} && echo "terraform init ${UPGRADE}"
	${INIT} && terraform init ${UPGRADE}
	${DEBUG} && ${UPDATE} && echo "terraform get -update"
	${UPDATE} && terraform get -update
	${DEBUG} && ${PLAN} && echo "terraform plan -out=create_dcos_cluster.out"
	${PLAN} && terraform plan -out=create_dcos_cluster.out
	${DEBUG} && echo "terraform apply -no-color create_dcos_cluster.out | tee /project/dcos_setup.log"
	terraform apply -no-color create_dcos_cluster.out | tee /project/dcos_setup.log

	# Gets the cluster config.
	${DEBUG} && echo "Updating DCOS config variables"
	CLUSTER_ADDRESS=`cat /project/dcos_setup.log | \
		grep "cluster-address = " | \
		sed -e "s/cluster-address = //" -e 's/"//g'`
	PUBLIC_ADDRESS=`cat /project/dcos_setup.log | \
		grep "public-agents-loadbalancer = " | \
		sed -e 's/public-agents-loadbalancer = //' -e 's/"//g'`
	AGENT_INSTANCES=`sed -n -e '/private-agents-instances = \[/,/\]/p' dcos_setup.log | 
		sed -e 's/private-agents-instances = \[//' -e 's/\]//' -e 's/"//g'`
	AGENT_INSTANCES="${AGENT_INSTANCES},
	$(sed -n -e '/public-agents-instances = \[/,/\]/p' dcos_setup.log | 
		sed -e 's/public-agents-instances = \[//' -e 's/\]//' -e 's/\"//g')"
	AGENT_INSTANCES=`echo ${AGENT_INSTANCES} | sed -e 's/ //g' -e 's/,/\\,/g' -e 's/"//g'`	
	MASTERS_IPS=`sed -n -e '/masters-ips = \[/,/\]/p' dcos_setup.log | 
		sed -e 's/masters-ips = \[//' -e 's/\]//' `
	MASTERS_IPS=`echo ${MASTERS_IPS} | sed -e 's/ //g' -e 's/,/\\,/g' -e 's/"//g'`	
	BOOTSTRAP_INSTANCE=`cat /project/dcos_setup.log | \
		grep "bootstrap-instance = " | \
		sed -e "s/bootstrap-instance = //" -e 's/"//g'`
	
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

# If agents should be configured.
if ${CONFIGURE_AGENTS}
then

	# For each agent instance.
	${DEBUG} && echo "AGENT_INSTANCES=${AGENT_INSTANCES}"
	AGENT_INSTANCES=`echo ${AGENT_INSTANCES} | sed -e "s/,/\n/g"`
	for AGENT_INSTANCE in ${AGENT_INSTANCES}
	do
	
		${DEBUG} && echo "AGENT_INSTANCE=${AGENT_INSTANCE}"
		AGENT_INSTANCE_NAME=`aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} | grep -A 1 "\"Key\": \"Name\""`
		AGENT_INSTANCE_NAME=`echo ${AGENT_INSTANCE_NAME} | sed -e "s/.*dcos/dcos/g" -e "s/\"$//"`
		${DEBUG} && echo "AGENT_INSTANCE_NAME=${AGENT_INSTANCE_NAME}"
		AGENT_INSTANCE_AZ=`aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
		--query 'Reservations[0].Instances[0].Placement.AvailabilityZone'`
		AGENT_INSTANCE_AZ=${AGENT_INSTANCE_AZ//\"}
		${DEBUG} && echo "AGENT_INSTANCE_AZ=${AGENT_INSTANCE_AZ}"
		AGENT_IP=`aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
		--query 'Reservations[0].Instances[0].PublicIpAddress'`
		AGENT_IP=${AGENT_IP//\"}
		${DEBUG} && echo "AGENT_IP=${AGENT_IP}"

		# Get placement tags
		USE_PLACEMENT_TAGS=false
		if ${UPDATE_MESOS_ATTRIBUTES_FROM_TAGS}
		then
			GROUP=
			INSTANCE_TAGS=$(aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
			--query "Reservations[].Instances[].Tags[].Key[]" --output text)
			${DEBUG} && echo "INSTANCE_TAGS=${INSTANCE_TAGS}"
			if echo ${INSTANCE_TAGS} | grep -w ${UPDATE_GROUP_TAG};
			then
				USE_PLACEMENT_TAGS=true
				for INSTANCE_TAG in $INSTANCE_TAGS; do
					if echo $INSTANCE_TAG | tr '[:upper:]' '[:lower:]' | grep -s "^$PLACEMENT_PREFIX";
					then
						TAG_VALUE=$(aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
						--query "Reservations[].Instances[].Tags[?Key=='$INSTANCE_TAG'].Value[]" --output text)
						GROUP_KEY=$(echo $INSTANCE_TAG| tr '[:upper:]' '[:lower:]' | sed -e "s/$PLACEMENT_PREFIX//")
						GROUP="$GROUP_KEY:$TAG_VALUE;$GROUP"
					fi
				done
				GROUP=$(echo $GROUP | tr '[:upper:]' '[:lower:]')
				${DEBUG} && echo "Groups: $GROUP"
			fi
		fi
		
		if (ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} "ls" || false)
		then
		
			# Mesos agent configuration file.
			AGENT_CONFIGURATION_FILE="/var/lib/dcos/mesos-slave-common"
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
			
			# If the agent is public.
			PUBLIC_AGENT=false
			if ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} \
				"sudo systemctl list-unit-files | grep dcos-mesos-slave-public"
			then
				PUBLIC_AGENT=true
			fi
			
			# Yum update.
			${DEBUG} && echo "Updating yum for agent ${AGENT_IP}"
			${YUM_NOT_UPDATE} || \
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} \
			"
                echo "sudo yum update -y --exclude=docker* --exclude=container*" && \
                sudo yum update -y --exclude=docker* --exclude=container*
            "
		
            # Configures the swap.
            ${DEBUG} && echo "Configuring swap for agent ${AGENT_IP}"
            if ! ${DO_NOT_UPDATE_SWAP}
            then
                if [ ! -z "${AGENTS_SWAP}" ] && [ "${AGENTS_SWAP}" -gt "0" ]
                then
                
                   ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
                   centos@${AGENT_IP} \
                   "( ( sudo swapon -s | grep /swapfile ) ) || \
                       ( \
                           ( sudo swapoff -v /swapfile || true ) && \
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

                else 
               
                   ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
                   centos@${AGENT_IP} \
                   "
                       sudo swapoff -a && \
                       sudo rm -f /swapfile && \
                       sudo cp -f /etc/fstab /etc/fstab.swap.bkp 
                       sudo sed '/swapfile/d' /etc/fstab | sudo tee /etc/fstab
                   "
                
                fi
           
            fi
			
			
			# If docker should be configured.
			if ${CONFIGURE_DOCKER}
			then
			
				# Configures the docker as non-root.
				${DEBUG} && echo "Configuring Docker as non-root for agent ${AGENT_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key centos@${AGENT_IP} \
				'sudo usermod -aG docker $USER || true'
			
				# Puts the DCOS properties into context.
				. /project/dcos_cli.properties
				
				# Prepares the docker config.
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} \
						"sudo rm -f /etc/docker/daemon.json && \
							rm -f /home/centos/.docker/config.json"
				
				
				# For each docker repository.
				if [ ! -z "${DOCKER_INSECURE_REPOSITORIES}" ]
				then
					# Configures insecure repositories.
					${DEBUG} && echo "Logging docker in the repository."
					ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
						centos@${AGENT_IP} \
						"echo '{ \"insecure-registries\": [ ${DOCKER_INSECURE_REPOSITORIES} ] }' | sudo tee /etc/docker/daemon.json && \
							cat /etc/docker/daemon.json" || true
				fi
				for DOCKER_REPOSITORY in $(echo ${DOCKER_REPOSITORIES} | sed -e 's/,/\n/g')
				do
					# Logs docker in the repository.
					${DEBUG} && echo "Logging docker in the repository."
					ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
						centos@${AGENT_IP} \
						"sudo mkdir -p /etc/docker/certs.d/${DOCKER_REPOSITORY}/ && \
							sudo rm -f /etc/docker/certs.d/${DOCKER_REPOSITORY}/* && \
							(echo -n | openssl s_client -connect ${DOCKER_REPOSITORY}:443 -showcerts -servername ${DOCKER_REPOSITORY} | \
								sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee /etc/docker/certs.d/${DOCKER_REPOSITORY}/ca.crt) && \
							docker login -u ${DOCKER_USER} -p ${DOCKER_PASSWORD} ${DOCKER_REPOSITORY}" || true
				done
				
				# Finishes docker config.
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} \
						"cd ~ && tar -czf private-docker.tar.gz .docker && \
							sudo mv private-docker.tar.gz /etc/ && \
							rm -f /home/centos/.docker/config.json"
				
			fi
			
			# If the CPU soft limit is already set.
			${DEBUG} && echo "sudo cat ${AGENT_CONFIGURATION_FILE} | grep \"MESOS_CGROUPS_ENABLE_CFS\""
			if ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
				centos@${AGENT_IP} "sudo cat ${AGENT_CONFIGURATION_FILE} | grep \"MESOS_CGROUPS_ENABLE_CFS\""
			then
				# Sets CPU soft limit for the agent.
				${DEBUG} && echo "sudo sed -i \
					\"s/MESOS_CGROUPS_ENABLE_CFS=.*/MESOS_CGROUPS_ENABLE_CFS=${CPU_HARD_LIMIT}/\" \
					${AGENT_CONFIGURATION_FILE}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} "sudo sed -i \
					\"s/MESOS_CGROUPS_ENABLE_CFS=.*/MESOS_CGROUPS_ENABLE_CFS=${CPU_HARD_LIMIT}/\" \
					${AGENT_CONFIGURATION_FILE}"
			# If the CPU soft limit is not already set.
			else
				# Sets CPU soft limit for the agent.
				${DEBUG} && echo "echo \"MESOS_CGROUPS_ENABLE_CFS=${CPU_HARD_LIMIT}\" | \
					sudo tee -a ${AGENT_CONFIGURATION_FILE}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} "echo \"MESOS_CGROUPS_ENABLE_CFS=${CPU_HARD_LIMIT}\" | \
					sudo tee -a ${AGENT_CONFIGURATION_FILE}"
			fi
		
			${DEBUG} && ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} "cat ${AGENT_CONFIGURATION_FILE}"
			
			# If zone and region should be updated.
			if ${UPDATE_ZONE_REGION}
			then
			
				# Mesos attributes.
				MESOS_ATTRIBUTES="region:${AWS_DEFAULT_REGION};zone:${AGENT_INSTANCE_AZ};node:${AGENT_INSTANCE_NAME}"
				if ${PUBLIC_AGENT}
				then
					MESOS_ATTRIBUTES="${MESOS_ATTRIBUTES};public_ip:true"
				fi

				# If should use attributes from tags
				if ${USE_PLACEMENT_TAGS}
				then
					MESOS_ATTRIBUTES="region:${AWS_DEFAULT_REGION};node:${AGENT_INSTANCE_NAME};${GROUP}"
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
				
				${DEBUG} && ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
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
			
	
			# If sysctl should be configured.
			if ${CONFIGURE_SYSCTL}
			then
				# Define private instances huge pages
				TOTAL_MEM=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
				TOTAL_MEM=$(echo | awk "{ printf (\"%.f\", $TOTAL_MEM / 1024) }")
				HUGE_PAGE_SIZE=$(echo | awk "{ printf (\"%.f\", $TOTAL_MEM * 0.$HUGE_PAGES_PERCENTAGE) }")
				# No huge pages for public instances
				if ${PUBLIC_AGENT}
				then
					HUGE_PAGE_SIZE="0"
				fi
				${DEBUG} && echo "TOTAL_MEM=$TOTAL_MEM"
				${DEBUG} && echo "HUGE_PAGE_SIZE=$HUGE_PAGE_SIZE"
				# Configures prometheus.
				${DEBUG} && echo "Configuring sysctl.conf in agent node ${AGENT_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} "sudo /sbin/modprobe tcp_htcp && (sudo /sbin/modprobe tcp_bbr || true)"
				HUGE_PAGE_SIZE=${HUGE_PAGE_SIZE} envsubst </project/sysctl | ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} "sudo bash -c 'cat > /etc/sysctl.conf' && sudo sysctl -p"
			fi
			

			# If zone and region should be updated.
			if ${CONFIGURE_PROMETHEUS}
			then
				# Configures prometheus.
				${DEBUG} && echo "Configuring prometheus agents in agent node ${AGENT_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} \
					"sudo yum install wget -y; \
						wget https://github.com/prometheus/node_exporter/releases/download/v1.0.1/node_exporter-1.0.1.linux-amd64.tar.gz; \
						tar xvfz node_exporter-1.0.1.linux-amd64.tar.gz; \
						rm node_exporter-1.0.1.linux-amd64.tar.gz; \
						sudo cp node_exporter-1.0.1.linux-amd64/node_exporter /usr/local/bin/node_exporter; \
						sudo rm -rf node_exporter-1.0.1.linux-amd64; \
						sudo useradd --no-create-home node_exporter; \
						cd /etc/systemd/system; \
						sudo bash -c 'cat << 'EOF' > node-exporter.service
[Unit]
Description=Prometheus Node Exporter Service
After=network.target
StartLimitIntervalSec=0s
[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=always
RestartSec=30
ExecStart=/usr/local/bin/node_exporter
[Install]
WantedBy=multi-user.target
EOF'; \
						sudo systemctl stop node-exporter; \
						sudo systemctl daemon-reload; \
						sudo systemctl enable node-exporter; \
						sudo systemctl start node-exporter; \
						sudo systemctl status node-exporter;" || true
			fi

			# Configure to use newer instances
			if ${CONFIGURE_NVME_MAPPING}
			then
				if [ ${AGENT_INSTANCE_AZ} = "us-east-1a" ]
				then
					# To use newer ec2 instances
					NVME_CMD=$(base64 /opt/dcos-script/dcos_setup_nvme.sh)
					echo ${NVME_CMD} | ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} " base64 -d | sudo bash"
					
				else
					echo "Not applying to this region yet - ${AGENT_INSTANCE_AZ}"
				fi
			fi

			# If agents should restart.
			if ${RESTART_AGENTS}
			then
			
				# Reload agent configuration.
				${DEBUG} && echo "ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} \"sudo systemctl daemon-reload && \
					sudo rm -f /var/lib/mesos/slave/meta/slaves/latest\""
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} \
					"sudo systemctl daemon-reload && \
					sudo rm -f /var/lib/mesos/slave/meta/slaves/latest && \
					sudo systemctl daemon-reload"
			
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
		
		fi
	
	done
	
fi




# If masters should be configured.
if ${CONFIGURE_MASTERS}
then

	# For each master instance.
	${DEBUG} && echo "MASTERS_IPS=${MASTERS_IPS}"
	MASTERS_IPS=`echo ${MASTERS_IPS} | sed -e "s/,/\n/g"`
	for MASTER_IP in ${MASTERS_IPS}
	do
	
		${DEBUG} && echo "MASTER_IP=${MASTER_IP}"
		
		if ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${MASTER_IP} "ls"
		then
		
			# Yum update.
			${DEBUG} && echo "Updating yum for master ${MASTER_IP}"
			${YUM_NOT_UPDATE} || \
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${MASTER_IP} \
            "
                echo "sudo yum update -y --exclude=docker* --exclude=container*" && \
                sudo yum update -y --exclude=docker* --exclude=container*
            "

            # Configures the swap.
            ${DEBUG} && echo "Configuring swap for master ${MASTER_IP}"
            if ! ${DO_NOT_UPDATE_SWAP}
            then
                if [ ! -z "${MASTERS_SWAP}" ] && [ "${MASTERS_SWAP}" -gt "0" ]
                then
                
                   ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
                   centos@${MASTER_IP} \
                   "( ( sudo swapon -s | grep /swapfile ) ) || \
                       ( \
                           ( sudo swapoff -v /swapfile || true ) && \
                           sudo rm -f /swapfile && \
                           sudo dd if=/dev/zero of=/swapfile count=${MASTERS_SWAP} bs=1MiB && \
                           sudo chmod 600 /swapfile && \
                           sudo mkswap /swapfile && \
                           sudo swapon /swapfile && \
                           ( \
                               ( ${DEBUG} && sudo cat /etc/fstab ) &&
                               ( sudo cat /etc/fstab | grep /swapfile ) || \
                               ( echo \"/swapfile swap swap sw 0 0\" | sudo tee -a /etc/fstab ) \
                           )
                       )"

                else 
                
                   ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
                   centos@${MASTER_IP} \
                   "
                       sudo swapoff -a && \
                       sudo rm -f /swapfile && \
                       sudo cp -f /etc/fstab /etc/fstab.swap.bkp 
                       sudo sed '/swapfile/d' /etc/fstab | sudo tee /etc/fstab
                   "
               
                fi
           
            fi
			
				
			# If docker should be configured.
			if ${CONFIGURE_DOCKER}
			then
			
				# Configures the docker as non-root.
				${DEBUG} && echo "Configuring Docker as non-root for master ${MASTER_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key centos@${MASTER_IP} \
				'sudo usermod -aG docker $USER || true'
			
				# Puts the DCOS properties into context.
				. /project/dcos_cli.properties
				
				# For each docker repository.
				if [ ! -z "${DOCKER_INSECURE_REPOSITORIES}" ]
				then
					# Configures insecure repositories.
					${DEBUG} && echo "Logging docker in the repository."
					ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
						centos@${MASTER_IP} \
						"echo '{ \"insecure-registries\": [ ${DOCKER_INSECURE_REPOSITORIES} ] }' | sudo tee /etc/docker/daemon.json && \
							cat /etc/docker/daemon.json" || true
				fi
				for DOCKER_REPOSITORY in $(echo ${DOCKER_REPOSITORIES} | sed -e 's/,/\n/g')
				do
					# Logs docker in the repository.
					${DEBUG} && echo "Logging docker in the repository."
					ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
						centos@${MASTER_IP} \
						"sudo mkdir -p /etc/docker/certs.d/${DOCKER_REPOSITORY}/ && \
							sudo rm -f /etc/docker/certs.d/${DOCKER_REPOSITORY}/* && \
							(echo -n | openssl s_client -connect ${DOCKER_REPOSITORY}:443 -showcerts -servername ${DOCKER_REPOSITORY} | \
								sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' | sudo tee /etc/docker/certs.d/${DOCKER_REPOSITORY}/ca.crt) && \
							docker login -u ${DOCKER_USER} -p ${DOCKER_PASSWORD} ${DOCKER_REPOSITORY}" || true
				done
				
				# Finishes docker config.
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${MASTER_IP} \
						"cd ~ && tar -czf private-docker.tar.gz .docker && \
							sudo mv private-docker.tar.gz /etc/ && \
							rm -f /home/centos/.docker/config.json"
						
			
			fi
			
			
			# If sysctl should be configured.
			if ${CONFIGURE_SYSCTL}
			then
				TOTAL_MEM=$(awk '/MemTotal/ {print $2}' /proc/meminfo)
				TOTAL_MEM=$(echo | awk "{ printf (\"%.f\", $TOTAL_MEM / 1024) }")
				HUGE_PAGE_SIZE=$(echo | awk "{ printf (\"%.f\", $TOTAL_MEM * 0.$HUGE_PAGES_PERCENTAGE) }")
				${DEBUG} && echo "TOTAL_MEM=$TOTAL_MEM"
				${DEBUG} && echo "HUGE_PAGE_SIZE=$HUGE_PAGE_SIZE"
				# Configures prometheus.
				${DEBUG} && echo "Configuring sysctl.conf in agent node ${MASTER_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${MASTER_IP} "sudo /sbin/modprobe tcp_htcp && (sudo /sbin/modprobe tcp_bbr || true)"
				HUGE_PAGE_SIZE=${HUGE_PAGE_SIZE} envsubst </project/sysctl | ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${MASTER_IP} "sudo bash -c 'cat > /etc/sysctl.conf' && sudo sysctl -p"
			fi
			
			
			# If zone and region should be updated.
			if ${CONFIGURE_PROMETHEUS}
			then
				# Configures prometheus.
				${DEBUG} && echo "Configuring prometheus agents in master node ${MASTER_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${MASTER_IP} \
					"sudo yum install wget -y; \
						wget https://github.com/prometheus/node_exporter/releases/download/v1.0.1/node_exporter-1.0.1.linux-amd64.tar.gz; \
						tar xvfz node_exporter-1.0.1.linux-amd64.tar.gz; \
						rm node_exporter-1.0.1.linux-amd64.tar.gz; \
						sudo cp node_exporter-1.0.1.linux-amd64/node_exporter /usr/local/bin/node_exporter; \
						sudo rm -rf node_exporter-1.0.1.linux-amd64; \
						sudo useradd --no-create-home node_exporter; \
						cd /etc/systemd/system; \
						sudo bash -c 'cat << 'EOF' > node-exporter.service
[Unit]
Description=Prometheus Node Exporter Service
After=network.target
StartLimitIntervalSec=0s
[Service]
User=node_exporter
Group=node_exporter
Type=simple
Restart=always
RestartSec=30
ExecStart=/usr/local/bin/node_exporter
[Install]
WantedBy=multi-user.target
EOF'; \
						sudo systemctl stop node-exporter; \
						sudo systemctl daemon-reload; \
						sudo systemctl enable node-exporter; \
						sudo systemctl start node-exporter; \
						sudo systemctl status node-exporter;" || true
			fi
		
		fi

	done
	
fi

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


