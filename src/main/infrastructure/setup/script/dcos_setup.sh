#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
RUN_TERRAFORM=true
CPU_HARD_LIMIT=false
UPDATE_ZONE_REGION=false
DO_NOT_UPDATE_SWAP=true
MASTERS_SWAP=16000
AGENTS_SWAP=32000
CONFIGURE_SYSCTL=false
CONFIGURE_PROMETHEUS=false
CONFIGURE_DOCKER=false
CONFIGURE_AGENTS=true
CONFIGURE_MASTERS=true
RESTART_AGENTS=false
RESTART_AGENTS_HARD=false
STOP_BOOTSTRAP=true
INIT=false
UPGRADE=
PLAN=false
UPDATE=false
APPLY=false
DESTROY=false
DESTROY_CONFIRM=false

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

		# If docker should be configured.
		--configure-docker)
			CONFIGURE_DOCKER=true
			;;

		# If Prometheus should be configured.
		--configure-prometheus)
			CONFIGURE_PROMETHEUS=true
			;;

		# If sysctl should be configured.
		--configure-sysctl)
			CONFIGURE_SYSCTL=true
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
	`sed -n -e '/public-agents-instances = \[/,/\]/p' dcos_setup.log | 
		sed -e 's/public-agents-instances = \[//' -e 's/\]//' -e 's/"//g'`"
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
		AGENT_INSTANCE_AZ=`aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
		--query 'Reservations[0].Instances[0].Placement.AvailabilityZone'`
		AGENT_INSTANCE_AZ=${AGENT_INSTANCE_AZ//\"}
		${DEBUG} && echo "AGENT_INSTANCE_AZ=${AGENT_INSTANCE_AZ}"
		AGENT_IP=`aws ec2 describe-instances --region ${AWS_DEFAULT_REGION} --instance-id ${AGENT_INSTANCE} \
		--query 'Reservations[0].Instances[0].PublicIpAddress'`
		AGENT_IP=${AGENT_IP//\"}
		${DEBUG} && echo "AGENT_IP=${AGENT_IP}"
		
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
		
			# Configures the swap.
			${DEBUG} && echo "Configuring swap for agent ${AGENT_IP}"
			${DO_NOT_UPDATE_SWAP} || \
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${AGENT_IP} \
			"( ( sudo swapon -s | grep /swapfile ) ) || \
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
				
				# Prepares the docker config.
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} \
						"sudo rm -f /etc/docker/daemon.json && \
							rm -f /home/centos/.docker/config.json"
				
				# For each docker repository.
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
			
	
			# If TCP should be configured.
			if ${CONFIGURE_SYSCTL}
			then
				# Configures prometheus.
				${DEBUG} && echo "Configuring sysctl.conf in agent node ${AGENT_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${AGENT_IP} \
					"sudo /sbin/modprobe tcp_htcp && \
						(sudo /sbin/modprobe tcp_bbr || true) && \
						sudo bash -c 'cat << 'EOF' > /etc/sysctl.conf
# Do less swapping
vm.swappiness = 30
vm.dirty_ratio = 30
vm.dirty_background_ratio = 5

# Use BBR TCP congestion control and set tcp_notsent_lowat to 16384 to ensure HTTP/2 prioritization works optimally
# Fall-back to htcp if bbr is unavailable (older kernels)
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
    
# For servers with tcp-heavy workloads, enable fq queue management scheduler (kernel > 3.12)
net.core.default_qdisc = fq

# Turn on the tcp_window_scaling
net.ipv4.tcp_window_scaling = 1

# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.udp_rmem_min = 16384
net.core.rmem_default = 262144
net.core.rmem_max = 16777216

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_wmem_min = 16384
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

# Increase number of incoming connections
net.core.somaxconn = 32768

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 16384
net.core.dev_weight = 64

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 65535

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
net.ipv4.tcp_max_tw_buckets = 1440000

# try to reuse time-wait connections, but dont recycle them (recycle can break clients behind NAT)
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1

# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
net.ipv4.tcp_max_orphans = 16384
net.ipv4.tcp_orphan_retries = 0

# Limit the maximum memory used to reassemble IP fragments (CVE-2018-5391)
net.ipv4.ipfrag_low_thresh = 196608
net.ipv6.ip6frag_low_thresh = 196608
net.ipv4.ipfrag_high_thresh = 262144
net.ipv6.ip6frag_high_thresh = 262144

# dont cache ssthresh from previous connection
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# Increase size of RPC datagram queue length
net.unix.max_dgram_qlen = 50

# Dont allow the arp table to become bigger than this
net.ipv4.neigh.default.gc_thresh3 = 2048

# Tell the gc when to become aggressive with arp table cleaning.
# Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
net.ipv4.neigh.default.gc_thresh2 = 1024

# Adjust where the gc will leave arp table alone - set to 32.
net.ipv4.neigh.default.gc_thresh1 = 32

# Adjust to arp table gc to clean-up more often
net.ipv4.neigh.default.gc_interval = 30

# Increase TCP queue length
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6

# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesnt work for you
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_reordering = 3

# How many times to retry killing an alive TCP connection
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_retries1 = 3

# Avoid falling back to slow start after a connection goes idle
# keeps our cwnd large with the keep alive connections (kernel > 3.6)
net.ipv4.tcp_slow_start_after_idle = 0

# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)
net.ipv4.tcp_fastopen = 3

# This will enusre that immediatly subsequent connections use the new values
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1

# MTU probing (jumbo frames)
net.ipv4.tcp_mtu_probing=1
EOF'; \
						sudo sysctl -p"
			fi
			
			# If zone and regio# Do less swapping
vm.swappiness = 30
vm.dirty_ratio = 30
vm.dirty_background_ratio = 5

n should be updated.
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

			# Configures the swap.
			${DEBUG} && echo "Configuring swap for master ${MASTER_IP}"
			${DO_NOT_UPDATE_SWAP} || \
			ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
			centos@${MASTER_IP} \
			"( ( sudo swapon -s | grep \"/swapfile\" ) ) || \
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
			
			
			# If TCP should be configured.
			if ${CONFIGURE_SYSCTL}
			then
				# Configures prometheus.
				${DEBUG} && echo "Configuring sysctl.conf in agent node ${AGENT_IP}"
				ssh -oStrictHostKeyChecking=no -i ~/.ssh/aws_dcos_cluster_key \
					centos@${MASTER_IP} \
					"sudo /sbin/modprobe tcp_htcp && \
						(sudo /sbin/modprobe tcp_bbr || true) && \
						sudo bash -c 'cat << 'EOF' > /etc/sysctl.conf
# Do less swapping
vm.swappiness = 30
vm.dirty_ratio = 30
vm.dirty_background_ratio = 5

# Use BBR TCP congestion control and set tcp_notsent_lowat to 16384 to ensure HTTP/2 prioritization works optimally
# Fall-back to htcp if bbr is unavailable (older kernels)
net.ipv4.tcp_congestion_control = htcp
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_notsent_lowat = 16384
    
# For servers with tcp-heavy workloads, enable fq queue management scheduler (kernel > 3.12)
net.core.default_qdisc = fq

# Turn on the tcp_window_scaling
net.ipv4.tcp_window_scaling = 1

# Increase the read-buffer space allocatable
net.ipv4.tcp_rmem = 8192 87380 16777216
net.ipv4.udp_rmem_min = 16384
net.core.rmem_default = 262144
net.core.rmem_max = 16777216

# Increase the write-buffer-space allocatable
net.ipv4.tcp_wmem = 8192 65536 16777216
net.ipv4.udp_wmem_min = 16384
net.core.wmem_default = 262144
net.core.wmem_max = 16777216

# Increase number of incoming connections
net.core.somaxconn = 32768

# Increase number of incoming connections backlog
net.core.netdev_max_backlog = 16384
net.core.dev_weight = 64

# Increase the maximum amount of option memory buffers
net.core.optmem_max = 65535

# Increase the tcp-time-wait buckets pool size to prevent simple DOS attacks
net.ipv4.tcp_max_tw_buckets = 1440000

# try to reuse time-wait connections, but dont recycle them (recycle can break clients behind NAT)
net.ipv4.tcp_tw_recycle = 0
net.ipv4.tcp_tw_reuse = 1

# Limit number of orphans, each orphan can eat up to 16M (max wmem) of unswappable memory
net.ipv4.tcp_max_orphans = 16384
net.ipv4.tcp_orphan_retries = 0

# Limit the maximum memory used to reassemble IP fragments (CVE-2018-5391)
net.ipv4.ipfrag_low_thresh = 196608
net.ipv6.ip6frag_low_thresh = 196608
net.ipv4.ipfrag_high_thresh = 262144
net.ipv6.ip6frag_high_thresh = 262144

# dont cache ssthresh from previous connection
net.ipv4.tcp_no_metrics_save = 1
net.ipv4.tcp_moderate_rcvbuf = 1

# Increase size of RPC datagram queue length
net.unix.max_dgram_qlen = 50

# Dont allow the arp table to become bigger than this
net.ipv4.neigh.default.gc_thresh3 = 2048

# Tell the gc when to become aggressive with arp table cleaning.
# Adjust this based on size of the LAN. 1024 is suitable for most /24 networks
net.ipv4.neigh.default.gc_thresh2 = 1024

# Adjust where the gc will leave arp table alone - set to 32.
net.ipv4.neigh.default.gc_thresh1 = 32

# Adjust to arp table gc to clean-up more often
net.ipv4.neigh.default.gc_interval = 30

# Increase TCP queue length
net.ipv4.neigh.default.proxy_qlen = 96
net.ipv4.neigh.default.unres_qlen = 6

# Enable Explicit Congestion Notification (RFC 3168), disable it if it doesnt work for you
net.ipv4.tcp_ecn = 1
net.ipv4.tcp_reordering = 3

# How many times to retry killing an alive TCP connection
net.ipv4.tcp_retries2 = 15
net.ipv4.tcp_retries1 = 3

# Avoid falling back to slow start after a connection goes idle
# keeps our cwnd large with the keep alive connections (kernel > 3.6)
net.ipv4.tcp_slow_start_after_idle = 0

# Allow the TCP fastopen flag to be used, beware some firewalls do not like TFO! (kernel > 3.7)
net.ipv4.tcp_fastopen = 3

# This will enusre that immediatly subsequent connections use the new values
net.ipv4.route.flush = 1
net.ipv6.route.flush = 1

# MTU probing (jumbo frames)
net.ipv4.tcp_mtu_probing=1
EOF'; \
						sudo sysctl -p"
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


