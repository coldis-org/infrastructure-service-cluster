#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
WORK_DIRECTORY=.
SSH_USER=centos
USE_PRIVATE_IP=true
USE_SSH=false
SSH_ARGUMENTS=
EXTRA_ARGUMENTS=
COMMAND=
STD_IN=
STD_IN_TEMP_FILE=dcos_docker_exec_stdin.tmp

# For each parameter.
while :; do
	case ${1} in
		
		# If debug should be enabled.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;

		# If public IP should be used.
		--public-ip)
			USE_PRIVATE_IP=false
			;;
		
		# App id.
		-a|--app-id)
			APP_ID=${2}
			shift
			;;
			
		# If regular SSH should be used.
		--use-ssh)
			USE_SSH=true
			;;

		# SSH key.
		-k|--key)
			SSH_ARGUMENTS="${SSH_ARGUMENTS} --key ${2}"
			shift
			;;

		# Key checking desabled.
		--key-checking-disabled)
			SSH_ARGUMENTS="${SSH_ARGUMENTS} --key-checking-disabled"
			;;

		# If docker command should run as root.
		-r|--root)
			EXTRA_ARGUMENTS="${EXTRA_ARGUMENTS} -u root"
			;;

		# Extra arguments.
		-*)
			EXTRA_ARGUMENTS="${EXTRA_ARGUMENTS} ${1}"
			;;
			
		# Command.
		*)
			COMMAND="${@}"
			break

	esac 
	shift
done

# Reads from stdin.
rm -f ${STD_IN_TEMP_FILE}
touch ${STD_IN_TEMP_FILE}
if [ ! -t 0 ]
then
	while read LINE
	do
		USE_SSH=true
		STD_IN="${STD_IN}${LINE}\n"
		echo "${LINE}" >> ${STD_IN_TEMP_FILE}
	done
fi

# Using unavaialble variables should fail the script.
set -o nounset

# Enables interruption signal handling.
trap - INT TERM

# Print parameters if on debug mode.
${DEBUG} && echo "Running 'dcos_docker_exec'"
${DEBUG} && echo "APP_ID=${APP_ID}"
${DEBUG} && echo "SSH_ARGUMENTS=${SSH_ARGUMENTS}"
${DEBUG} && echo "EXTRA_ARGUMENTS=${EXTRA_ARGUMENTS}"
${DEBUG} && echo "COMMAND=${COMMAND}"
${DEBUG} && echo "STD_IN=$(cat ${STD_IN_TEMP_FILE})"

# Gets the agent information.
APP_INFO=$(dcos marathon app show ${APP_ID})
#${DEBUG} && echo "APP_INFO=${APP_INFO}"
APP_AGENT_ID=$(echo ${APP_INFO} | jq -r ".tasks[0].slaveId")
${DEBUG} && echo "APP_AGENT_ID=${APP_AGENT_ID}"
APP_TASK_ID=$(echo ${APP_INFO} | jq -r ".tasks[0].id")
${DEBUG} && echo "APP_TASK_ID=${APP_TASK_ID}"
APP_TASK_INFO=$(dcos task --json ${APP_TASK_ID})
#${DEBUG} && echo "APP_TASK_INFO=${APP_TASK_INFO}"
APP_CONTAINER_ID=mesos-`echo ${APP_TASK_INFO} | jq -r ".[0].statuses[] | \
	select(.state == \"TASK_RUNNING\") | \
	.container_status.container_id.value"`
${DEBUG} && echo "APP_CONTAINER_ID=${APP_CONTAINER_ID}"

AGENT_IP=
# If SSH should be used.
if ${USE_SSH}
then
	# If private IP should be used.
	if ${USE_PRIVATE_IP}
	then
		# Gets the agent IP.
		AGENT_IP=$(echo ${APP_INFO} | jq -r ".tasks[0].host")
	# If public IP should be used.
	else 
		# Gets the agent IP.
		AGENT_IP=`dcos node list --json | jq -r ".[] | \
			select(.id == \"${APP_AGENT_ID}\") | \
			.public_ips[0]"`
	fi
fi
${DEBUG} && echo "AGENT_IP=${AGENT_IP}"
IP_ADDRESS=$([ -z "${AGENT_IP}" ] && echo "" || echo "--ip ${AGENT_IP}")
${DEBUG} && echo "IP_ADDRESS=${IP_ADDRESS}"

# Runs the docker command.

# If there is no stdin.
if [ -z "${STD_IN}" ]
then 

	${DEBUG} && echo "Running 'dcos_ssh ${DEBUG_OPT} ${SSH_ARGUMENTS} --mesos-id=${APP_AGENT_ID} ${IP_ADDRESS} \
		sudo docker exec ${EXTRA_ARGUMENTS} ${APP_CONTAINER_ID} \"${COMMAND}\"'"
	dcos_ssh ${DEBUG_OPT} ${SSH_ARGUMENTS} --mesos-id=${APP_AGENT_ID} ${IP_ADDRESS} \
		sudo docker exec ${EXTRA_ARGUMENTS} ${APP_CONTAINER_ID} ${COMMAND}

# If there is stdin.
else 

	${DEBUG} && echo "Running 'dcos_ssh ${DEBUG_OPT} ${SSH_ARGUMENTS} --mesos-id=${APP_AGENT_ID} ${IP_ADDRESS} \
		sudo docker exec ${EXTRA_ARGUMENTS} ${APP_CONTAINER_ID} \"${COMMAND}\" < ${STD_IN_TEMP_FILE}'"
	dcos_ssh ${DEBUG_OPT} ${SSH_ARGUMENTS} --mesos-id=${APP_AGENT_ID} ${IP_ADDRESS} \
		sudo docker exec ${EXTRA_ARGUMENTS} ${APP_CONTAINER_ID} ${COMMAND} < ${STD_IN_TEMP_FILE}

fi


