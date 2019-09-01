#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
WORK_DIRECTORY=.

# For each parameter.
while :; do
	case ${1} in
		
		# If debug should be enabled.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;

		# App id.
		-a|--app-id)
			APP_ID=${2}
			shift
			;;
			
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
${DEBUG} && echo "Running 'dcos_docker_get_container'"
${DEBUG} && echo "APP_ID=${APP_ID}"

# Gets the agent information.
APP_INFO=`dcos marathon app show ${APP_ID}`
#${DEBUG} && echo "APP_INFO=${APP_INFO}"
APP_AGENT_ID=`echo ${APP_INFO} | jq -r ".tasks[0].slaveId"`
${DEBUG} && echo "APP_AGENT_ID=${APP_AGENT_ID}"
APP_TASK_ID=`echo ${APP_INFO} | jq -r ".tasks[0].id"`
${DEBUG} && echo "APP_TASK_ID=${APP_TASK_ID}"
APP_TASK_INFO=`dcos task --json ${APP_TASK_ID}`
#${DEBUG} && echo "APP_TASK_INFO=${APP_TASK_INFO}"
APP_CONTAINER_ID=mesos-`echo ${APP_TASK_INFO} | jq -r ".[0].statuses[] | \
	select(.state == \"TASK_RUNNING\") | \
	.container_status.container_id.value"`
${DEBUG} && echo "APP_CONTAINER_ID=${APP_CONTAINER_ID}"

echo "${APP_CONTAINER_ID}"