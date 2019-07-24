#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
WORK_DIRECTORY=/project
DCOS_CONFIG_FILE=dcos_cli.properties
DCOS_TEMP_SERVICE_FILE=${WORK_DIRECTORY}/temp-service.json
FORCE=

# For each parameter.
while :; do
	case ${1} in
		
		# If debug should be enabled.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;

		# If debug should be enabled.
		-f|--force)
			FORCE="--force"
			;;

		# No more options.
		*)
			break

	esac 
	shift
done

rm -f ${DCOS_TEMP_SERVICE_FILE}
touch ${DCOS_TEMP_SERVICE_FILE}
while read -r DCOS_TEMP_SERVICE_LINE
do
	echo "${DCOS_TEMP_SERVICE_LINE}" >> ${DCOS_TEMP_SERVICE_FILE}
done

# Using unavaialble variables should fail the script.
set -o nounset

# Enables interruption signal handling.
trap - INT TERM

# Print parameters if on debug mode.
${DEBUG} && echo "Running 'dcos_deploy_marathon'"
${DEBUG} && cat ${DCOS_TEMP_SERVICE_FILE}

# Generates the deploy id.
DEPLOY_ID="`head /dev/urandom | tr -dc \"0-9\" | head -c 13`"
${DEBUG} && echo "DEPLOY_ID=${DEPLOY_ID}"
echo `jq ".env.DEPLOY_ID = \"${DEPLOY_ID}\"" ${DCOS_TEMP_SERVICE_FILE}` > ${DCOS_TEMP_SERVICE_FILE}

# If the application exists in the cluster.
if dcos marathon app show `jq -r ".id" < ${DCOS_TEMP_SERVICE_FILE}`
then
	# Updates the app in the cluster.
	${DEBUG} && echo "Updating app in the cluster"
	SERVICE_ID="`jq -r ".id" < ${DCOS_TEMP_SERVICE_FILE}`"
	DEPLOYMENT_ID="`dcos marathon app update ${FORCE} ${SERVICE_ID} < ${DCOS_TEMP_SERVICE_FILE}`"
	DEPLOYMENT_ID=${DEPLOYMENT_ID#Created deployment *}
	${DEBUG} && echo "Watching deployment ${DEPLOYMENT_ID}"
	dcos marathon deployment watch --max-count=36 --interval=5 ${DEPLOYMENT_ID}
# If the application does not exist in the cluster.
else
	# Adds the app to the cluster.
	${DEBUG} && echo "Adding app to the cluster"
	DEPLOYMENT_ID="`dcos marathon app add < ${DCOS_TEMP_SERVICE_FILE}`"
	DEPLOYMENT_ID=${DEPLOYMENT_ID#Created deployment *}
	${DEBUG} && echo "Watching deployment ${DEPLOYMENT_ID}"
	dcos marathon deployment watch --max-count=36 --interval=5 ${DEPLOYMENT_ID}
fi


