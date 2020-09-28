#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
WORK_DIRECTORY=.
PRIVATE_KEY=
UID=
COMMAND=
INSECURE=--insecure

# For each parameter.
while :; do
	case ${1} in
		
		# Debug parameter.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;
			
		# Cluster address.
		-a|--cluster-address)
			CLUSTER_ADDRESS=${2}
			shift
			;;
			
		# Create service account.
		--create-service-account)
			CREATE_SERVICE_ACCOUNT=true
			;;
			
		# User id.
		--uid)
			UID=${2}
			shift
			;;
		
		# External user token.
		--external-user-token)
			EXTERNAL_USER_TOKEN=${2}
			shift
			;;
		
		# Private key.
		--private-key)
			PRIVATE_KEY=${2}
			shift
			;;
		
		# Other option.
		*)
			COMMAND="${@}"
			break

	esac 
	shift
done

# Using unavaialble variables should fail the script.
set -o nounset

# Enables interruption signal handling.
trap - INT TERM

# Print parameters if on debug mode.
${DEBUG} && echo "Running 'dcos_init'"
${DEBUG} && echo "DEBUG=${DEBUG}"
${DEBUG} && echo "UID=${UID}"
${DEBUG} && echo "PRIVATE_KEY=${PRIVATE_KEY}"
${DEBUG} && echo "EXTERNAL_USER_TOKEN=${EXTERNAL_USER_TOKEN}"
${DEBUG} && echo "CLUSTER_ADDRESS=${CLUSTER_ADDRESS}"

# Sets up the cluster.
if [ "${PRIVATE_KEY}" != "" ]
then
	${DEBUG} && echo "Logging in with private key"
	dcos cluster setup "https://${CLUSTER_ADDRESS}" --username "${UID}" ${INSECURE} --private-key "${PRIVATE_KEY}" 
else
	${DEBUG} && echo "Logging in with token"
	echo ${EXTERNAL_USER_TOKEN} | dcos cluster setup "http://${CLUSTER_ADDRESS}" --provider dcos-oidc-auth0
fi

echo "DCOS setup finished"


# If there is a command to execute.
if [ ! -z "${COMMAND}" ]
then
	# Executes the dcos script.
	${DEBUG} && echo "Running '${COMMAND}'"
	exec ${COMMAND}
fi

