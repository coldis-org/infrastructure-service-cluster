#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
NEXT_CMD=

# For each parameter.
while :; do
	case ${1} in
		
		# Debug parameter.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;

		# Other option.
		?*)
			NEXT_CMD="${NEXT_CMD} ${1}"
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
${DEBUG} && echo  "Running 'dcos_init'"

# Sets up the cluster.
echo ${CLUSTER_KEY} | dcos cluster setup http://${CLUSTER_IP}
echo "DCOS setup finished"

# Executes the dcos script.
${DEBUG} && echo  "Running '${NEXT_CMD}'"
exec ${NEXT_CMD} ${DEBUG_OPT}

