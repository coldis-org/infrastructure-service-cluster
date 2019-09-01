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
		
		# Debug parameter.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;
			
		# User id.
		--uid)
			UID=${2}
			shift
			;;
			
		# Public key.
		--public-key)
			PUBLIC_KEY=${2}
			shift
			;;
		
		# Other option.
		?*)
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
${DEBUG} && echo "Running 'dcos_create_user'"

# Creates the user.
AUTH_TOKEN=`dcos config show core.dcos_acs_token`
PUBLIC_KEY=$(sed ':a;N;$!ba;s/\n/\\n/g' ${PUBLIC_KEY})
${DEBUG} && echo "AUTH_TOKEN=${AUTH_TOKEN}"
${DEBUG} && echo "PUBLIC_KEY=${PUBLIC_KEY}"

curl -i -X DELETE http://${CLUSTER_ADDRESS}/acs/api/v1/users/${UID} \
-H 'Content-Type: application/json' -H "Authorization: token=${AUTH_TOKEN}"

curl -i -X PUT http://${CLUSTER_ADDRESS}/acs/api/v1/users/${UID} \
-d '{"public_key": "'"${PUBLIC_KEY}"'"}' \
-H 'Content-Type: application/json' -H "Authorization: token=${AUTH_TOKEN}"

