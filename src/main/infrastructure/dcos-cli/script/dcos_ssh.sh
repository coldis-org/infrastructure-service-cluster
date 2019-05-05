#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Debug is disabled by default.
DEBUG=false
DEBUG_OPT=

# Default paramentes.
SSH_USER=centos
SSH_OPTIONS=--master-proxy

# For each argument.
while :; do
	case ${1} in
		
		# If debug should be enabled.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;

		# SSH user.
		--user)
			SSH_USER=${2}
			shift
			;;

		# Other option.
		?*)
			SSH_OPTIONS="${SSH_OPTIONS} ${1}"
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

# Print arguments if on debug mode.
${DEBUG} && echo  "Running 'dcos_ssh'"
${DEBUG} && echo  "SSH_USER=${SSH_USER}"
${DEBUG} && echo  "SSH_OPTIONS=${SSH_OPTIONS}"

# Configures SSH.
mkdir -p ~/.ssh
cp /project/aws_dcos_cluster_key ~/.ssh/aws_dcos_cluster_key
eval `ssh-agent -s` && \
ssh-add ~/.ssh/aws_dcos_cluster_key

# Runs ssh.
${DEBUG} && echo  "Running 'dcos node ssh ${SSH_OPTIONS} --user=${SSH_USER}'"
dcos node ssh ${SSH_OPTIONS} --user=${SSH_USER}
