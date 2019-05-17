#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
STOP_BOOTSTRAP=true

# For each parameter.
while :; do
	case ${1} in
		
		# Debug parameter.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;

		# Stop bootstrap parameter.
		--stop-bootstrap)
			STOP_BOOTSTRAP=true
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

# Adds the AWS key.
${DEBUG} && echo "Adding AWS SSH key."
mkdir -p ~/.ssh
cp /project/aws_dcos_cluster_key ~/.ssh/aws_dcos_cluster_key
cp /project/aws_dcos_cluster_key.pub ~/.ssh/aws_dcos_cluster_key.pub
eval `ssh-agent -s` && \
ssh-add ~/.ssh/aws_dcos_cluster_key

# Puts the AWS basic config available to the scripts.
${DEBUG} && echo "Exporting AWS config variables."
. /project/aws_service_config_cluster.properties
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

# Executes the terraform script.
${DEBUG} && echo "terraform init
terraform plan -out=create_dcos_cluster.out
terraform apply create_dcos_cluster.out"
terraform init
terraform plan -out=create_dcos_cluster.out
terraform apply create_dcos_cluster.out > /project/dcos_setup.log


