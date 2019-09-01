#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
CLI_VERSION=1.13
COMMAND=dcos

# For each parameter.
while :; do
	case ${1} in
		
		# Debug parameter.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;
			
		# DCOS CLI version.
		--version)
			CLI_VERSION=${2}
			shift
			;;
		
		# DCOS CLI command name.
		--command)
			COMMAND=${2}
			shift
			;;
		
		# Other option.
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
${DEBUG} && echo "Running 'dcos_install'"

# Installs the CLI.
[ -d /usr/local/bin ] || sudo mkdir -p /usr/local/bin
curl https://downloads.dcos.io/binaries/cli/linux/x86-64/dcos-${DCOS_VERSION}/dcos -o dcos
mv dcos /usr/local/bin/${COMMAND}
chmod +x /usr/local/bin/${COMMAND}

