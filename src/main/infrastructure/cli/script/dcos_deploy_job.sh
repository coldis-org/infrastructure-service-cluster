#!/bin/sh

# Default script behavior.
set -o errexit
#set -o pipefail

# Default paramentes.
DEBUG=false
DEBUG_OPT=
WORK_DIRECTORY=.
DCOS_CONFIG_FILE=dcos_cli.properties
DCOS_TEMP_JOB_FILE=${WORK_DIRECTORY}/temp-job.json
DCOS_TEMP_SCHEDULES_FILE=${WORK_DIRECTORY}/temp-schedules.json
DCOS_TEMP_SCHEDULE_FILE=${WORK_DIRECTORY}/temp-schedule.json

# For each parameter.
while :; do
	case ${1} in
		
		# If debug should be enabled.
		--debug)
			DEBUG=true
			DEBUG_OPT="--debug"
			;;
			
		# Work directory.
		-w|--work-directory)
			WORK_DIRECTORY=${2}
			shift
			;;

		# No more options.
		*)
			break

	esac 
	shift
done

rm -f ${DCOS_TEMP_JOB_FILE}
touch ${DCOS_TEMP_JOB_FILE}
while read -r DCOS_TEMP_JOB_LINE
do
	echo "${DCOS_TEMP_JOB_LINE}" >> ${DCOS_TEMP_JOB_FILE}
done

# Using unavaialble variables should fail the script.
set -o nounset

# Enables interruption signal handling.
trap - INT TERM

# Print parameters if on debug mode.
${DEBUG} && echo "Running 'dcos_deploy_job'"

# Generates the deploy id.
DEPLOY_ID="$(head /dev/urandom | tr -dc "0-9a-z" | head -c 13)"
${DEBUG} && echo "DEPLOY_ID=${DEPLOY_ID}"
echo "$(jq ".run.env.DEPLOY_ID = \"${DEPLOY_ID}\"" ${DCOS_TEMP_JOB_FILE})" > ${DCOS_TEMP_JOB_FILE}

# Strips schedules from the file.
echo "$(jq -r ".schedules" ${DCOS_TEMP_JOB_FILE})" > ${DCOS_TEMP_SCHEDULES_FILE}
${DEBUG} && cat ${DCOS_TEMP_SCHEDULES_FILE}
echo "$(jq "del(.schedules)" ${DCOS_TEMP_JOB_FILE})" > ${DCOS_TEMP_JOB_FILE}

# If the job exists in the cluster.
${DEBUG} && cat ${DCOS_TEMP_JOB_FILE}
if dcos job show $(jq -r ".id"  ${DCOS_TEMP_JOB_FILE})
then
	# Updates the job in the cluster.
	${DEBUG} && echo "Updating job in the cluster"
	dcos job update ${DCOS_TEMP_JOB_FILE}
else
	# Adds the job to the cluster.
	${DEBUG} && echo "Adding job to the cluster"
	dcos job add ${DCOS_TEMP_JOB_FILE}
fi


# For each schedule.
for SCHEDULE in "$(jq -c ".[]" ${DCOS_TEMP_SCHEDULES_FILE})"
do

	# Creates the schedule json.
	echo "${SCHEDULE}" > ${DCOS_TEMP_SCHEDULE_FILE}

	# If the job exists in the cluster.
	${DEBUG} && cat ${DCOS_TEMP_SCHEDULE_FILE}
	if (dcos job schedule show $(jq -r ".id" ${DCOS_TEMP_JOB_FILE}) | grep $(jq -r ".id" ${DCOS_TEMP_SCHEDULE_FILE}))
	then
		# Updates the schedule in the cluster.
		${DEBUG} && echo "Updating job schedule in the cluster"
		dcos job schedule update $(jq -r ".id" ${DCOS_TEMP_JOB_FILE}) ${DCOS_TEMP_SCHEDULE_FILE}
	else
		# Adds the schedule to the cluster.
		${DEBUG} && echo "Adding job schedule to the cluster"
		dcos job schedule add $(jq -r ".id" ${DCOS_TEMP_JOB_FILE}) ${DCOS_TEMP_SCHEDULE_FILE}
	fi

done


