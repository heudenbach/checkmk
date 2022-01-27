#!/bin/bash

# function to help the user out with the usage of this script
usage() {
  echo -e "Usage: $0 \n -t <timeout> \tTimeout for plugin execution (OPTIONAL, default 60s)\n -s <security> \tIndicate whether or not to output only security updates (OPTIONAL, default 'off')\n -h <help> \tDisplays this help message\n" 1>&2;
  exit 3;
}

# check for command line arguments
while getopts ":t:s:h:" option; do
  case "${option}" in
    t) timeout=${OPTARG};;
    s) security=${OPTARG};;
    h) usage;;
    *) usage;;
  esac
done

# Resets position of first non-option argument
shift "$((OPTIND-1))"

# ensures the timeout is set as default 60 seconds if not supplied via command
if [ -z "${timeout}" ]; then
  timeout=60
fi

CMD=""

# handle "s" flag
if [ -z "${security}" ]; then
  security="off"
elif [[ "$security" == "on" ]]; then
  CMD="--security"
elif [[ "$security" == "off" ]]; then
  :
else
  usage
fi

EXITCODE="0"
NUMSECURITYUPDATES="$(echo $NUMUPDATES |cut -d';' -f1)"

######ab Hier H. Eudenbach 14.10.2021
# Werte holen
PUTSTD=(grep "$(date +['%-m/%-d %H:%M:%S: %Z'])" /var/log/syslog | grep -c 'PUT')
GETSTD=grep "$(date +['%-m/%-d %H:%M:%S: %Z'])" /var/log/syslog | grep -c 'GET')

/var/log/httpd/access_log

# Veriablen
PUTWRITE="$(echo $PUTSTD)"
GETWRITE="$(echo $GETSTD)"

# regex for numbers
numcheck='^[0-9]+$'

# output number
echo "${PUTWRITE} PUTs in der letzten Stunde, ${GETWRITE} WRITEs in der letzten Stunde | 'PUT'=${PUTWRITE};;1;; 'WRITE'=${GETWRITE};;1;;"

exit ${EXITCODE}

