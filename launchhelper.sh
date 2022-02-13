#!/bin/sh

#############
# CONSTANTS #
#############

UX_NAME='LeagueClientUx.exe'
CLIENT_NAME='LeagueClient.exe'
SCC_SH='syscall_check.sh'


#############
# FUNCTIONS #
#############

die() {
    >&2 echo "ERROR: ${1}"
    sleep 5
    exit 1
}

wait_for() {
    timeout --foreground "${1}" sh -c '
        start_time=$(date +%s)
    	until '"${2}"'; do \
    	    sleep 0.2; \
            elapsed=$(( $(date +%s) - start_time ))
            printf "\r\e[KElapsed Time: %3ds... " "$elapsed" >&2; \
        done;'
}


########
# MAIN #
########

# call syscall_check
own_dir="$(dirname "$(readlink -f "${0}")")"
# if ! [ -x "${own_dir}/${SCC_SH}" ]; then
#     die "Please place this script into the same directory as '${SCC_SH}'!"
# fi
# "${own_dir}/${SCC_SH}"

# find pid of LeagueClientUx process
echo "Waiting for process of '${UX_NAME}' ..."
ux_pid=$(wait_for 2m "pidof '${UX_NAME}'")
echo "OK"

if [ -z "${ux_pid}" ]; then
    die "Could not find processes of '${UX_NAME}'"
fi

echo "${UX_NAME} pid found: ${ux_pid}"

# find port of LeagueClientUx process
ux_port=$(grep -ao -- '--app-port=[0-9]*' "/proc/${ux_pid}/cmdline" | grep -o '[0-9]*')

if [ -z "${ux_port}" ]; then
    die "Could not find port of '${UX_NAME}' process!"
fi

echo "${UX_NAME} port found: ${ux_port}"

# pause LeagueClientUx process
kill -STOP "${ux_pid}"

echo "Waiting for port ${ux_port} ..."
wait_for 5m "echo 'Q' | openssl s_client -connect ':${ux_port}' >/dev/null 2>&1"
echo "OK"
#read -rsn1 -p"Press any key to continue";echo

# continue LeagueClientUx process
kill -CONT "${ux_pid}"

# finalize
echo "${UX_NAME} continues, my job is done!"

sleep 5

exit 0
