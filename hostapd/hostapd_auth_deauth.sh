#!/bin/sh
LOG_FILE=/tmp/hostapd_auth_deauth.log

operation="$1"
mac="$2"
port="$3"
vlan=$(bridge vlan show dev "$port" | tail -1 |tr -s ' ' | cut -d' ' -f2)
vlan=$(bridge vlan show dev "$port" | tail -1 | tr -s "\t" " " | cut -d" " -f2 | grep -Eo '[0-9]{1,4}')

if [ -z "$vlan" ] ; then
    cmd="bridge fdb ""$operation"" ""$mac"" dev ""$port"" master dynamic"
else
    cmd="bridge fdb ""$operation"" ""$mac"" dev ""$port"" vlan ""$vlan"" master dynamic"
fi

{
    printf "Date is %s\n" "$(date)"
    printf "Operastion is %s\n" "$operation"
    printf "MAC is %s\n" "$mac"
    printf "Port is %s\n" "$port"
    if [ -z "$vlan" ] ; then
	printf "VLAN is empty\n"
    else
	printf "VLAN is %s\n" "$vlan"
    fi
    printf "\n"
    printf "Cmd is %s\n" "$cmd"
} > "$LOG_FILE"

if ! $cmd >> "$LOG_FILE" 2>&1 ; then
    printf "HOSTAPD AUTH SCRIPT: Command %s failed!\n" "$cmd"
    cat "$LOG_FILE"
    exit 1
fi

exit 0
