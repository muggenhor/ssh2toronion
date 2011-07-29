#!/bin/sh

set -e

host="$1"
port="$2"

if ! grep -q "^$host\b" $HOME/.ssh/known_hosts; then
	workip="$(hexdump -n 2 -e '1/1 "127.7.%u" 1/1 ".%u"' /dev/random)"
	workport=0
	while [ $workport -le 1024 -o $workport -ge 65535 ]
	do
		workport="$(hexdump -n 2 -e '/2 "%u"' /dev/random)"
	done

	# Fetch the remote SSH key and convert it to an onion address
	/usr/bin/socat TCP4-LISTEN:$workport,bind=$workip,reuseaddr SOCKS4A:127.0.0.1:"$host":"$port",SOCKSPORT=9050 &
	sleep 0.1
	hostline="`/usr/bin/ssh-keyscan -4 -p $workport -T 120 -t rsa $workip < /dev/null 2> /dev/null | /home/giel/ssh2onion-address`"
	wait %1

	# Check if the onion address matches the public SSH key
	if [ "$host" = "$(echo "$hostline" | cut -d' ' -f1)" ]; then
		echo "$hostline" >> $HOME/.ssh/known_hosts
	fi
fi

# Execute the tunnel
exec /usr/bin/socat STDIO SOCKS4A:127.0.0.1:"$host":"$port",SOCKSPORT=9050
