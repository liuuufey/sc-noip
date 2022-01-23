#!/bin/bash
red='\e[1;31m'
green='\e[0;32m'
NC='\e[0m'
MYIP=$(wget -qO- ifconfig.me/ip);
echo "Checking VPS"
clear
sslh="$(netstat -nlpt | grep -i sslh | grep -i 0.0.0.0 | awk '{print $4}' | cut -d: -f2)"
echo -e "      Change Port $sslh"
read -p "New Port sslh: " sslh2
if [ -z $sslh2 ]; then
echo "Please Input Port"
exit 0
fi
cek=$(netstat -nutlp | grep -w $sslh2)
if [[ -z $cek ]]; then
rm -f /etc/default/sslh
cat > /etc/default/sslh <<-END
# Default options for sslh initscript
# sourced by /etc/init.d/sslh

# Disabled by default, to force yourself
# to read the configuration:
# - /usr/share/doc/sslh/README.Debian (quick start)
# - /usr/share/doc/sslh/README, at "Configuration" section
# - sslh(8) via "man sslh" for more configuration details.
# Once configuration ready, you *must* set RUN to yes here
# and try to start sslh (standalone mode only)

RUN=yes

# binary to use: forked (sslh) or single-thread (sslh-select) version
# systemd users: don't forget to modify /lib/systemd/system/sslh.service
DAEMON=/usr/sbin/sslh

DAEMON_OPTS="--user sslh --listen 0.0.0.0:$sslh2 --ssh 127.0.0.1:22 --ssl 127.0.0.1:2053 --http 127.0.0.1:700  --pidfile /var/run/sslh/sslh.pid"
END
systemctl restart sslh
echo -e "\e[032;1mPort $sslh2 modified successfully\e[0m"
else
echo "Port $sslh2 is used"
fi

