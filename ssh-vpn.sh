#!/bin/bash
#
# ==================================================
# Getting
dateFromServer=$(curl -v --insecure --silent https://google.com/ 2>&1 | grep Date | sed -e 's/< Date: //')
biji=`date +"%Y-%m-%d" -d "$dateFromServer"`
#########################

BURIQ () {
    curl -sS https://raw.githubusercontent.com/liuuufey/aksesip/main/scnoip  > /root/tmp
    data=( `cat /root/tmp | grep -E "^### " | awk '{print $2}'` )
    for user in "${data[@]}"
    do
    exp=( `grep -E "^### $user" "/root/tmp" | awk '{print $3}'` )
    d1=(`date -d "$exp" +%s`)
    d2=(`date -d "$biji" +%s`)
    exp2=$(( (d1 - d2) / 86400 ))
    if [[ "$exp2" -le "0" ]]; then
    echo $user > /etc/.$user.ini
    else
    rm -f /etc/.$user.ini > /dev/null 2>&1
    fi
    done
    rm -f /root/tmp
}

MYIP=$(curl -sS ipinfo.io/ip)
Name=$(curl -sS https://raw.githubusercontent.com/liuuufey/aksesip/main/scnoip  | grep $MYIP | awk '{print $2}')
echo $Name > /usr/local/etc/.$Name.ini
CekOne=$(cat /usr/local/etc/.$Name.ini)

Bloman () {
if [ -f "/etc/.$Name.ini" ]; then
CekTwo=$(cat /etc/.$Name.ini)
    if [ "$CekOne" = "$CekTwo" ]; then
        res="Expired"
    fi
else
res="Permission Accepted..."
fi
}

PERMISSION () {
    MYIP=$(curl -sS ipinfo.io/ip)
    IZIN=$(curl -sS https://raw.githubusercontent.com/liuuufey/aksesip/main/scnoip  | awk '{print $4}' | grep $MYIP)
    if [ "$MYIP" = "$IZIN" ]; then
    Bloman
    else
    res="Permission Denied!"
    fi
    BURIQ
}
red='\e[1;31m'
green='\e[1;32m'
NC='\e[0m'
green() { echo -e "\\033[32;1m${*}\\033[0m"; }
red() { echo -e "\\033[31;1m${*}\\033[0m"; }
PERMISSION

if [ -f /home/needupdate ]; then
red "Your script need to update first !"
exit 0
elif [ "$res" = "Permission Accepted..." ]; then
echo -ne
else
red "Permission Denied!"
exit 0
fi
clear
# initializing var
export DEBIAN_FRONTEND=noninteractive
MYIP=$(wget -qO- icanhazip.com);
MYIP2="s/xxxxxxxxx/$MYIP/g";
NET=$(ip -o $ANU -4 route show to default | awk '{print $5}');
source /etc/os-release
ver=$VERSION_ID

#detail nama perusahaan
country=ID
state=Jabar
locality=Sukabumi
organization=netnot.xyz
organizationalunit=www.sundanesee.eu.org
commonname=www.netnot.xyz
email=admin@jhoy.my.id

# simple password minimal
wget -O /etc/pam.d/common-password "https://raw.githubusercontent.com/liuuufey/sc-noip/main/password"
chmod +x /etc/pam.d/common-password

# go to root
cd

# Edu OVPN
wget -q -O /usr/local/bin/edu-ovpn https://raw.githubusercontent.com/liuuufey/sc-noip/main/cdn-ovpn.py
chmod +x /usr/local/bin/edu-ovpn

# Installing Service
cat > /etc/systemd/system/edu-ovpn.service << END
[Unit]
Description=Python Edu Ovpn By Liuuufey
Documentation=https://sundanese.ml
After=network.target nss-lookup.target

[Service]
Type=simple
User=root
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/bin/python -O /usr/local/bin/edu-ovpn 2082
Restart=on-failure

[Install]
WantedBy=multi-user.target
END

systemctl daemon-reload
systemctl enable edu-ovpn
systemctl restart edu-ovpn

# Edit file /etc/systemd/system/rc-local.service
cat > /etc/systemd/system/rc-local.service <<-END
[Unit]
Description=/etc/rc.local
ConditionPathExists=/etc/rc.local
[Service]
Type=forking
ExecStart=/etc/rc.local start
TimeoutSec=0
StandardOutput=tty
RemainAfterExit=yes
SysVStartPriority=99
[Install]
WantedBy=multi-user.target
END

# nano /etc/rc.local
cat > /etc/rc.local <<-END
#!/bin/sh -e
# rc.local
# By default this script does nothing.
exit 0
END

# Ubah izin akses
chmod +x /etc/rc.local

# enable rc local
systemctl enable rc-local
systemctl start rc-local.service

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

#update
apt update -y
apt upgrade -y
apt dist-upgrade -y
apt-get remove --purge ufw firewalld -y
apt-get remove --purge exim4 -y

# install wget and curl
apt -y install wget curl
apt -y install python

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Jakarta /etc/localtime

# set locale
sed -i 's/AcceptEnv/#AcceptEnv/g' /etc/ssh/sshd_config

# install
apt-get --reinstall --fix-missing install -y bzip2 gzip coreutils wget screen rsyslog iftop htop net-tools zip unzip wget net-tools curl nano sed screen gnupg gnupg1 bc apt-transport-https build-essential dirmngr libxml-parser-perl neofetch git lsof
echo "clear" >> .profile
echo "neofetch" >> .profile
echo "infow" >> .profile


# install webserver
apt -y install nginx
cd
rm /etc/nginx/sites-enabled/default
rm /etc/nginx/sites-available/default
wget -O /etc/nginx/nginx.conf "https://raw.githubusercontent.com/liuuufey/sc-noip/main/nginx.conf"
mkdir -p /home/vps/public_html
wget -O /etc/nginx/conf.d/vps.conf "https://raw.githubusercontent.com/liuuufey/sc-noip/main/vps.conf"
/etc/init.d/nginx restart

# install badvpn
cd
wget -O /usr/bin/badvpn-udpgw "https://raw.githubusercontent.com/liuuufey/sc-noip/main/badvpn-udpgw64"
chmod +x /usr/bin/badvpn-udpgw
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500' /etc/rc.local
sed -i '$ i\screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500' /etc/rc.local
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500

# setting port ssh
sed -i '/Port 22/a Port 88' /etc/ssh/sshd_config
sed -i 's/#Port 22/Port 22/g' /etc/ssh/sshd_config

# install dropbear
apt -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 109 -p 69"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
echo "/usr/sbin/nologin" >> /etc/shells
/etc/init.d/dropbear restart

# install squid
cd
apt -y install squid3
wget -O /etc/squid/squid.conf "https://raw.githubusercontent.com/liuuufey/sc-noip/main/squid3.conf"
sed -i $MYIP2 /etc/squid/squid.conf

# setting vnstat
apt -y install vnstat
/etc/init.d/vnstat restart
apt -y install libsqlite3-dev
wget https://humdi.net/vnstat/vnstat-2.6.tar.gz
tar zxvf vnstat-2.6.tar.gz
cd vnstat-2.6
./configure --prefix=/usr --sysconfdir=/etc && make && make install
cd
vnstat -u -i $NET
sed -i 's/Interface "'""eth0""'"/Interface "'""$NET""'"/g' /etc/vnstat.conf
chown vnstat:vnstat /var/lib/vnstat -R
systemctl enable vnstat
/etc/init.d/vnstat restart
rm -f /root/vnstat-2.6.tar.gz
rm -rf /root/vnstat-2.6

# install stunnel
apt install stunnel4 -y
cat > /etc/stunnel/stunnel.conf <<-END
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1

[dropbear]
accept = 222
connect = 127.0.0.1:109

[dropbear]
accept = 777
connect = 127.0.0.1:22

[openvpn]
accept = 442
connect = 127.0.0.1:1194

[ws-stunnel]
accept = 2053
connect = 127.0.0.1:443

END

# make a certificate
openssl genrsa -out key.pem 2048
openssl req -new -x509 -key key.pem -out cert.pem -days 1095 \
-subj "/C=$country/ST=$state/L=$locality/O=$organization/OU=$organizationalunit/CN=$commonname/emailAddress=$email"
cat key.pem cert.pem >> /etc/stunnel/stunnel.pem

# konfigurasi stunnel
sed -i 's/ENABLED=0/ENABLED=1/g' /etc/default/stunnel4
/etc/init.d/stunnel4 restart

cd
#install sslh
apt-get install sslh -y

#konfigurasi
#port 443 to 77 and 777
wget -O /etc/default/sslh "https://raw.githubusercontent.com/liuuufey/sc-noip/main/sslh.conf"
service sslh restart

#privoxy
apt -y install privoxy
rm /etc/privoxy/config
wget -O /etc/privoxy/config "https://raw.githubusercontent.com/liuuufey/sc-noip/main/config"
service privoxy restart

#install badvpncdn
wget https://github.com/ambrop72/badvpn/archive/master.zip
unzip master.zip
cd badvpn-master
mkdir build
cmake .. -DBUILD_NOTHING_BY_DEFAULT=1 -DBUILD_UDPGW=1
sudo make install

END
#OpenVPN
wget https://raw.githubusercontent.com/liuuufey/sc-noip/main/vpn.sh &&  chmod +x vpn.sh && ./vpn.sh

# install fail2ban
apt -y install fail2ban

# Instal DDOS Flate
if [ -d '/usr/local/ddos' ]; then
	echo; echo; echo "Please un-install the previous version first"
	exit 0
else
	mkdir /usr/local/ddos
fi
clear
echo; echo 'Installing DOS-Deflate 0.6'; echo
echo; echo -n 'Downloading source files...'
wget -q -O /usr/local/ddos/ddos.conf http://www.inetbase.com/scripts/ddos/ddos.conf
echo -n '.'
wget -q -O /usr/local/ddos/LICENSE http://www.inetbase.com/scripts/ddos/LICENSE
echo -n '.'
wget -q -O /usr/local/ddos/ignore.ip.list http://www.inetbase.com/scripts/ddos/ignore.ip.list
echo -n '.'
wget -q -O /usr/local/ddos/ddos.sh http://www.inetbase.com/scripts/ddos/ddos.sh
chmod 0755 /usr/local/ddos/ddos.sh
cp -s /usr/local/ddos/ddos.sh /usr/local/sbin/ddos
echo '...done'
echo; echo -n 'Creating cron to run script every minute.....(Default setting)'
/usr/local/ddos/ddos.sh --cron > /dev/null 2>&1
echo '.....done'
echo; echo 'Installation has completed.'
echo 'Config file is at /usr/local/ddos/ddos.conf'
echo 'Please send in your comments and/or suggestions to zaf@vsnl.com'

# banner /etc/issue.net
wget -O /etc/issue.net "https://raw.githubusercontent.com/liuuufey/sc-noip/main/banner.conf"
echo "Banner /etc/issue.net" >>/etc/ssh/sshd_config
sed -i 's@DROPBEAR_BANNER=""@DROPBEAR_BANNER="/etc/issue.net"@g' /etc/default/dropbear

# blockir torrent
iptables -A FORWARD -m string --algo bm --string "BitTorrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "BitTorrent protocol" -j DROP
iptables -A FORWARD -m string --algo bm --string "peer_id=" -j DROP
iptables -A FORWARD -m string --algo bm --string ".torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce.php?passkey=" -j DROP
iptables -A FORWARD -m string --algo bm --string "torrent" -j DROP
iptables -A FORWARD -m string --algo bm --string "announce" -j DROP
iptables -A FORWARD -m string --algo bm --string "info_hash" -j DROP
iptables -A FORWARD -m string --algo bm --string "/default.ida?" -j DROP
iptables -A FORWARD -m string --algo bm --string ".exe?/c+dir" -j DROP
iptables -A FORWARD -m string --algo bm --string ".exe?/c_tftp" -j DROP
iptables -A FORWARD -m string --string "peer_id" --algo kmp -j DROP
iptables -A FORWARD -m string --string "BitTorrent" --algo kmp -j DROP
iptables -A FORWARD -m string --string "BitTorrent protocol" --algo kmp -j DROP
iptables -A FORWARD -m string --string "bittorrent-announce" --algo kmp -j DROP
iptables -A FORWARD -m string --string "announce.php?passkey=" --algo kmp -j DROP
iptables -A FORWARD -m string --string "find_node" --algo kmp -j DROP
iptables -A FORWARD -m string --string "info_hash" --algo kmp -j DROP
iptables -A FORWARD -m string --string "get_peers" --algo kmp -j DROP
iptables -A FORWARD -m string --string "announce" --algo kmp -j DROP
iptables -A FORWARD -m string --string "announce_peers" --algo kmp -j DROP
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload

# install python
apt -y install ruby
gem install lolcat
apt -y install figlet
apt -y install dos2unix

# download script
cd /usr/bin
wget -O add-host "https://raw.githubusercontent.com/liuuufey/sc-noip/main/add-host.sh"
wget -O about "https://raw.githubusercontent.com/liuuufey/sc-noip/main/about.sh"
wget -O usernew "https://raw.githubusercontent.com/liuuufey/sc-noip/main/usernew.sh"
wget -O trial "https://raw.githubusercontent.com/liuuufey/sc-noip/main/trial.sh"
wget -O hapus "https://raw.githubusercontent.com/liuuufey/sc-noip/main/hapus.sh"
wget -O member "https://raw.githubusercontent.com/liuuufey/sc-noip/main/member.sh"
wget -O delete "https://raw.githubusercontent.com/liuuufey/sc-noip/main/delete.sh"
wget -O cek "https://raw.githubusercontent.com/liuuufey/sc-noip/main/cek.sh"
wget -O restart "https://raw.githubusercontent.com/liuuufey/sc-noip/main/restart.sh"
wget -O speedtest "https://raw.githubusercontent.com/liuuufey/sc-noip/main/speedtest_cli.py"
wget -O info "https://raw.githubusercontent.com/liuuufey/sc-noip/main/info.sh"
wget -O ram "https://raw.githubusercontent.com/liuuufey/sc-noip/main/ram.sh"
wget -O renew "https://raw.githubusercontent.com/liuuufey/sc-noip/main/renew.sh"
wget -O autokill "https://raw.githubusercontent.com/liuuufey/sc-noip/main/autokill.sh"
wget -O ceklim "https://raw.githubusercontent.com/liuuufey/sc-noip/main/ceklim.sh"
wget -O tendang "https://raw.githubusercontent.com/liuuufey/sc-noip/main/tendang.sh"
wget -O clear-log "https://raw.githubusercontent.com/liuuufey/sc-noip/main/clear-log.sh"
wget -O change-port "https://raw.githubusercontent.com/liuuufey/sc-noip/main/change.sh"
wget -O port-ovpn "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-ovpn.sh"
wget -O port-ssl "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-ssl.sh"
wget -O port-wg "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-wg.sh"
wget -O port-tr "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-tr.sh"
wget -O port-sstp "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-sstp.sh"
wget -O port-squid "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-squid.sh"
wget -O port-ws "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-ws.sh"
wget -O port-vless "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-vless.sh"
wget -O wbmn "https://raw.githubusercontent.com/liuuufey/sc-noip/main/webmin.sh"
wget -O xp "https://raw.githubusercontent.com/liuuufey/sc-noip/main/xp.sh"
wget -O swap "https://raw.githubusercontent.com/liuuufey/sc-noip/main/swapkvm.sh"
wget -O menu "https://raw.githubusercontent.com/liuuufey/sc-noip/main/menu.sh"
wget -O bbr "https://raw.githubusercontent.com/liuuufey/sc-noip/main/update/bbr.sh"
wget -O bannerku "https://raw.githubusercontent.com/liuuufey/sc-noip/main/bannerku"
wget -O /usr/bin/user-limit https://raw.githubusercontent.com/liuuufey/sc-noip/main/user-limit.sh && chmod +x /usr/bin/user-limit
wget -O autoreboot "https://raw.githubusercontent.com/liuuufey/sc-noip/main/autoreboot.sh"
wget -O point "https://raw.githubusercontent.com/liuuufey/sc-noip/main/pointing.sh"
wget -O service-status "https://raw.githubusercontent.com/liuuufey/sc-noip/main/service.sh"
wget -O infow "https://raw.githubusercontent.com/liuuufey/sc-noip/main/infow.sh"
wget -O bcknginx "https://raw.githubusercontent.com/liuuufey/sc-noip/main/backup-nginx.sh"
wget -O update "https://raw.githubusercontent.com/liuuufey/sc-noip/main/update.sh"
wget "https://raw.githubusercontent.com/liuuufey/sc-noip/main/add-trgo"
wget "https://raw.githubusercontent.com/liuuufey/sc-noip/main/del-trgo"
wget "https://raw.githubusercontent.com/liuuufey/sc-noip/main/cek-trgo"
wget "https://raw.githubusercontent.com/liuuufey/sc-noip/main/renew-trgo"
wget -O port-sslh "https://raw.githubusercontent.com/liuuufey/sc-noip/main/port-sslh.sh"
wget -O log-ws "https://raw.githubusercontent.com/liuuufey/sc-noip/main/log-ws.sh"
chmod +x add-host
chmod +x usernew
chmod +x trial
chmod +x hapus
chmod +x member
chmod +x delete
chmod +x cek
chmod +x restart
chmod +x speedtest
chmod +x info
chmod +x ram
chmod +x renew
chmod +x about
chmod +x autokill
chmod +x ceklim
chmod +x tendang
chmod +x clear-log
chmod +x change-port
chmod +x port-ovpn
chmod +x port-ssl
chmod +x port-wg
chmod +x port-tr
chmod +x port-sstp
chmod +x port-squid
chmod +x port-ws
chmod +x port-vless
chmod +x wbmn
chmod +x xp
chmod +x swap
chmod +x menu
chmod +x bbr
chmod +x bannerku
chmod +x autoreboot
chmod +x point
chmod +x service-status
chmod +x infow
chmod +x bcknginx
chmod +x update
chmod +x add-trgo
chmod +x del-trgo
chmod +x cek-trgo
chmod +x renew-trgo
dos2unix add-trgo
dos2unix del-trgo
dos2unix cek-trgo
dos2unix renew-trgo
chmod +x port-sslh
chmod +x log-ws
echo "0 5 * * * root clear-log && reboot" >> /etc/crontab
echo "0 0 * * * root xp" >> /etc/crontab
# remove unnecessary files
cd
echo "1" > /proc/sys/net/ipv4/ip_forward; wget -O /usr/bin/point 'https://raw.githubusercontent.com/liuuufey/sc-noip/main/pointing.sh'; chmod +x /usr/bin/point
apt autoclean -y
apt -y remove --purge unscd
apt-get -y --purge remove samba*;
apt-get -y --purge remove apache2*;
apt-get -y --purge remove bind9*;
apt-get -y remove sendmail*
apt autoremove -y
# finishing
cd
chown -R www-data:www-data /home/vps/public_html
/etc/init.d/nginx restart
/etc/init.d/ssh restart
/etc/init.d/sslh restart
/etc/init.d/stunnel4 restart
/etc/init.d/openvpn restart
/etc/init.d/cron restart
/etc/init.d/ssh restart
/etc/init.d/dropbear restart
/etc/init.d/fail2ban restart
/etc/init.d/vnstat restart
/etc/init.d/squid restart
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7100 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7200 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7300 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7400 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7500 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7600 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7700 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7800 --max-clients 500
screen -dmS badvpn badvpn-udpgw --listen-addr 127.0.0.1:7900 --max-clients 500
history -c
echo "unset HISTFILE" >> /etc/profile

cd
rm -f /root/key.pem
rm -f /root/cert.pem
rm -f /root/ssh-vpn.sh

# finihsing
clear
