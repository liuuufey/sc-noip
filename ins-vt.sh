#!/bin/bash
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
domain=$(cat /root/domain)
apt install iptables iptables-persistent -y
apt install curl socat xz-utils wget apt-transport-https gnupg gnupg2 gnupg1 dnsutils lsb-release -y 
apt install socat cron bash-completion ntpdate -y
ntpdate pool.ntp.org
apt -y install chrony
timedatectl set-ntp true
systemctl enable chronyd && systemctl restart chronyd
systemctl enable chrony && systemctl restart chrony
timedatectl set-timezone Asia/Jakarta
chronyc sourcestats -v
chronyc tracking -v
date

mkdir -p /etc/trojan/
touch /etc/trojan/akun.conf
# install v2ray
wget https://raw.githubusercontent.com/liuuufey/sc-noip/main/go.sh && chmod +x go.sh && ./go.sh
rm -f /root/go.sh
bash -c "$(wget -O- https://raw.githubusercontent.com/trojan-gfw/trojan-quickstart/master/trojan-quickstart.sh)"
mkdir /root/.acme.sh
curl https://acme-install.netlify.app/acme.sh -o /root/.acme.sh/acme.sh
chmod +x /root/.acme.sh/acme.sh
/root/.acme.sh/acme.sh --set-default-ca  --server  letsencrypt
/root/.acme.sh/acme.sh --issue -d $domain --standalone -k ec-256
~/.acme.sh/acme.sh --installcert -d $domain --fullchainpath /etc/v2ray/v2ray.crt --keypath /etc/v2ray/v2ray.key --ecc
service squid start
uuid=$(cat /proc/sys/kernel/random/uuid)
cat> /etc/v2ray/config.json << END
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 8443,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 2
#tls
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "etc/v2ray/v2ray.crt",
              "keyFile": "/etc/v2ray/v2ray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/v2ray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /etc/v2ray/none.json << END
{
  "log": {
    "access": "/var/log/v2ray/access.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 80,
      "protocol": "vmess",
      "settings": {
        "clients": [
          {
            "id": "${uuid}",
            "alterId": 1
#none
          }
        ]
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/v2ray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /etc/v2ray/vless.json << END
{
  "log": {
    "access": "/var/log/v2ray/access2.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 2083,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
#tls
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "security": "tls",
        "tlsSettings": {
          "certificates": [
            {
              "certificateFile": "etc/v2ray/v2ray.crt",
              "keyFile": "/etc/v2ray/v2ray.key"
            }
          ]
        },
        "wsSettings": {
          "path": "/v2ray",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat> /etc/v2ray/vnone.json << END
{
  "log": {
    "access": "/var/log/v2ray/access2.log",
    "error": "/var/log/v2ray/error.log",
    "loglevel": "info"
  },
  "inbounds": [
    {
      "port": 8880,
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${uuid}"
#none
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "ws",
        "wsSettings": {
          "path": "/e-jhoy",
          "headers": {
            "Host": ""
          }
         },
        "quicSettings": {},
        "sockopt": {
          "mark": 0,
          "tcpFastOpen": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      },
      "domain": "$domain"
    }
  ],
  "outbounds": [
    {
      "protocol": "freedom",
      "settings": {}
    },
    {
      "protocol": "blackhole",
      "settings": {},
      "tag": "blocked"
    }
  ],
  "routing": {
    "rules": [
      {
        "type": "field",
        "ip": [
          "0.0.0.0/8",
          "10.0.0.0/8",
          "100.64.0.0/10",
          "169.254.0.0/16",
          "172.16.0.0/12",
          "192.0.0.0/24",
          "192.0.2.0/24",
          "192.168.0.0/16",
          "198.18.0.0/15",
          "198.51.100.0/24",
          "203.0.113.0/24",
          "::1/128",
          "fc00::/7",
          "fe80::/10"
        ],
        "outboundTag": "blocked"
      },
      {
        "type": "field",
        "outboundTag": "blocked",
        "protocol": [
          "bittorrent"
        ]
      }
    ]
  }
}
END
cat <<EOF > /etc/trojan/config.json
{
    "run_type": "server",
    "local_addr": "0.0.0.0",
    "local_port": 2087,
    "remote_addr": "127.0.0.1",
    "remote_port": 2603,
    "password": [
        "$uuid"
    ],
    "log_level": 1,
    "ssl": {
        "cert": "/etc/v2ray/v2ray.crt",
        "key": "/etc/v2ray/v2ray.key",
        "key_password": "",
        "cipher": "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384",
        "cipher_tls13": "TLS_AES_128_GCM_SHA256:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_256_GCM_SHA384",
        "prefer_server_cipher": true,
        "alpn": [
            "http/1.1"
        ],
        "reuse_session": true,
        "session_ticket": false,
        "session_timeout": 600,
        "plain_http_response": "",
        "curves": "",
        "dhparam": ""
    },
    "tcp": {
        "prefer_ipv4": false,
        "no_delay": true,
        "keep_alive": true,
        "reuse_port": false,
        "fast_open": false,
        "fast_open_qlen": 20
    },
    "mysql": {
        "enabled": false,
        "server_addr": "127.0.0.1",
        "server_port": 3306,
        "database": "trojan",
        "username": "trojan",
        "password": "",
        "key": "",
        "cert": "",
        "ca": ""
    }
}
EOF
cat <<EOF> /etc/systemd/system/trojan.service
[Unit]
Description=Trojan
Documentation=https://trojan-gfw.github.io/trojan/

[Service]
Type=simple
ExecStart=/usr/local/bin/trojan -c /etc/trojan/config.json -l /var/log/trojan.log
Type=simple
KillMode=process
Restart=no
RestartSec=42s

[Install]
WantedBy=multi-user.target

EOF

cat <<EOF > /etc/trojan/uuid.txt
$uuid
EOF
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 2087 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 2083 -j ACCEPT
iptables -I INPUT -m state --state NEW -m tcp -p tcp --dport 8880 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2087 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 8443 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 80 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 2083 -j ACCEPT
iptables -I INPUT -m state --state NEW -m udp -p udp --dport 8880 -j ACCEPT
iptables-save > /etc/iptables.up.rules
iptables-restore -t < /etc/iptables.up.rules
netfilter-persistent save
netfilter-persistent reload
systemctl daemon-reload
systemctl enable v2ray@none.service
systemctl start v2ray@none.service
systemctl enable v2ray@vless.service
systemctl start v2ray@vlessservice
systemctl enable v2ray@vnone.service
systemctl start v2ray@vnone.service
systemctl restart trojan
systemctl enable trojan
systemctl restart v2ray
systemctl enable v2ray
cd /usr/bin
wget -O add-ws "https://raw.githubusercontent.com/liuuufey/sc-noip/main/add-ws.sh"
wget -O add-vless "https://raw.githubusercontent.com/liuuufey/sc-noip/main/add-vless.sh"
wget -O add-tr "https://raw.githubusercontent.com/liuuufey/sc-noip/main/add-tr.sh"
wget -O del-ws "https://raw.githubusercontent.com/liuuufey/sc-noip/main/del-ws.sh"
wget -O del-vless "https://raw.githubusercontent.com/liuuufey/sc-noip/main/del-vless.sh"
wget -O del-tr "https://raw.githubusercontent.com/liuuufey/sc-noip/main/del-tr.sh"
wget -O cek-ws "https://raw.githubusercontent.com/liuuufey/sc-noip/main/cek-ws.sh"
wget -O cek-vless "https://raw.githubusercontent.com/liuuufey/sc-noip/main/cek-vless.sh"
wget -O cek-tr "https://raw.githubusercontent.com/liuuufey/sc-noip/main/cek-tr.sh"
wget -O renew-ws "https://raw.githubusercontent.com/liuuufey/sc-noip/main/renew-ws.sh"
wget -O renew-vless "https://raw.githubusercontent.com/liuuufey/sc-noip/main/renew-vless.sh"
wget -O renew-tr "https://raw.githubusercontent.com/liuuufey/sc-noip/main/renew-tr.sh"
wget -O certv2ray "https://raw.githubusercontent.com/liuuufey/sc-noip/main/cert.sh"
chmod +x add-ws
chmod +x add-vless
chmod +x add-tr
chmod +x del-ws
chmod +x del-vless
chmod +x del-tr
chmod +x cek-ws
chmod +x cek-vless
chmod +x cek-tr
chmod +x renew-ws
chmod +x renew-vless
chmod +x renew-tr
chmod +x certv2ray
cd
rm -f ins-vt.sh
mv /root/domain /etc/v2ray
clear
