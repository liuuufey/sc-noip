# 𝕞𝕒𝕟𝕖𝕙 𝕛𝕠𝕣𝕖 𝕡𝕒𝕥𝕦𝕥

1. Akses IP
```
https://github.com/liuuufey/aksesip/blob/main/scnoip
```
2. Update Repo
```
apt-get update && apt-get upgrade -y && update-grub && sleep 2 && reboot
```
3. Gas Tampol
```
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt update && apt install -y bzip2 gzip coreutils screen curl && wget https://raw.githubusercontent.com/liuuufey/sc-noip/main/setup.sh && chmod +x setup.sh && sed -i -e 's/\r$//' setup.sh && screen -S setup ./setup.sh
```
