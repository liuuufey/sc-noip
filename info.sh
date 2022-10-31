#!/bin/bash

clear
neofetch
echo -e    ""
echo -e    ""
echo -e    "  Information System VPS :"
ISP=$(curl -s ipinfo.io/org | cut -d " " -f 2-10 )
CITY=$(curl -s ipinfo.io/city )
WKT=$(curl -s ipinfo.io/timezone )
IPVPS=$(curl -s ipinfo.io/ip )
    cname=$( awk -F: '/model name/ {name=$2} END {print name}' /proc/cpuinfo )
   	cores=$( awk -F: '/model name/ {core++} END {print core}' /proc/cpuinfo )
	freq=$( awk -F: ' /cpu MHz/ {freq=$2} END {print freq}' /proc/cpuinfo )
	tram=$( free -m | awk 'NR==2 {print $2}' )
	swap=$( free -m | awk 'NR==4 {print $2}' )
	up=$(uptime|awk '{ $1=$2=$(NF-6)=$(NF-5)=$(NF-4)=$(NF-3)=$(NF-2)=$(NF-1)=$NF=""; print }')
    echo -e  ""
	echo -e    "    \e[032;1mCPU Model:\e[0m $cname"
	echo -e    "    \e[032;1mNumber Of Cores:\e[0m $cores"
	echo -e    "    \e[032;1mCPU Frequency:\e[0m $freq MHz"
	echo -e    "    \e[032;1mTotal Amount Of RAM:\e[0m $tram MB"
	echo -e    "    \e[032;1mSystem Uptime:\e[0m $up"
    echo -e    "    \e[032;1mIsp Name:\e[0m $ISP"
    echo -e    "    \e[032;1mCity:\e[0m $CITY"
    echo -e    "    \e[032;1mTime:\e[0m $WKT"
    echo -e    "    \e[033;1mIPVPS:\e[0m $IPVPS"
echo -e    ""
echo -e    ""

