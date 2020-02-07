#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

systemctl stop nginx &> /dev/null
sleep 2
"/root/.acme.sh"/acme.sh --cron --home "/root/.acme.sh" &> /dev/null
sleep 2
systemctl start nginx &> /dev/null
