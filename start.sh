#!/bin/bash
BOTNAME="thelibertybot"

export TZ=EST5EDT
export EDITOR=vi
export PIP_USER=yes

alias startwatch="cd ~/github/bots/${BOTNAME};/usr/bin/screen -dmS ${BOTNAME} python3 ${BOTNAME}.py"
alias watchlog="tail -f ~/github/bots/${BOTNAME}/bot.log"
alias watchstatus="ps -ef|grep ${BOTNAME}.py |grep -v grep"

BOTDIR="${HOME}/github/bots/${BOTNAME}"
cd $BOTDIR
BOTPIDFILE="${BOTDIR}/bot.pid"
BOTPID=$(cat ${BOTPIDFILE})

if [ -f ${BOTDIR}/DONOTSTART ]; then
	exit 0
fi

if ! ps -ef |awk '{print $2}' |grep -q ${BOTPID}; then
    	/usr/bin/screen -dmS ${BOTNAME} python3 -u ${BOTNAME}.py
else
	echo "Bot running: pid=${BOTPID}" 
	exit 0
fi

