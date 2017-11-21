#!/usr/bash


	###########################################
	###	  Castro Rendón Virgilio	###
	###########################################
#| | | | \ | | / _ \ |  \/  |      /  __ \|  ___| ___ \_   _|
#| | | |  \| |/ /_\ \| .  . |______| /  \/| |__ | |_/ / | |
#| | | | . ` ||  _  || |\/| |______| |    |  __||    /  | |
#| |_| | |\  || | | || |  | |      | \__/\| |___| |\ \  | |
# \___/\_|_\_/\_|_|_/\_| _|_/       \____/\____/\_| \_| \_/
#
#
# _       _  ____ ____ _  __
#| |     / / ___/ ___// //_/
#| | /| / /\__ \\__ \/ ,<
#| |/ |/ /___/ /__/ / /| |
#|__/|__//____/____/_/ |_|



LOG="`pwd`/installWSSK.log"
userName=`whoami`
repositoryChange=0



user_install()
{
	if [ $userName != "root" ]; then
		echo
		echo "##########################################"
		echo "#Use the root account to run this script #"
		echo "##########################################"
		echo
		exit 1
	fi
}



banner_log()
{
	echo                                           > $LOG
	echo                                          >> $LOG
	echo "#####################################################" >> $LOG
	echo "###    Web Security Swiss Knife INSTALLATION     ####" >> $LOG
	echo "#####################################################" >> $LOG
	echo                                          >> $LOG
	echo                                          >> $LOG
	echo
	echo
	echo "#####################################################"
	echo "###    Web Security Swiss Knife INSTALLATION     ####"
	echo "#####################################################"
	echo
	echo
}



#Writes in log file the command and if it was correct or not
log_command()
{
	if [ $1 -ne 0 ]; then
		echo "[`date +"%F %X"`] : $2 : [ERROR]" >> $LOG
		exit_install
	else
		echo "[`date +"%F %X"`] : $2 : [OK]" 	>> $LOG
	fi
}



#########################################
#	Starts the installation		#
#########################################

user_install
banner_log

cmd="apt-get update"
$cmd
log_command $? "$cmd"

cmd="apt-get install -y python-pip git-core libssl-dev swig nmap"
$cmd
log_command $? "$cmd"

cmd="pip install virtualenv"
$cmd
log_command $? "$cmd"

cmd="mkdir /opt/wssk"
$cmd
log_command $? "$cmd"

cmd="cd /opt/wssk"
$cmd
log_command $? "$cmd"

cmd="virtualenv wssk-venv"
$cmd
log_command $? "$cmd"

cmd="source wssk-venv/bin/activate"
$cmd
log_command $? "$cmd"

cmd="pip install django pycrpto urllib3 requests m2crypto anytree"
$cmd
log_command $? "$cmd" 

cmd="git clone https://github.com/Siegfried148/WSSK"
$cmd
log_command $? "$cmd"

cmd="mkdir /opt/wssk/lists"
$cmd
log_command $? "$cmd"

cmd="cp /opt/wssk/WSSK/tools/admin_dirs.short /opt/wssk/lists/admin_dirs"
$cmd
log_command $? "$cmd"

cmd="cp /opt/wssk/WSSK/tools/backup_names.short /opt/wssk/lists/backup_names"
$cmd
log_command $? "$cmd"

cmd="cp /opt/wssk/WSSK/tools/installation_dirs /opt/wssk/lists/installation_dirs"
$cmd
log_command $? "$cmd"

cmd="cp /opt/wssk/WSSK/tools/sensitive_files.short /opt/wssk/lists/sensitive_files"
$cmd
log_command $? "$cmd"

cmd="cp /opt/wssk/WSSK/tools/index_files.short /opt/wssk/lists/index_files"
$cmd
log_command $? "$cmd"

cmd="cd /opt/wssk/WSSK"
$cmd
log_command $? "$cmd"

cmd="python manage.py runserver 0.0.0.0:8000"
$cmd
log_command $? "$cmd"

cmd=""
$cmd
log_command $? "$cmd"

