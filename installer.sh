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

exit_install()
{
	echo >> $LOG
	echo "[`date +"%F %X"`] - The installation script failed" >> $LOG
	echo >> $LOG
	echo
	echo "[`date +"%F %X"`] - The installation script failed"
	echo
	end_repository
	exit 1
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

activate () {
	. /opt/wssk/wssk-venv/bin/activate
}


#########################################
#	Starts the installation		#
#########################################

user_install
banner_log
echo -n "Enter the IP address that will be used by WSSK > "
read ip_address

cmd="apt-get update"
$cmd
log_command $? "$cmd"

cmd="apt-get install -y python-pip git-core libssl-dev swig nmap traceroute whois"
$cmd
log_command $? "$cmd"

cmd="pip install virtualenv"
$cmd
log_command $? "$cmd"

cmd="mkdir /opt/wssk"
$cmd
log_command $? "$cmd"

cmd="virtualenv /opt/wssk/wssk-venv"
$cmd
log_command $? "$cmd"

activate

cmd="pip install django pycrypto urllib3 requests m2crypto anytree"
$cmd
log_command $? "$cmd" 

cmd="cd /opt/wssk"
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

cmd="mkdir /opt/wssk/db"
$cmd
log_command $? "$cmd"

cmd="python /opt/wssk/WSSK/database.py"
$cmd
log_command $? "$cmd"

sed -i "s/\(substitute-address\)/$ip_address/" /opt/wssk/WSSK/wssk/settings.py

cmd="python /opt/wssk/WSSK/manage.py runserver 0.0.0.0:8000"
$cmd
log_command $? "$cmd"

