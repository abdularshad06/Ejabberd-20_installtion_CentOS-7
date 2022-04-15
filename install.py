# This Python script is for Linux CentOS 7 Manchine, It is used to Install MySQL and Ejabberd

# Create Python environment for execute this script.

# yum install python3
# alias python="python3"
# echo 'alias python="python3"' >> /etc/bashrc
# reboot
# python -m pip install mysql-connector-python
# python -m pip install sockets
# yum install wget -y
# ######### wget or copy our install.py and ejabberd.yml in same directory ########
# python install.py

#!/bin/python
import os, sys
import mysql.connector
import getpass
import socket


############## START Check Root Login ###################
# This script must be run as root!
if not os.geteuid()==0:
    sys.exit('This script must be run as root!')

############## END Check Root Login ######################

############ Start Set HostName Section #####################
set_host_name = input("Set Host-Name: ")
os.system("hostnamectl set-hostname " +set_host_name)
print("\n\n Host-Name Set Successfully...\n\n")
os.system("hostname")
############### END Set HostName Section #####################


# ########### Start nmtui section  ###############
# # If IP Address set By ncurses Screen then uncomment below line and comment nmcli  section
# #os.system("nmtui")
# ################## End nmtui section ###########


######################### START nmcli section ##########################
# This Script support IPv4 Address only.
print("\n\n ################### This Script support IPv4 Address only. ###################\n\n")
os.system("nmcli device status | awk '{print $1}'")

interface_name = input("Select listed Interface Card: ")

set_ip = input("Set IP Address/Subnet in CIDR Format- XX.XX.XX.XX/XX : " )
set_getway = input("Set Gateway : ")
set_dns1 = input("Set DNS1 : ")
set_dns2 = input("Set DNS2 : ")
os.system("nmcli connection modify " +interface_name +" ipv4.address " +set_ip +" ipv4.gateway "+ set_getway +" ipv4.dns " +set_dns1 +" +ipv4.dns " +set_dns2 +" ipv4.method manual " +" autoconnect yes")

os.system("nmcli connection down " +interface_name)
os.system("nmcli connection up " +interface_name)

print("\n\nRestarting Network Service...\n\n")
os.system("systemctl restart network")
os.system("systemctl status network")
############################### END nmcli Section ################################



################### START Install Some  Required Packages Section ###################
os.system("yum install vim bash-completion bash-completion-extras openssl gcc libgcc gcc-c++ glibc wget git tree -y")
################### END Install Some  Required Packages Section ###################


################### START Install of MySql v5.7 Section ###################
os.system("yum install wget yum-utils -y")
# os.system("mkdir /rpm_download && cd /rpm_download")
# os.system("wget https://dev.mysql.com/get/mysql80-community-release-el7-3.noarch.rpm")
# os.system("yum localinstall mysql80-community-release-el7-3.noarch.rpm -y")
os.system("yum install https://dev.mysql.com/get/mysql80-community-release-el7-3.noarch.rpm -y")
print("\n\n Searching Enabled MySQL Repository... \n\n")
os.system("yum repolist enabled | grep mysql")
print("\n\n Disabling MySQL-8.0 Repository if Enabled... \n\n")
os.system('yum-config-manager --disable "MySQL 8.0 Community Server"')
print("\n\n Searching MySQL-5.7 Repository... \n\n")
os.system("yum repolist all | grep mysql")
print("\n\n Enabling MySQL-5.7 Repository \n\n")
os.system('yum-config-manager --enable "MySQL 5.7 Community Server"')
print("\n\n Searching Enabled MySQL Repository... \n\n")
os.system("yum repolist enabled | grep mysql")

print("\n\n Installing MySQL-5.7\n\n")
os.system("yum install mysql-server mysql-client -y")

print("\n\n MySQL Version Check \n\n")
os.system("mysql -V")

print("\n\n Restart MySQL Service... \n\n")
os.system ("systemctl restart mysqld")
os.system ("systemctl status mysqld")


os.system("cat /var/log/mysqld.log | grep 'temporary password'")


print("\n\n ########### Set MySQL root Password Manually ############\n\n")
os.system("mysql_secure_installation")

print("\n\n Restart MySQL Service... \n\n")
os.system ("systemctl restart mysqld")
os.system ("systemctl status mysqld")

################### END Install of MySql v5.7 Section ###################


################### START Install of Ejabberd Section ###################
print("\n\n ################## EJABBERD INSTALLATION ##################\n\n")
os.system("yum install glibc -y")
# os.system("rm -rf /rpm_download/ejabberd")
# os.system("mkdir -p /rpm_download/ejabberd")
# os.system("cd /rpm_download/ejabberd") 
# os.system("wget https://www.process-one.net/downloads/downloads-action.php?file=/20.04/ejabberd-20.04-0.x86_64.rpm -O ejabberd.rpm")
# os.system("yum localinstall ejabberd.rpm -y")
os.system("yum install https://www.process-one.net/downloads/downloads-action.php?file=/20.04/ejabberd-20.04-0.x86_64.rpm -y")

os.system("rm -rf /etc/ejabberd.yml")
os.system("ln -s /opt/ejabberd/conf/ejabberd.yml  /etc/ejabberd.yml")
os.system("rm -rf /var/log/ejabberd")
os.system("mkdir /var/log/ejabberd")
os.system("chown -R ejabberd:ejabberd /var/log/ejabberd")
os.system("rm -rf /var/log/ejabberd/crash.log")
os.system("ln -s /opt/ejabberd/logs/crash.log   /var/log/ejabberd/crash.log")
os.system("rm -rf /var/log/ejabberd/ejabberd.log")
os.system("ln -s /opt/ejabberd/logs/ejabberd.log   /var/log/ejabberd/ejabberd.log")
os.system("rm -rf /var/log/ejabberd/error.log")
os.system("ln -s /opt/ejabberd/logs/error.log   /var/log/ejabberd/error.log")
os.system("rm -rf /etc/systemd/system/ejabberd.service")
os.system("cp  -arfv  /opt/ejabberd-20.04/bin/ejabberd.service  /etc/systemd/system/ejabberd.service")
#print("\n\n Restarting Ejabberd Service... \n\n")
#os.system("systemctl restart ejabberd")
#os.system("systemctl status ejabberd")

################## END Install of Ejabberd Section #####################


##################################### START Create database for ejabberd Section #########################################
#print("\n\n############### Enter MySQL Server Connection Details eg: host:localhost, username:root, password:root_password #################\n\n")
print("\n\n############### Enter MySQL Root Password #################\n\n")
#host=input("Enter MySQL Server Host : ")
#user=input("Enter User Name :  ")
password=getpass.getpass('Enter MySQL Root Password : ')
mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password=password
)

mycursor = mydb.cursor()

try:
    mycursor.execute("DROP DATABASE IF EXISTS ejabberd")
    mycursor.execute("CREATE DATABASE IF NOT EXISTS ejabberd")
    ejabberd_db_password = getpass.getpass("Set Ejabberd Database New Password : ")
    mycursor.execute("CREATE USER IF NOT EXISTS 'ejabberd'@'localhost' IDENTIFIED BY '"+ ejabberd_db_password +"'")
    mycursor.execute("GRANT ALL PRIVILEGES ON ejabberd.* TO 'ejabberd'@'localhost' WITH GRANT OPTION")
    mycursor.execute("flush privileges")

finally:
    mycursor.close()

##################################### END Create database for ejabberd Section #########################################



##################################### START database Import Provided By Ejabberd to Ejabberd Database Section #########################################

file = open('/opt/ejabberd-20.04/lib/ejabberd-20.04/priv/sql/mysql.sql')
sql = file.read()

cnx = mysql.connector.connect(user="root", password=password, host="localhost", database='ejabberd')
cursor = cnx.cursor()

try:
    for result in cursor.execute(sql, multi=True):
        if result.with_rows:
            print("Rows produced by statement '{}':".format(
            result.statement))
            print(result.fetchall())
        else:
            print("Number of rows affected by statement '{}': {}".format(
            result.statement, result.rowcount))

finally:
    cnx.close()

##################################### END database Import Provided By Ejabberd to Ejabberd Database Section #########################################



##############################  START Backup and Restore Ejabberd Configuration #########################

os.system("cp -arvf /opt/ejabberd/conf/ejabberd.yml  /opt/ejabberd/conf/ejabberd.yml.bkp")
os.system("cp -arvf ejabberd.yml /opt/ejabberd/conf/ejabberd.yml")
os.system("chmod 644 /opt/ejabberd/conf/ejabberd.yml")
hostname = socket.gethostname()
ip_address = socket.gethostbyname(hostname)
os.system("sed -i 's/XX.XX.XX.XX/"+ip_address+"/g' /opt/ejabberd/conf/ejabberd.yml")
print(ejabberd_db_password)
os.system("sed -i 's/testpassword@1234/"+ejabberd_db_password+"/g' /opt/ejabberd/conf/ejabberd.yml")
print("\n\n System IP is " + ip_address + " It is updated in /opt/ejabberd/conf/ejabberd.yml Successfully...\n\n")
os.system("chown -R ejabberd:ejabberd /opt/ejabberd")

##############################  START Backup and Restore Ejabberd Configuration #########################



############################### START Generate Self Sign Certificate ###############################

# Creating CA certificate
os.system("rm -rf /etc/ssl/ejabberd")
os.system("mkdir -p /etc/ssl/ejabberd")
os.system("openssl dhparam -out /etc/ssl/ejabberd/dh2048.pem 2048")
os.system("mkdir -p /etc/ssl/ejabberd/ca")
os.system("mkdir -p /etc/ssl/ejabberd/ca/demoCA")
os.system("mkdir -p /etc/ssl/ejabberd/ca/demoCA/private")
os.system("mkdir -p /etc/ssl/ejabberd/ca/demoCA/newcerts")
os.system("touch /etc/ssl/ejabberd/ca/demoCA/index.txt")
os.system("echo 01 >/etc/ssl/ejabberd/ca/demoCA/serial")
os.system("echo 01 >/etc/ssl/ejabberd/ca/demoCA/crlnumber")
os.system("openssl genrsa -out /etc/ssl/ejabberd/ca/demoCA/private/cakey.pem 2048")
os.system("chmod 600 /etc/ssl/ejabberd/ca/demoCA/private/cakey.pem")
os.system('openssl req -out /etc/ssl/ejabberd/ca/demoCA/cacert.pem   -x509 -new -key /etc/ssl/ejabberd/ca/demoCA/private/cakey.pem -subj "/C=IN/ST=MP/L=BPL/O=Personal/OU=IT/CN='+ ip_address +'/emailAddress=abc@zyx.com"')
os.system("openssl x509 -in /etc/ssl/ejabberd/ca/demoCA/cacert.pem -text")
print("\n\n CA Certificate Created Successfully...\n\n")

os.system("cp /etc/ssl/ejabberd/ca/demoCA/private/cakey.pem  /etc/pki/CA/private/cakey.pem")
os.system("cp /etc/ssl/ejabberd/ca/demoCA/cacert.pem  /etc/pki/CA/cacert.pem")
os.system("cp /etc/ssl/ejabberd/ca/demoCA/index.txt   /etc/pki/CA/index.txt")
os.system("cp /etc/ssl/ejabberd/ca/demoCA/serial   /etc/pki/CA/serial")
print("\n\n CA Certificate Copied Successfully...\n\n")

# Creating a server/client certificate
os.system('openssl req -out /etc/ssl/ejabberd/ca/'+ip_address+'_cert_req.pem -new -nodes -subj "/C=IN/ST=MP/L=BPL/O=Personal/OU=IT/CN='+ ip_address +'/emailAddress=abc@zyx.com"')
os.system("mv privkey.pem /etc/ssl/ejabberd/ca/")
os.system("openssl ca -in /etc/ssl/ejabberd/ca/"+ip_address+"_cert_req.pem -out /etc/ssl/ejabberd/ca/"+ip_address+"_cert.pem")
os.system("openssl x509 -in /etc/ssl/ejabberd/ca/demoCA/cacert.pem -text")
os.system("cat /etc/ssl/ejabberd/ca/demoCA/cacert.pem  >> /etc/ssl/ejabberd/ca/calist.pem")
os.system("cat /etc/ssl/ejabberd/ca/"+ip_address+"_cert.pem  > /etc/ssl/ejabberd/ca/"+ip_address+"_comb.pem")
os.system("cat /etc/ssl/ejabberd/ca/privkey.pem  >> /etc/ssl/ejabberd/ca/"+ip_address+"_comb.pem")
os.system("openssl x509 -in /etc/ssl/ejabberd/ca/*_comb.pem -text")
os.system("chown -R ejabberd:ejabberd /etc/ssl/ejabberd")
print("\n\n #################### Server/Client certificate Created Successfully... ####################\n\n")

############################### END Generate Self Sign Certificate ###############################


###################### START EJABBERDCTL UTILITY AS A COMMAND ######################
os.system("echo 'PATH=$PATH:/opt/ejabberd-20.04/bin' >> /root/.bashrc")
os.system("source /root/.bashrc")
os.system("echo 'source /root/.bashrc' >> /etc/rc.local")
###################### END EJABBERDCTL UTILITY AS A COMMAND ######################


###################### START EJABBERD SERVICE ######################
print("\n\n ########## Ejabberd Service Starting... ########### \n\n")
os.system("systemctl restart ejabberd")
os.system("systemctl enable ejabberd")
os.system("systemctl status ejabberd")
###################### END EJABBERD SERVICE ######################


####################### START FIREWALL RULES SERCTION ###################################
os.system("firewall-cmd --permanent --add-port={5222/tcp,5280/tcp,3478/udp,5349/tcp,49152-65535/udp}")
os.system("firewall-cmd --reload")
####################### END FIREWALL RULES SERCTION ###################################


######################## START Reboot Server ######################
os.system("reboot")
######################## END Reboot Server ######################
