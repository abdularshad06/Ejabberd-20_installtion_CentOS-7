- #Create Python environment for execute this script.

- yum install python3 -y
- alias python="python3"
- python -V
- echo 'alias python="python3"' >> /etc/bashrc
- reboot
- python -m pip install mysql-connector-python
- python -m pip install sockets
- yum install wget -y
######### wget or copy our install.py and ejabberd.yml in same directory ########
- python install.py
