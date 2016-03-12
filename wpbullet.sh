#!/bin/bash

show_credentials() {
#--------------------------------------------------------------------------------------------------------------------------------
# Show credentials
#--------------------------------------------------------------------------------------------------------------------------------
echo "MySQL root password ${MYSQLROOTPASS}"
echo "WordPress MySQL username ${WORDPRESSSQLUSER}"
echo "WordPress MySQL password ${WORDPRESSSQLPASS}"
echo "WordPress MySQL database ${WORDPRESSSQLDB}"
}

clear_bash_history() {
#--------------------------------------------------------------------------------------------------------------------------------
# Erase bash history because we used MySQL root password
#--------------------------------------------------------------------------------------------------------------------------------
#http://askubuntu.com/questions/191999/how-to-clear-bash-history-completely
cat /dev/null > ~/.bash_history
}

get_user_input () {
#--------------------------------------------------------------------------------------------------------------------------------
# Get user input for WordPress
#--------------------------------------------------------------------------------------------------------------------------------
#generate random passwords http://www.howtogeek.com/howto/30184/10-ways-to-generate-a-random-password-from-the-command-line/
MYSQLROOTPASS=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
MYSQLROOTPASS=$(whiptail --inputbox "Choose the MySQL root password" 8 78 $MYSQLROOTPASS --title "$SECTION" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSQLDB=$(whiptail --inputbox "Choose the WordPress MySQL database name" 8 78 "WordPressDB" --title "$SECTION" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSQLUSER=$(whiptail --inputbox "Choose the WordPress MySQL user" 8 78 "WordPressMySQLuser" --title "$SECTION" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSQLPASS=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
WORDPRESSSQLPASS=$(whiptail --inputbox "Choose the WordPress MySQL password" 8 78 $WORDPRESSSQLPASS --title "$SECTION" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSITE=$(whiptail --inputbox "Choose the WordPress sitename" 8 78 "WP-Bullet.com" --title "$SECTION" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
}

install_nginx_fastcgi () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install nginx with fastcgi caching
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
install_dotdeb
install_nginx
cp configs/wordpressfastcgi /etc/nginx/sites-available/wordpress
ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/wordpress
install_mariadb
install_wordpress
#Fix CloudFlare IP
cat > /etc/nginx/conf.d/cloudflare.conf<<EOF
#CloudFlare
set_real_ip_from   199.27.128.0/21;
set_real_ip_from   173.245.48.0/20;
set_real_ip_from   103.21.244.0/22;
set_real_ip_from   103.22.200.0/22;
set_real_ip_from   103.31.4.0/22;
set_real_ip_from   141.101.64.0/18;
set_real_ip_from   108.162.192.0/18;
set_real_ip_from   190.93.240.0/20;
set_real_ip_from   188.114.96.0/20;
set_real_ip_from   197.234.240.0/22;
set_real_ip_from   198.41.128.0/17;
set_real_ip_from   162.158.0.0/15;
set_real_ip_from   104.16.0.0/12;
set_real_ip_from   172.64.0.0/13;
set_real_ip_from   2400:cb00::/32;
set_real_ip_from   2606:4700::/32;
set_real_ip_from   2803:f800::/32;
set_real_ip_from   2405:b500::/32;
set_real_ip_from   2405:8100::/32;
#Set the real ip header
real_ip_header     CF-Connecting-IP;
EOF
service nginx restart
service php5-fpm restart
show_credentials
clear_bash_history
}

install_nginx_varnish () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install nginx and Varnish
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
install_dotdeb
install_nginx
cp configs/wordpressvarnish /etc/nginx/sites-available/wordpress
ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/wordpress
install_mariadb
install_varnish
cp configs/default.vcl /etc/varnish/default.vcl
sed -i s"/Web.Server.IP/${SERVERIP}/" /etc/varnish/default.vcl
install_wordpress
#Fix CloudFlare IP
cat > /etc/nginx/conf.d/cloudflare.conf<<EOF
#CloudFlare
set_real_ip_from   199.27.128.0/21;
set_real_ip_from   173.245.48.0/20;
set_real_ip_from   103.21.244.0/22;
set_real_ip_from   103.22.200.0/22;
set_real_ip_from   103.31.4.0/22;
set_real_ip_from   141.101.64.0/18;
set_real_ip_from   108.162.192.0/18;
set_real_ip_from   190.93.240.0/20;
set_real_ip_from   188.114.96.0/20;
set_real_ip_from   197.234.240.0/22;
set_real_ip_from   198.41.128.0/17;
set_real_ip_from   162.158.0.0/15;
set_real_ip_from   104.16.0.0/12;
set_real_ip_from   172.64.0.0/13;
set_real_ip_from   2400:cb00::/32;
set_real_ip_from   2606:4700::/32;
set_real_ip_from   2803:f800::/32;
set_real_ip_from   2405:b500::/32;
set_real_ip_from   2405:8100::/32;
#Set the real ip header
set_real_ip_from   127.0.0.1/32;
real_ip_header     X-Actual-IP;
EOF
service nginx restart
service php5-fpm restart
service varnish restart
show_credentials
clear_bash_history
}

install_nginx_varnish_haproxy () {
#--------------------------------------------------------------------------------------------------------------------------------
# install nginx with Varnish SSL Terminal from haproxy
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
install_dotdeb
install_nginx
cp configs/wordpressvarnish /etc/nginx/sites-available/wordpress
ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/wordpress
install_mariadb
install_varnish
cp configs/default.vcl /etc/varnish/default.vcl
sed -i s"/Web.Server.IP/${SERVERIP}/" /etc/varnish/default.vcl
install_haproxy
install_wordpress
#WordPress SSL fix
echo "if (\$_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')
        \$_SERVER['HTTPS']='on';" >> /var/www/${WORDPRESSSITE}/wp-config.php
#Fix CloudFlare IP
cat > /etc/nginx/conf.d/cloudflare.conf<<EOF
#CloudFlare
set_real_ip_from   199.27.128.0/21;
set_real_ip_from   173.245.48.0/20;
set_real_ip_from   103.21.244.0/22;
set_real_ip_from   103.22.200.0/22;
set_real_ip_from   103.31.4.0/22;
set_real_ip_from   141.101.64.0/18;
set_real_ip_from   108.162.192.0/18;
set_real_ip_from   190.93.240.0/20;
set_real_ip_from   188.114.96.0/20;
set_real_ip_from   197.234.240.0/22;
set_real_ip_from   198.41.128.0/17;
set_real_ip_from   162.158.0.0/15;
set_real_ip_from   104.16.0.0/12;
set_real_ip_from   172.64.0.0/13;
set_real_ip_from   2400:cb00::/32;
set_real_ip_from   2606:4700::/32;
set_real_ip_from   2803:f800::/32;
set_real_ip_from   2405:b500::/32;
set_real_ip_from   2405:8100::/32;
#Set the real ip header
set_real_ip_from   127.0.0.1/32;
real_ip_header     X-Actual-IP;
EOF
service nginx restart
service php5-fpm restart
service varnish restart
service haproxy restart
show_credentials
clear_bash_history
}

install_dotdeb () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install dotdeb repo
#--------------------------------------------------------------------------------------------------------------------------------
wget -qO - http://www.dotdeb.org/dotdeb.gpg | apt-key add -
cat > /etc/apt/sources.list.d/dotdeb.list<<EOF
deb http://packages.dotdeb.org jessie all
EOF
}

install_nginx () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install nginx
#--------------------------------------------------------------------------------------------------------------------------------
install_dotdeb
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install nginx -y
cp configs/nginx.conf /etc/nginx/nginx.conf
unlink /etc/nginx/sites-enabled/default
service nginx restart
}

install_wordpress () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install wordpress
#--------------------------------------------------------------------------------------------------------------------------------

debconf-apt-progress -- apt-get install curl php5-curl php5-mysql php5-cli php5-fpm php5-gd -y
cp configs/www.conf /etc/php5/fpm/pool.d/www.conf
mkdir -p /var/www/${WORDPRESSSITE}
cd /var/www/${WORDPRESSSITE}
wget http://wordpress.org/latest.tar.gz
tar --strip-components=1 -xf latest.tar.gz
rm latest.tar.gz
chown -R www-data:www-data /var/www/${WORDPRESSSITE}

mysql -u root -p${MYSQLROOTPASS} -e "CREATE USER ${WORDPRESSSQLUSER}@localhost IDENTIFIED BY '${WORDPRESSSQLPASS}';"
mysql -u root -p${MYSQLROOTPASS} -e "CREATE DATABASE ${WORDPRESSSQLDB};"
mysql -u root -p${MYSQLROOTPASS} -e "GRANT ALL PRIVILEGES ON ${WORDPRESSSQLDB}.* TO ${WORDPRESSSQLUSER}@localhost IDENTIFIED BY '${WORDPRESSSQLPASS}';"
mysql -u root -p${MYSQLROOTPASS} -e "FLUSH PRIVILEGES;"

cp /var/www/${WORDPRESSSITE}/wp-config-sample.php wp-config.php
#replace wp-config variables with the WordPress MySQL user and password
sed -i "/define('DB_NAME', 'database_name_here');/c\define('DB_NAME', '${WORDPRESSSQLDB}');" /var/www/${WORDPRESSSITE}/wp-config.php
sed -i "/define('DB_USER', 'username_here');/c\define('DB_USER', '${WORDPRESSSQLUSER}');" /var/www/${WORDPRESSSITE}/wp-config.php
sed -i "/define('DB_PASSWORD', 'password_here');/c\define('DB_PASSWORD', '${WORDPRESSSQLPASS}');" /var/www/${WORDPRESSSITE}/wp-config.php
chown -R www-data:www-data /var/www/${WORDPRESSSITE}/
chmod 755 /var/www/${WORDPRESSSITE}/
chmod 644 /var/www/${WORDPRESSSITE}/wp-config.php
}

install_mariadb () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install mariadb
#--------------------------------------------------------------------------------------------------------------------------------
debconf-apt-progress -- apt-get install debconf -y
echo "mariadb-server-10.0 mysql-server/root_password password ${MYSQLROOTPASS}" | debconf-set-selections
echo "mariadb-server-10.0 mysql-server/root_password_again password ${MYSQLROOTPASS}" | debconf-set-selections
debconf-apt-progress -- apt-get -y install mariadb-server mariadb-client
}

install_varnish (){
#--------------------------------------------------------------------------------------------------------------------------------
# Install high-performance HTTP accelerator
#-------------------------------------------------------------------------------------------------------------------------------- 
apt-get install apt-transport-https -y
wget -qO - https://repo.varnish-cache.org/GPG-key.txt | apt-key add -
cat > /etc/apt/sources.list.d/varnish-cache.list<<EOF
deb https://repo.varnish-cache.org/debian/ jessie varnish-4.1
EOF
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install varnish -y
mkdir -p /etc/systemd/system/varnish.service.d/
cat > /etc/systemd/system/varnish.service.d/local.conf<<EOF
[Service]
ExecStart=
ExecStart=/usr/sbin/varnishd -a :80 -T localhost:6082 -f /etc/varnish/default.vcl -S /etc/varnish/secret -s malloc,256m
EOF
systemctl daemon-reload
mv /etc/varnish/default.vcl /etc/varnish/default.vcl.bak
}

install_haproxy () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install haproxy
#--------------------------------------------------------------------------------------------------------------------------------
apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys 1C61B9CD
cat > /etc/apt/sources.list.d/haproxy.list<<EOF
deb http://ppa.launchpad.net/vbernat/haproxy-1.6/ubuntu trusty main
EOF
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install openssl haproxy -y
mv /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.bak
cp configs/haproxy.cfg /etc/haproxy/haproxy.cfg
#openssl req -new -newkey rsa:2048 -nodes -out /etc/ssl/wpbullet.pem -keyout /etc/ssl/wpbullet.pem -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"
openssl req -new -x509 -days 365 -nodes -out /etc/ssl/wp-bullet.pem -keyout /etc/ssl/wp-bullet.pem -subj "/C=/ST=/L=/O=Company Name/OU=Org/CN=${WORDPRESSSITE}"

}

install_webmin () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install webmin
#--------------------------------------------------------------------------------------------------------------------------------
#install csf with webmin module
sudo apt-get update
sudo apt-get install libauthen-pam-perl libio-pty-perl libnet-ssleay-perl libapt-pkg-perl apt-show-versions libwww-perl -y
cd /tmp
wget http://www.webmin.com/download/deb/webmin-current.deb
dpkg -i webmin*
}

install_csf () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install csf
#--------------------------------------------------------------------------------------------------------------------------------
#install csf
apt-get install iptables unzip -y
cd /tmp
wget https://download.configserver.com/csf.tgz
tar -xvf csf.tgz -C /opt
cd /opt/csf
bash /opt/csf/install.sh
#install csf webmin module
cd /usr/share/webmin
perl install-module.pl /etc/csf/csfwebmin.tgz
#install nginx webmin module
cd /tmp
wget http://www.justindhoffman.com/sites/justindhoffman.com/files/nginx-0.08.wbm__0.gz
cd /usr/share/webmin
perl install-module.pl /tmp/nginx-0.08.wbm__0.gz
#install opcache webmin module
#cd /tmp
#wget http://github.com/jesucarr/webmin-php-opcache-status/releases/download/v1.0/php-opcache-status.wbm.gz
#cd /usr/share/webmin
#perl install-module.pl /tmp/php-opcache-status.wbm.gz
#install php module
cd /tmp
wget http://www.webmin.com/webmin/download/modules/phpini.wbm.gz
cd /usr/share/webmin
perl install-module.pl /tmp/phpini.wbm.gz
echo "CSF Firewall is installed, configure it with this guide"
}

install_suhosin () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install suhosin
#--------------------------------------------------------------------------------------------------------------------------------
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install php5-dev git build-essential -y
cd /tmp
SUHOSINLATEST=$(wget -q -O - https://github.com/stefanesser/suhosin/releases/ | grep tar.gz | awk -F [\"] 'NR==1 {print $2}')
wget https://github.com$SUHOSINLATEST -O suhosin.tar.gz
tar -xvf suhosin.tar.gz
cd suhosin*
phpize
./configure
make
make install
PHPINI=($(find / -iname php.ini))
for ini in "${PHPINI[@]}"
do
  echo "extension=suhosin.so" >> "${ini}"
done
service php5-fpm restart
}

install_redis () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install suhosin
#--------------------------------------------------------------------------------------------------------------------------------
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install php5-dev build-essential -y
cd /tmp
#build redis
wget http://download.redis.io/redis-stable.tar.gz
tar xzf redis*
cd redis*
sudo make
sudo make install PREFIX=/usr
sudo mkdir /etc/redis
sudo cp redis.conf /etc/redis/
cd ..
rm -Rf redis*
#add redis user
adduser --system --user-group redis --no-create-home --shell /bin/nologin
mv /etc/redis/redis.conf /etc/redis/redis.conf.bak
#create redis configuration
cat > /etc/redis/redis.conf<<EOF
bind 127.0.0.1
daemonize yes
stop-writes-on-bgsave-error no
rdbcompression yes
maxmemory 50M
maxmemory-policy allkeys-lru
EOF
cat > /etc/systemd/system/redis-server.service<<EOF
[Unit]
Description=Redis Datastore Server
After=network.target
[Service]
Type=forking
User=redis
Group=redis
ExecStart=/usr/bin/redis-server /etc/redis/redis.conf --daemonize yes
[Install]
WantedBy=multi-user.target
EOF
systemctl enable redis-server
service redis-server start
#build the php extension
cd /tmp
debconf-apt-progress -- git -y
git clone https://github.com/phpredis/phpredis
cd phpredis
phpize
./configure
make
make install
PHPINI=($(find / -iname php.ini))
for ini in "${PHPINI[@]}"
do
  echo "extension=redis.so" >> "${ini}"
done
service php5-fpm restart
installer
}

#--------------------------------------------------------------------------------------------------------------------------------
# WELCOME SCREEN
#--------------------------------------------------------------------------------------------------------------------------------

whiptail --title "Welcome to the WP Bullet WordPress VPS Installer" --msgbox "This Ubuntu and Debian Installer will prompt for credentials and autoconfigure everything" 8 78
#get ip
SERVERIP=$(ifconfig eth0 | awk -F"[: ]+" '/inet addr:/ {print $4}')


#--------------------------------------------------------------------------------------------------------------------------------
# MAIN INSTALL
#--------------------------------------------------------------------------------------------------------------------------------

installer () {
ins_variable=$(whiptail --ok-button "Choose" --title "WP Bullet VPS Installer for Ubuntu/Debian (c) WP-Bullet.com" --menu "\nIP:   $serverIP\nFQDN: $HOSTNAMEFQDN\n\nChoose what you want to install:" 30 99 12 \
"nginx + fastcgi caching" "nginx with fastcgi caching        "  \
"nginx + Varnish" "nginx with Varnish caching        "  \
"nginx + Varnish + haproxy" "nginx with Varnish caching SSL termination by haproxy"  \
"Monit" "Monitor your programs"  \
"Webmin" "Easy GUI VPS administration"  \
"CSF Firewall" "Comprehensive Firewall"  \
"Suhosin" "Enable PHP Security"  \
"Redis" "Install Redis Server"  \
"Memcached" "Install Memcached"  \
"Create SWAP File" "Creates SWAP on your VPS"  3>&1 1>&2 2>&3) exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi


case $ins_variable in
	"nginx + fastcgi caching") 		install_nginx_fastcgi;;
	"nginx + Varnish") 			install_nginx_varnish;;
	"nginx + Varnish + haproxy") 		install_nginx_varnish_haproxy;;
	"Monit") 				install_monit;;
	"Webmin") 				install_webmin;;
	"CSF Firewall") 			install_csf;;
	"Suhosin") 				install_suhosin;;
	"Redis") 				install_redis;;
	"Memcached") 				install_memcached;;
	"Create SWAP File") 			install_swap;;
                *)
                ;;
esac
		
}

installer
