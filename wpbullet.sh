#!/bin/bash
#make sure you are root
if [ $(id -u) != "0" ]; then
    echo "You must be root to run this script, use root or a sudo user."
    exit 1
fi
#PHPTYPE=($(apt-cache search --names-only 'php.*(igbinary|gd|msgpack)$' | awk '{print $1}'))
#apt-get install ${PHPTYPE[@]}
#wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/wpbullet.sh -O destination

#check some essential software is installed
echo "Doing intial update, please wait"
apt-get update -qq
if dpkg-query -W wget debconf-utils whiptail; then
echo "Necessary Programs Installed :)"
else
echo "Installing necessary programs"
apt-get install wget debconf-utils whiptail -qq -y
#debconf-apt-progress -- apt-get upgrade -y
fi

show_summary() {
#--------------------------------------------------------------------------------------------------------------------------------
# Show summary
#--------------------------------------------------------------------------------------------------------------------------------
#define colors for output
red=`tput setaf 1`
green=`tput setaf 2`
yellow=`tput setaf 3`
blue=`tput setaf 4`
reset=`tput sgr0`
#echo "${red}red text ${green}green text${reset}"
echo -e "\n\n"
echo "${yellow}=== WP Bullet WordPress VPS Installer Complete ===${reset}"
echo ""
echo "${red}Copy the credentials somewhere safe in case you ever need them!${reset}"
echo ""
if [ "${ins_nginx_fastcgi}" == "true" ] || [ "${ins_nginx_fastcgissl}" == "true" ] || [ "${ins_nginx_varnish}" == "true" ] || [ "${ins_nginx_varnish_haproxy}" == "true" ] || [ "${ins_apache}" == "true" ] || [ "${ins_apache_nginx}" == "true" ]; then
echo -e "MySQL root password \t\t${green}${MYSQLROOTPASS}${reset}"
echo -e "WordPress MySQL username \t${green}${WORDPRESSSQLUSER}${reset}"
echo -e "WordPress MySQL password \t${green}${WORDPRESSSQLPASS}${reset}"
echo -e "WordPress MySQL database \t${green}${WORDPRESSSQLDB}${reset}"
echo -e "WordPress Admin username \t${green}${WPADMINUSER}${reset}"
echo -e "WordPress Admin password \t${green}${WPADMINPASS}${reset}"
echo "WordPress is available on ${green}${WORDPRESSSITE}${reset}"
echo ""
echo "If you chose SSL define your site as https in ${blue}General > Settings${reset}"
fi
if [ "${ins_monit}" == "true" ]; then
echo ""
echo "Monit is running on ${green}https://$SERVERIP:2812${reset}"
echo -e "Monit username is \t${green}${MONITUSER}${reset}"
echo -e "Monit password is \t${green}${MONITPASS}${reset}"
fi
if [ "${ins_webmin}" == "true" ]; then
echo ""
echo "Webmin is running on https://$SERVERIP:10000"
echo "Webmin username is system root or sudo user"
fi
echo ""
echo "WordPress VPS Installer by ${yellow}https://wp-bullet.com${reset}"
}

clear_bash_history() {
#--------------------------------------------------------------------------------------------------------------------------------
# Erase bash history because we used MySQL root password
#--------------------------------------------------------------------------------------------------------------------------------
#http://askubuntu.com/questions/191999/how-to-clear-bash-history-completely
cat /dev/null > ~/.bash_history
#http://serverfault.com/questions/332459/how-do-i-delete-values-from-the-debconf-database
#clear root mysql password from debconf
if hash mysqld  2>/dev/null; then
echo PURGE | debconf-communicate mariadb-server-10.0 > /dev/null
fi

}

get_user_input () {
#--------------------------------------------------------------------------------------------------------------------------------
# Get user input for WordPress
#--------------------------------------------------------------------------------------------------------------------------------
#if (("$ASKED" != "true")); then
#generate random passwords http://www.howtogeek.com/howto/30184/10-ways-to-generate-a-random-password-from-the-command-line/
#if (${ins_nginx_fastcgi} || ${ins_nginx_varnish} || ${ins_nginx_varnish_haproxy} == "true";) then
#if hash mysql 2>/dev/null; then
MYSQLROOTPASS=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
MYSQLROOTPASS=$(whiptail --inputbox "Choose the MySQL root password (use Ctr+U to clear random password)" 8 78 $MYSQLROOTPASS --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSQLDB=$(whiptail --inputbox "Choose the WordPress MySQL database name" 8 78 "WordPressDB" --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSQLUSER=$(whiptail --inputbox "Choose the WordPress MySQL user" 8 78 "WPMySQLuser" --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSQLPASS=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
WORDPRESSSQLPASS=$(whiptail --inputbox "Choose the WordPress MySQL password (use Ctr+U to clear random password)" 8 78 $WORDPRESSSQLPASS --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSSITE=$(whiptail --inputbox "Choose the WordPress site domain (include domain extension without www.)" 8 78 "WP-Bullet.com" --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WORDPRESSTITLE=$(whiptail --inputbox "Choose the WordPress site title" 8 78 "WP Bullet" --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WPADMINUSER=$(whiptail --inputbox "Choose the WordPress site admin username" 8 78 "wpadmin" --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WPADMINPASS=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
WPADMINPASS=$(whiptail --inputbox "Choose the WordPress admin password (use Ctr+U to clear below)" 8 78 $WPADMINPASS --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
WPADMINEMAIL=$(whiptail --inputbox "Choose the WordPress admin email" 8 78 "admin@wp-bullet.com" --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
}

install_nginx_fastcgi () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install nginx with fastcgi caching
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
#nginxssl=$(whiptail --ok-button "Choose" --title "fastcgi nginx security choice (c) WP-Bullet.com" --menu "\nChoose basic http or https:" 20 78 9 \
#"fastcgi http" "fastcgi http only        "  \
#"fastcgi https" "fastcgi https only        " 3>&1 1>&2 2>&3) exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
#if [ "$nginxssl" == "fastcgi https" ]; then
#install_nginx_fastcgissl
#fi
install_dotdeb
install_nginx
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/nginx/wordpressfastcgi -O /etc/nginx/sites-available/wordpress
ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/wordpress
install_mariadb
install_wordpress
#Fix CloudFlare IP
enable_cloudflare
service nginx restart
service php7.0-fpm restart

}

install_nginx_fastcgissl () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install nginx with fastcgi caching ssl
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
#generate ssl
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install openssl -y
mkdir -p /etc/nginx/ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/nginx/ssl/nginx.key -out /etc/nginx/ssl/nginx.crt -subj "/C=/ST=/L=/O=Company Name/OU=Org/CN=${WORDPRESSSITE}"
install_dotdeb
install_nginx
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/nginx/wordpressfastcgissl -O /etc/nginx/sites-available/wordpress
ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/wordpress
install_mariadb
install_wordpress
#Fix CloudFlare IP
enable_cloudflare
service nginx restart
service php7.0-fpm restart

}

install_nginx_varnish () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install nginx and Varnish
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
install_dotdeb
install_nginx
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/nginx/wordpressvarnish -O /etc/nginx/sites-available/wordpress
ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/wordpress
install_mariadb
install_varnish
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/default.vcl -O /etc/varnish/default.vcl
sed -i s"/Web.Server.IP/${SERVERIP}/" /etc/varnish/default.vcl
install_wordpress
#Fix CloudFlare IP
enable_cloudflare
sed -i s"/CF-Connecting-IP/X-Actual-IP/g" /etc/nginx/conf.d/cloudflare.conf
service nginx restart
service php7.0-fpm restart
service varnish restart
}

install_nginx_varnish_haproxy () {
#--------------------------------------------------------------------------------------------------------------------------------
# install nginx with Varnish SSL Terminal from haproxy
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
install_dotdeb
install_nginx
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/nginx/wordpressvarnish -O /etc/nginx/sites-available/wordpress
ln -s /etc/nginx/sites-available/wordpress /etc/nginx/sites-enabled/wordpress
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/wordpress
install_mariadb
install_varnish
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/default.vcl -O /etc/varnish/default.vcl
sed -i s"/Web.Server.IP/${SERVERIP}/" /etc/varnish/default.vcl
sed -i s"/DOMAIN/${WORDPRESSSITE}/" /etc/varnish/default.vcl
install_haproxy
install_wordpress
#WordPress SSL fix now use different vcl
#echo "if (\$_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https')
#        \$_SERVER['HTTPS']='on';" >> /var/www/${WORDPRESSSITE}/wp-config.php
#rm /var/www/${WORDPRESSSITE}/wp-config.php
#WPCONFIG=$(find / -iname wp-config.php | grep configs)
#cp $WPCONFIG /var/www/${WORDPRESSSITE}/wp-config.php
#sed -i "/define('DB_NAME', 'database_name_here');/c\define('DB_NAME', '${WORDPRESSSQLDB}');" /var/www/${WORDPRESSSITE}/wp-config.php
#sed -i "/define('DB_USER', 'username_here');/c\define('DB_USER', '${WORDPRESSSQLUSER}');" /var/www/${WORDPRESSSITE}/wp-config.php
#sed -i "/define('DB_PASSWORD', 'password_here');/c\define('DB_PASSWORD', '${WORDPRESSSQLPASS}');" /var/www/${WORDPRESSSITE}/wp-config.php
#sed -i "s/sitename/${WORDPRESSSITE}/" /var/www/${WORDPRESSSITE}/wp-config.php
#chown -R www-data:www-data /var/www/${WORDPRESSSITE}/
#chmod 755 /var/www/${WORDPRESSSITE}/
#chmod 644 /var/www/${WORDPRESSSITE}/wp-config.php
#Fix CloudFlare IP
enable_cloudflare
sed -i s"/CF-Connecting-IP/X-Actual-IP/g" /etc/nginx/conf.d/cloudflare.conf
service nginx restart
service php7.0-fpm restart
service varnish restart
service haproxy restart
}

install_apache_nginx () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install Apache with nginx reverse proxy with WordPress
#--------------------------------------------------------------------------------------------------------------------------------
install_apache
#fix apache ports to listen on 8080
sed -i s"/80/8080/g" /etc/apache2/ports.conf
sed -i s"/80/8080/g" /etc/apache2/sites-available/${WORDPRESSSITE}.conf
service apache2 restart
#nginx reverse proxy part
install_nginx
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/nginx/reverseproxy -O  /etc/nginx/sites-available/reverseproxy
ln -s /etc/nginx/sites-available/reverseproxy /etc/nginx/sites-enabled/reverseproxy
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/nginx/sites-enabled/reverseproxy
sed -i s"/Web.Server.IP/${SERVERIP}/g" /etc/nginx/sites-enabled/reverseproxy
service nginx restart
}

install_apache () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install Apache with WordPress
#--------------------------------------------------------------------------------------------------------------------------------
get_user_input
install_dotdeb
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install openssl apache2 php7.0 libapache2-mod-php7.0 php7.0-mcrypt php7.0-mysql php7.0-gd php7.0-cgi php7.0-common php7.0-curl -y
mkdir -p /etc/apache2/conf.d
cat > /etc/apache2/mods-enabled/dir.conf <<EOF
<IfModule mod_dir.c>
    DirectoryIndex index.php index.html index.cgi index.pl index.xhtml index.htm
</IfModule>
EOF
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/apache/apache2.conf -O /etc/apache2/apache2.conf
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/apache/apache2vhost -O /etc/apache2/sites-available/${WORDPRESSSITE}.conf
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/apache/apache2vhostssl -O /etc/apache2/sites-available/${WORDPRESSSITE}ssl.conf
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/apache2/sites-available/${WORDPRESSSITE}.conf
sed -i s"/example.com/${WORDPRESSSITE}/g" /etc/apache2/sites-available/${WORDPRESSSITE}ssl.conf
#install_mariadb
#install_wordpress
#ssl certificate
mkdir -p /etc/apache2/ssl
openssl req -new -x509 -days 365 -nodes -out /etc/apache2/ssl/wp-bullet.crt -keyout /etc/apache2/ssl/wp-bullet.key -subj "/C=/ST=/L=/O=Company Name/OU=Org/CN=${WORDPRESSSITE}"
a2enmod rewrite
a2enmod ssl
a2dissite 000-default
a2ensite ${WORDPRESSSITE}
a2ensite ${WORDPRESSSITE}ssl
install_mariadb
install_wordpress
cat > /var/www/${WORDPRESSSITE}/.htaccess<<EOF
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^index\.php\$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>
#prevent directory listing
Options -Indexes
EOF
chown -R www-data:www-data /var/www
service apache2 restart
}

enable_cloudflare () {
#--------------------------------------------------------------------------------------------------------------------------------
# Enable CloudFlare for nginx
#--------------------------------------------------------------------------------------------------------------------------------
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
real_ip_header     CF-Connecting-IP;
EOF
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
debconf-apt-progress -- apt-get install nginx nginx-extras -y
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/nginx/nginx.conf -O /etc/nginx/nginx.conf
unlink /etc/nginx/sites-enabled/default
debconf-apt-progress -- apt-get install curl php7.0-curl php7.0-mysql php7.0-cli php7.0-fpm php7.0-gd -y
wget https://github.com/wpbullet/WP-Bullet-VPS-Installer/raw/php7/configs/www.conf /etc/php/7.0/fpm/pool.d/www.conf
}

install_wordpress () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install wordpress
#--------------------------------------------------------------------------------------------------------------------------------
debconf-apt-progress -- apt-get install pngtools optipng gifsicle libjpeg-progs -y
wget -q https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar -O /usr/bin/wp
chmod 755 /usr/bin/wp
mkdir -p /var/www/${WORDPRESSSITE}
cd /var/www/${WORDPRESSSITE}
wp core download --path=/var/www/${WORDPRESSSITE} --allow-root
#wget -q http://wordpress.org/latest.tar.gz
#tar --strip-components=1 -xf latest.tar.gz
#rm latest.tar.gz
chown -R www-data:www-data /var/www/${WORDPRESSSITE}
cp /var/www/${WORDPRESSSITE}/wp-config-sample.php wp-config.php
#replace wp-config variables with the WordPress MySQL user and password
sed -i "/define('DB_NAME', 'database_name_here');/c\define('DB_NAME', '${WORDPRESSSQLDB}');" /var/www/${WORDPRESSSITE}/wp-config.php
sed -i "/define('DB_USER', 'username_here');/c\define('DB_USER', '${WORDPRESSSQLUSER}');" /var/www/${WORDPRESSSITE}/wp-config.php
sed -i "/define('DB_PASSWORD', 'password_here');/c\define('DB_PASSWORD', '${WORDPRESSSQLPASS}');" /var/www/${WORDPRESSSITE}/wp-config.php
wp core install --url=${WORDPRESSSITE} --title="${WORDPRESSTITLE}" --admin_user=${WPADMINUSER} --admin_password=${WPADMINPASS} --admin_email=${WPADMINEMAIL} --skip-email --allow-root
wp option update permalink_structure '/%postname%' --allow-root
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
service mysql restart
mv /etc/mysql/my.cnf /etc/mysql/my.cnf.bak
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/my.cnf -O /etc/mysql/my.cnf
service mysql reload
#create the wordpress sql database
mysql -u root -p${MYSQLROOTPASS} -e "CREATE USER ${WORDPRESSSQLUSER}@localhost IDENTIFIED BY '${WORDPRESSSQLPASS}';"
mysql -u root -p${MYSQLROOTPASS} -e "CREATE DATABASE ${WORDPRESSSQLDB};"
mysql -u root -p${MYSQLROOTPASS} -e "GRANT ALL PRIVILEGES ON ${WORDPRESSSQLDB}.* TO ${WORDPRESSSQLUSER}@localhost IDENTIFIED BY '${WORDPRESSSQLPASS}';"
mysql -u root -p${MYSQLROOTPASS} -e "FLUSH PRIVILEGES;"
}

install_varnish (){
#--------------------------------------------------------------------------------------------------------------------------------
# Install high-performance HTTP accelerator
#-------------------------------------------------------------------------------------------------------------------------------- 
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install apt-transport-https -y
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
systemctl enable varnish
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
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/haproxy.cfg -O /etc/haproxy/haproxy.cfg
#openssl req -new -newkey rsa:2048 -nodes -out /etc/ssl/wpbullet.pem -keyout /etc/ssl/wpbullet.pem -subj "/C=US/ST=Oregon/L=Portland/O=Company Name/OU=Org/CN=www.example.com"
openssl req -new -x509 -days 365 -nodes -out /etc/ssl/wp-bullet.pem -keyout /etc/ssl/wp-bullet.pem -subj "/C=/ST=/L=/O=Company Name/OU=Org/CN=${WORDPRESSSITE}"

}

install_webmin () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install webmin
#--------------------------------------------------------------------------------------------------------------------------------
#install csf with webmin module
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install libauthen-pam-perl libio-pty-perl libnet-ssleay-perl libapt-pkg-perl apt-show-versions libwww-perl -y
cd /tmp
wget http://www.webmin.com/download/deb/webmin-current.deb
dpkg -i webmin*
}

install_csf () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install csf
#--------------------------------------------------------------------------------------------------------------------------------
#install csf
debconf-apt-progress -- apt-get remove ufw -y
debconf-apt-progress -- apt-get install iptables unzip -y
cd /tmp
wget -q https://download.configserver.com/csf.tgz
tar -xf csf.tgz -C /opt
cd /opt/csf
bash /opt/csf/install.sh
#copy template over
mv /etc/csf/csf.conf /etc/csf/csf.conf.bak
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/csf.conf -O /etc/csf/csf.conf /etc/csf/csf.conf
csf -r > /dev/null
#webmin modules
WEBMINPATH=/usr/share/webmin
if [ -d "$WEBMINPATH" ]; then
#install csf webmin module
cd $WEBMINPATH
perl install-module.pl /etc/csf/csfwebmin.tgz
#install nginx webmin module
if hash nginx 2> /dev/null; then
cd /tmp
wget -q http://www.justindhoffman.com/sites/justindhoffman.com/files/nginx-0.08.wbm__0.gz
cd $WEBMINPATH
perl install-module.pl /tmp/nginx-0.08.wbm__0.gz
fi
#install opcache webmin module
#cd /tmp
#wget http://github.com/jesucarr/webmin-php-opcache-status/releases/download/v1.0/php-opcache-status.wbm.gz
#cd /usr/share/webmin
#perl install-module.pl /tmp/php-opcache-status.wbm.gz
#install php module
cd /tmp
wget -q http://www.webmin.com/webmin/download/modules/phpini.wbm.gz
cd $WEBMINPATH
perl install-module.pl /tmp/phpini.wbm.gz
fi
echo "CSF Firewall is installed, configure it with this guide"
}

install_suhosin () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install suhosin
#--------------------------------------------------------------------------------------------------------------------------------
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install php7.0-dev git build-essential -y
cd /tmp
git clone https://github.com/sektioneins/suhosin7
cd suhosin*
phpize > /dev/null
./configure > /dev/null
make > /dev/null
make install > /dev/null
PHPINI=($(find /etc -iname php.ini))
for ini in "${PHPINI[@]}"
do
  echo "extension=suhosin7.so" >> "${ini}"
  echo 'suhosin.executor.include.whitelist="phar"' >> "${ini}"
done
servercheck
}

install_redis () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install redis
#--------------------------------------------------------------------------------------------------------------------------------
install_dotdeb
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install php7.0-dev build-essential -y
cd /tmp
#build redis
wget http://download.redis.io/redis-stable.tar.gz
tar xzf redis*
cd redis*
echo "Building Redis"
make > /dev/null
make install PREFIX=/usr > /dev/null
mkdir /etc/redis
cp redis.conf /etc/redis/
cd ..
rm -Rf redis*
#add redis user
adduser --system --group --disabled-login redis --home /usr/bin/redis-server --shell /bin/nologin --quiet
#create unix socket path
mkdir -p /var/run/redis
chown -R redis:redis /var/run/redis
mv /etc/redis/redis.conf /etc/redis/redis.conf.bak
#create redis configuration
cat > /etc/redis/redis.conf<<EOF
# create a unix domain socket to listen on
#unixsocket /var/run/redis/redis.sock
# set permissions for the socket
#unixsocketperm 755
bind 127.0.0.1
daemonize yes
stop-writes-on-bgsave-error no
rdbcompression yes
# maximum memory allowed for redis
maxmemory 50M
# how redis will evice old objects - least recently used
maxmemory-policy allkeys-lru
EOF
cat > /etc/systemd/system/redis-server.service<<EOF
[Unit]
Description=Redis Datastore Server
After=network.target

[Service]
Type=forking
Restart=always
User=redis
ExecStart=/sbin/start-stop-daemon --start --pidfile /var/run/redis/redis.pid --umask 007 --exec /usr/bin/redis-server -- /etc/redis/redis.conf

ExecReload=/bin/kill -USR2 $MAINPID

[Install]
WantedBy=multi-user.target
EOF
systemctl enable redis-server
service redis-server start
#build the php extension
cd /tmp
debconf-apt-progress -- git -y
git clone https://github.com/phpredis/phpredis -b php7
cd phpredis
echo "Building Redis pecl extension"
phpize > /dev/null
./configure > /dev/null
make > /dev/null
make install
PHPINI=($(find /etc -iname conf.d | grep php))
for ini in "${PHPINI[@]}"
do
  echo "extension=redis.so" > "${ini}/30-redis.ini"
done
servercheck
}

install_memcached () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install memcached
#--------------------------------------------------------------------------------------------------------------------------------
install_dotdeb
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install libmemcached* memcached libanyevent-perl libyaml-perl libterm-readkey-perl libevent-dev libsasl2-2 sasl2-bin libsasl2-2 libsasl2-dev libsasl2-modules php7.0-dev php7.0-json php7.0-igbinary php7.0-msgpack pkg-config libtool-bin build-essential -y
MEMCACHELATEST=$(wget -q http://www.memcached.org -O - | grep tar.gz | awk -F "[\"]" '{print $2}')
cd /tmp
wget -q $MEMCACHELATEST -O memcached.tar.gz
tar -xf memcached.tar.gz
cd memcached*
./configure --prefix=/usr
make
make install
#adduser --system --group --disabled-login memcache --home /usr/bin/memcached --shell /bin/nologin --quiet
cat > /etc/memcached.conf<<EOF
# Run memcached as a daemon. This command is implied, and is not needed for the
# daemon to run. See the README.Debian that comes with this package for more
# information.
-d
# Log memcached's output to /var/log/memcached
logfile /var/log/memcached.log
# Be verbose
# -v
# Be even more verbose (print client commands as well)
# -vv
# Start with a cap of 64 megs of memory. It's reasonable, and the daemon default
# Note that the daemon will grow to this size, but does not start out holding this much
# memory
-m 50
# Default connection port is 11211
-p 11211
# Run the daemon as root. The start-memcached will default to running as root if no
# -u command is present in this config file
-u memcache
# Specify which IP address to listen on. The default is to listen on all IP addresses
# This parameter is one of the only security measures that memcached has, so make sure
# it's listening on a firewalled interface.
-l 127.0.0.1
# Set unix socket which we put in the folder /var/run/memcached and made memcache user the owner
#-s /var/run/memcached/memcached.sock
# set permissions for the memcached socket
#-a 755
# Limit the number of simultaneous incoming connections. The daemon default is 1024
# -c 1024
# Lock down all paged memory. Consult with the README and homepage before you do this
# -k
EOF
# Make memcached socket folder
mkdir -p /var/run/memcached
chown -R memcache:memcache /var/run/memcached
cp scripts/memcached-init /etc/init.d/memcached
cat > /etc/default/memcached<<EOF
# Set this to no to disable memcached.
ENABLE_MEMCACHED=yes
EOF
chmod +x /etc/init.d/memcached
update-rc.d memcached defaults
service memcached start
#build memcached pecl extension
#build libmemcached first
#debconf-apt-progress -- apt-get install libsasl2-dev git php7.0-dev pkg-config build-essential -y
#cd /tmp
#wget -q https://launchpad.net/libmemcached/1.0/1.0.18/+download/libmemcached-1.0.18.tar.gz
#tar -xf libmemcached-1.0.18.tar.gz
#cd libmemcached*
#./configure
#make
#make install
#build the actual pecl extension
cd /tmp
git clone https://github.com/php-memcached-dev/php-memcached -b php7
cd php-memcached
libtoolize
phpize
#--disable-memcached-sasl --enable-memcached-json --enable-memcached-igbinary
./configure --prefix=/usr --enable-memcached-igbinary --enable-memcached-json --enable-memcached-msgpack
make
make install
PHPINI=($(find /etc -iname conf.d | grep php))
for ini in "${PHPINI[@]}"
do
  echo "extension=memcached.so" >> "${ini}/30-memcached.ini"
done
servercheck
service memcached restart
}

install_monit () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install monit
#--------------------------------------------------------------------------------------------------------------------------------
#monit credentials
MONITUSER=$(whiptail --inputbox "Choose the Monit username for the WebUI" 8 78 "WP-Bullet" --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
MONITPASS=$(date +%s | sha256sum | base64 | head -c 32 ; echo)
MONITPASS=$(whiptail --inputbox "Choose the Monit password for the WebUI" 8 78 $MONITPASS --title "WP-Bullet.com" 3>&1 1>&2 2>&3)
exitstatus=$?; if [ $exitstatus = 1 ]; then exit 1; fi
MONITCONFIGSFOLDER=$(find / -iname monit | grep configs)
debconf-apt-progress -- apt-get update
debconf-apt-progress -- apt-get install monit openssl -y
openssl req -new -x509 -days 365 -nodes -out /etc/ssl/monit.pem -keyout /etc/ssl/monit.pem -subj "/C=/ST=/L=/O=Company Name/OU=Org/CN=Monit"
chmod 0700 /etc/ssl/monit.pem
mv /etc/monit/monitrc /etc/monit/monitrc.bak
cat > /etc/monit/monitrc<<EOF
set daemon 60 #check services every 60 seconds
  set logfile /var/log/monit.log
  set idfile /var/lib/monit/id
  set statefile /var/lib/monit/state

#Event queue
  set eventqueue
      basedir /var/lib/monit/events # set the base directory where events will be stored
      slots 100                     # optionally limit the queue size

#Mail settings
# set mail-format {
#     from: monit@\$HOST
#  subject: monit alert --  \$EVENT $SERVICE
#  message: \$EVENT Service \$SERVICE
#                Date:        \$DATE
#                Action:      \$ACTION
#                Host:        \$HOST
#                Description: \$DESCRIPTION
#
#           Your faithful employee,
#           Monit } 
#  set mailserver smtp.gmail.com port 587 
#     username "wp" password "bullet"
#  using TLSV1 with timeout 30 seconds
#  set alert wpbullet@gmail.com #email address which will receive monit alerts

#http settings
 set httpd port 2812 address 0.0.0.0  # allow port 2812 connections on all network adapters
    ssl enable
    pemfile  /etc/ssl/monit.pem
    allow 0.0.0.0/0.0.0.0 # allow all IPs, can use local subnet too
#    allow htpcguides.crabdance.com        # allow dynamicdns address to connect
    allow ${MONITUSER}:"${MONITPASS}"      # require user wp with password bullet

#allow modular structure
    include /etc/monit/conf.d/*
EOF
chmod 0700 /etc/monit/monitrc
#create array to iterate over
MONITCHECK=(nginx php7.0-fpm mysqld varnishd haproxy redis-server memcached lfd sshd)
#loop through array and copy monit configuration if binary exists
for monit in "${MONITCHECK[@]}"
do
  if hash "${monit}"  2>/dev/null; then
        wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/php7/configs/monit/${monit} -O /etc/monit/conf.d/${monit}
  fi
done
#hashing webmin doesn't work so check for the pid file instead
if [ -e /var/run/miniserv.pid ]; then
wget https://raw.githubusercontent.com/wpbullet/WP-Bullet-VPS-Installer/master/configs/monit/webmin -O /etc/monit/conf.d/webmin
fi
#make sure nginx is listening on the right port
if hash nginx 2>/dev/null; then
SITELIST=($(ls -lh /etc/nginx/sites-enabled/ | awk '{print $9}'))
for SITE in ${SITELIST[@]};
do
if (grep "listen 8080;" /etc/nginx/sites-enabled/$SITE >/dev/null); then
sed -i 's/80/8080/' /etc/monit/conf.d/nginx
fi
if (grep "listen 443;" /etc/nginx/sites-enabled/$SITE >/dev/null); then
sed -i 's/80/443/' /etc/monit/conf.d/nginx
fi
done
fi
service monit restart
}

servercheck () {
#--------------------------------------------------------------------------------------------------------------------------------
# check and restart server daemons
#--------------------------------------------------------------------------------------------------------------------------------
SERVERCHECK=(php7.0-fpm apache2)
#loop through array and copy monit configuration if binary exists
for server in "${SERVERCHECK[@]}"
do
  if hash "${server}" 2>/dev/null; then
        service ${server} restart
  fi
done
}

install_swap () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install swap
#--------------------------------------------------------------------------------------------------------------------------------
swapoff -a
dd if=/dev/zero of=/swapfile bs=1M count=1024
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
echo "/swapfile   none    swap    sw    0   0" >> /etc/fstab
echo "vm.swappiness = 10" >> /etc/sysctl.conf
echo "vm.vfs_cache_pressure = 50" >> /etc/sysctl.conf
sysctl -p
}

install_unattended () {
#--------------------------------------------------------------------------------------------------------------------------------
# Install and activate unattended upgrades
#--------------------------------------------------------------------------------------------------------------------------------
debconf-apt-progress -- apt-get update
echo "unattended-upgrades unattended-upgrades/enable_auto_updates boolean true" | debconf-set-selections
debconf-apt-progress -- apt-get install unattended-upgrades -y
}

#--------------------------------------------------------------------------------------------------------------------------------
# WELCOME SCREEN
#--------------------------------------------------------------------------------------------------------------------------------

whiptail --title "Welcome to the WP Bullet WordPress VPS Installer" --msgbox "This Ubuntu and Debian Installer will prompt for credentials and autoconfigure everything" 8 78
#get ip
#SERVERIP=$(ifconfig eth0 | awk -F"[: ]+" '/inet addr:/ {print $4}')
#dig +short myip.opendns.com @resolver1.opendns.com
SERVERIP=$(wget http://ipinfo.io/ip -qO -)
#--------------------------------------------------------------------------------------------------------------------------------
# MAIN INSTALL
#--------------------------------------------------------------------------------------------------------------------------------

whiptail --ok-button "Install" --title "WP Bullet VPS Installer for Ubuntu/Debian (c) WP-Bullet.com" --checklist --separate-output "\nIP:   ${SERVERIP}\n\nChoose what you want to install:" 25 78 12 \
"nginx + fastcgi caching" "nginx with fastcgi caching        " off \
"nginx + fastcgi caching ssl" "nginx ssl with fastcgi caching        " off \
"nginx + Varnish" "nginx with Varnish caching        " off \
"nginx + Varnish + haproxy" "nginx + Varnish caching + haproxy SSL" off \
"Apache" "Apache" off \
"Apache with nginx cache" "Apache with nginx reverse proxy cache" off \
"Webmin" "Easy GUI VPS administration" off \
"CSF Firewall" "Comprehensive Firewall" off \
"Suhosin" "Enable PHP Security" off \
"Redis" "Install Redis Server" off \
"Memcached" "Install Memcached" off \
"Monit" "Monitor your programs" off \
"Automatic security updates" "Automatic security updates" off \
"Create SWAP File" "Creates SWAP on your VPS" off 2>results
while read choice
do
case $choice in
	"nginx + fastcgi caching") 		ins_nginx_fastcgi="true";;
	"nginx + fastcgi caching ssl") 		ins_nginx_fastcgissl="true";;
	"nginx + Varnish") 			ins_nginx_varnish="true";;
	"nginx + Varnish + haproxy") 		ins_nginx_varnish_haproxy="true";;
	"Apache") 				ins_apache="true";;
	"Apache with nginx cache") 		ins_apache_nginx="true";;
	"Webmin") 				ins_webmin="true";;
	"CSF Firewall") 			ins_csf="true";;
	"Suhosin") 				ins_suhosin="true";;
	"Redis") 				ins_redis="true";;
	"Memcached") 				ins_memcached="true";;
	"Monit") 				ins_monit="true";;
	"Automatic security updates") 		ins_unattended="true";;
	"Create SWAP File") 			ins_swap="true";;
                *)
                ;;
	esac
done < results
if [[ "$ins_nginx_fastcgi" == "true" ]]; 		then install_nginx_fastcgi;		fi
if [[ "$ins_nginx_fastcgissl" == "true" ]]; 		then install_nginx_fastcgissl;		fi
if [[ "$ins_nginx_varnish" == "true" ]]; 		then install_nginx_varnish;		fi
if [[ "$ins_nginx_varnish_haproxy" == "true" ]]; 	then install_nginx_varnish_haproxy;	fi
if [[ "$ins_apache" == "true" ]]; 			then install_apache;			fi
if [[ "$ins_apache_nginx" == "true" ]]; 		then install_apache_nginx;		fi
if [[ "$ins_webmin" == "true" ]]; 			then install_webmin;			fi
if [[ "$ins_csf" == "true" ]]; 				then install_csf;			fi
if [[ "$ins_suhosin" == "true" ]]; 			then install_suhosin;			fi
if [[ "$ins_redis" == "true" ]]; 			then install_redis;			fi
if [[ "$ins_memcached" == "true" ]]; 			then install_memcached;			fi
if [[ "$ins_monit" == "true" ]]; 			then install_monit;			fi
if [[ "$ins_unattended" == "true" ]]; 			then install_unattended;		fi
if [[ "$ins_swap" == "true" ]]; 			then install_swap;			fi

show_summary
clear_bash_history
