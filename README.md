# [WP Bullet](https://wp-bullet.com) VPS Installer
The provisioning tool for preconfiguring a VPS for WordPress on a Debian 8 x64 system, it may work on Ubuntu 15.x and later

**You should only use this on a fresh VPS!**

## Installation php 7 version

    sudo apt-get install git -y
    cd ~
    git clone https://github.com/wpbullet/WP-Bullet-VPS-Installer/tree/php7
    cd WP-Bullet-WordPress-VPS-Installer
    sudo bash wpbullet.sh
    
## Usage and Notes

* Only choose **one** of items 1-6 beginning with Apache or nginx
* Use Spacebar to choose items to install
* Use Tab to choose Install and press Enter to begin
* Random passwords are generated for you
* Uses [wp-cli](https://github.com/wp-cli/wp-cli)
* You can use an IP instead of a domain name for local environments
* A summary of credentials is displayed when the installer completes
* SSL configuration use self-signed certificates to use Full SSL with CloudFlare

![Screenshot](http://i.imgur.com/TFNjHxl.png)
