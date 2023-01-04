docker run --name phpmyadmin -d --link mariadb:db -p 8080:80 --restart=always --priviliged -v /home/btuser/experiment/phpmyadmin/config.user.inc.php:/etc/phpmyadmin/config.user.inc.php phpmyadmin

