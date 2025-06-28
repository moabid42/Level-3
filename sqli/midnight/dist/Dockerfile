FROM php:8.2-apache
RUN apt-get update && apt-get install -y default-mysql-client
RUN docker-php-ext-install mysqli && docker-php-ext-enable mysqli
COPY challenge.php /var/www/html/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"] 