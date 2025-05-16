# Dockerfile

FROM php:8.1-apache

# ARG: Web root jail
ARG APACHE_DOC_ROOT=/var/www/html/jail
ENV APACHE_DOC_ROOT=${APACHE_DOC_ROOT}

# Step 2: Configure PHP open_basedir to restrict access
RUN mkdir -p ${APACHE_DOC_ROOT}

# Step 3: Build the vulnerable setuid-root binary
RUN apt-get update \
 && apt-get install -y gcc \
 && apt-get purge -y gcc \
 && apt-get autoremove -y \
 && rm -rf /var/lib/apt/lists/*

# Step 4: Update Apache config to serve jail
RUN sed -ri \
     -e "s|DocumentRoot /var/www/html|DocumentRoot ${APACHE_DOC_ROOT}|g" \
     -e "s|<Directory /var/www/html>|<Directory ${APACHE_DOC_ROOT}>|g" \
    /etc/apache2/sites-available/000-default.conf \
 && sed -ri \
     -e "s|DocumentRoot /var/www/html|DocumentRoot ${APACHE_DOC_ROOT}|g" \
    /etc/apache2/apache2.conf

# Step 5: Configure PHP settings
RUN { \
    echo "[PHP]"; \
    echo "open_basedir=${APACHE_DOC_ROOT}:/tmp"; \
} > /usr/local/etc/php/conf.d/openbasedir.ini

# Step 6: Copy application files and set permissions
COPY index.php ${APACHE_DOC_ROOT}/index.php

# Step 7: Create flag in the web root directory
RUN echo "CTF{race_condition_symlink}" > ${APACHE_DOC_ROOT}/flag \
 && chmod 400 ${APACHE_DOC_ROOT}/flag \
 && chown www-data:www-data ${APACHE_DOC_ROOT}/flag

# Step 8: Set proper permissions for web root
RUN chown -R www-data:www-data ${APACHE_DOC_ROOT} \
 && chmod 1777 /tmp

EXPOSE 80

# Step 9: Switch to www-data user for web operations
USER www-data
