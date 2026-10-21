# Image of the demo for a public deployment: Apache with PHP 8.3 serving
# demo/public/index.php, which every request is routed to (see
# demo/apache.conf). bin/demo, on this machine, does not use it.
#
# Build from the root of the repository:
#
#     docker build -f demo/Dockerfile -t ezxmldsig-demo .
#     docker run --rm -p 127.0.0.1:8000:8000 ezxmldsig-demo
#
# The container listens on port 8000, as user www-data. Environment:
#
#   DEMO_PUBLIC_HOST   the host name the demo answers on besides 127.0.0.1
#                      and localhost, served over HTTPS by a proxy, e.g.
#                      ezxmldsig.example.org
#
# Writable at run time: demo/var/ (the replay memories of the visitors),
# /var/run/apache2 and /var/lock/apache2. The rest of the file system can be
# mounted read-only.
#
# What it copies from the repository is listed in /.dockerignore.
#
# WARNING: the image holds the keys of demo/certs/, which are public.

FROM composer:2 AS vendor
WORKDIR /app
COPY composer.json ./
COPY src src
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist --optimize-autoloader

FROM php:8.3-apache
RUN cp "$PHP_INI_DIR/php.ini-production" "$PHP_INI_DIR/php.ini" \
    && printf 'expose_php = Off\n' > "$PHP_INI_DIR/conf.d/demo.ini" \
    && a2enmod rewrite \
    && sed -i 's/^Listen 80$/Listen 8000/' /etc/apache2/ports.conf
COPY demo/apache.conf /etc/apache2/sites-available/000-default.conf
WORKDIR /app
COPY --from=vendor /app/vendor vendor
COPY src src
COPY demo demo
RUN mkdir -p demo/var && chown www-data:www-data demo/var
USER www-data
EXPOSE 8000
