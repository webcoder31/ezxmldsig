# Image of the single sign-on demo for a public deployment: Apache with PHP
# 8.3 serving demo-sso/public/index.php, which every request is routed to
# (see demo-sso/apache.conf). bin/demo-sso, on this machine, does not use it.
#
# Build from the root of the repository:
#
#     docker build -f demo-sso/Dockerfile -t ezxmldsig-sso .
#
# The container listens on port 8000, as user www-data. Environment:
#
#   DEMO_SSO_PUBLIC_DOMAIN   the domain whose subdomains are the sites of the
#                            demo, served over HTTPS by a proxy, e.g.
#                            sso.example.org: the home page on it, and
#                            idp., mail. and crm. under it
#
# Writable at run time: demo-sso/var/ (a directory per visitor),
# /var/run/apache2 and /var/lock/apache2. The rest of the file system can be
# mounted read-only.
#
# What it copies from the repository is listed in /.dockerignore.
#
# WARNING: the image holds the keys of demo/certs/ and demo-sso/certs/, which
# are public.

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
COPY demo-sso/apache.conf /etc/apache2/sites-available/000-default.conf
WORKDIR /app
COPY --from=vendor /app/vendor vendor
COPY src src
# The demo of the token holds what this one builds on: its receiver, its
# keys, its style sheet.
COPY demo demo
COPY demo-sso demo-sso
RUN mkdir -p demo-sso/var && chown www-data:www-data demo-sso/var
USER www-data
EXPOSE 8000
