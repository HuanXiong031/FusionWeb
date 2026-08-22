#!/bin/sh
set -eu

https_port="${FUSIONWEB_HTTPS_PORT:-8988}"
case "$https_port" in
  *[!0-9]*|'') echo "FUSIONWEB_HTTPS_PORT 必须是数字" >&2; exit 1 ;;
esac
sed -i "s/__FUSIONWEB_HTTPS_PORT__/$https_port/g" /etc/nginx/conf.d/default.conf

mkdir -p /etc/nginx/ssl
if [ ! -s /etc/nginx/ssl/server.crt ] || [ ! -s /etc/nginx/ssl/server.key ]; then
  openssl req -x509 -nodes -newkey rsa:2048 -days 3650 -subj "/CN=FusionWeb" -keyout /etc/nginx/ssl/server.key -out /etc/nginx/ssl/server.crt >/dev/null 2>&1
fi

if [ "${FUSIONWEB_BASIC_AUTH:-true}" = "true" ]; then
  pass="${FUSIONWEB_BASIC_PASS:-}"
  secret_file="${FUSIONWEB_SECRETS_DIR:-/run/fusionweb-secrets}/basic_pass"
  if [ -z "$pass" ] && [ -s "$secret_file" ]; then
    pass="$(cat "$secret_file")"
  fi
  if [ -z "$pass" ]; then
    echo 'Basic Auth 已启用，但未找到密码' >&2
    exit 1
  fi
  htpasswd -bc /etc/nginx/.htpasswd "${FUSIONWEB_BASIC_USER:-admin}" "$pass" >/dev/null
  sed -i 's/__FUSIONWEB_BASIC_AUTH__/"FusionWeb"/' /etc/nginx/conf.d/default.conf
else
  : > /etc/nginx/.htpasswd
  sed -i 's/__FUSIONWEB_BASIC_AUTH__/off/' /etc/nginx/conf.d/default.conf
fi