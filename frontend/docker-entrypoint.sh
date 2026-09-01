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

secret_dir="${FUSIONWEB_SECRETS_DIR:-/run/fusionweb-secrets}"
user_secret_file="$secret_dir/basic_user"
pass_secret_file="$secret_dir/basic_pass"

read_basic_user() {
  if [ -s "$user_secret_file" ]; then
    cat "$user_secret_file"
    return
  fi
  printf '%s' "${FUSIONWEB_BASIC_USER:-admin}"
}

read_basic_pass() {
  if [ -s "$pass_secret_file" ]; then
    cat "$pass_secret_file"
    return
  fi
  printf '%s' "${FUSIONWEB_BASIC_PASS:-}"
}

apply_basic_auth() {
  user="$(read_basic_user)"
  pass="$(read_basic_pass)"

  if [ -z "$user" ]; then
    user="admin"
  fi
  if [ -z "$pass" ]; then
    echo 'Basic Auth 已启用，但未找到密码' >&2
    exit 1
  fi

  htpasswd -bc /etc/nginx/.htpasswd "$user" "$pass" >/dev/null
}

watch_basic_auth() {
  last_user=""
  last_pass=""
  while :; do
    current_user="$(read_basic_user 2>/dev/null || true)"
    current_pass="$(read_basic_pass 2>/dev/null || true)"
    if [ "$current_user" != "$last_user" ] || [ "$current_pass" != "$last_pass" ]; then
      if [ -n "$current_user" ] && [ -n "$current_pass" ]; then
        htpasswd -bc /etc/nginx/.htpasswd "$current_user" "$current_pass" >/dev/null
        last_user="$current_user"
        last_pass="$current_pass"
      fi
    fi
    sleep 2
  done
}

if [ "${FUSIONWEB_BASIC_AUTH:-true}" = "true" ]; then
  apply_basic_auth
  sed -i 's/__FUSIONWEB_BASIC_AUTH__/"FusionWeb"/' /etc/nginx/conf.d/default.conf
  (watch_basic_auth >/tmp/fusionweb-basic-auth-watch.log 2>&1) &
else
  : > /etc/nginx/.htpasswd
  sed -i 's/__FUSIONWEB_BASIC_AUTH__/off/' /etc/nginx/conf.d/default.conf
fi