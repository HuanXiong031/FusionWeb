#!/bin/sh
set -eu

secrets_dir="${FUSIONWEB_SECRETS_DIR:-/run/fusionweb-secrets}"
data_dir="${FUSIONWEB_DATA_DIR:-/app/data}"
mkdir -p "$secrets_dir" "$data_dir"

if [ ! -d "$data_dir/pocs" ] && [ -d /opt/fusionweb-data/pocs ]; then
  cp -a /opt/fusionweb-data/. "$data_dir/"
fi

load_or_create_secret() {
  var_name="$1"
  file_name="$2"
  bytes="$3"
  default_value="${4:-}"
  eval "current=\${${var_name}:-}"
  file="$secrets_dir/$file_name"

  if [ -n "$current" ]; then
    printf '%s' "$current" > "$file"
    chmod 600 "$file"
  elif [ -s "$file" ]; then
    current="$(cat "$file")"
  elif [ -n "$default_value" ]; then
    current="$default_value"
    printf '%s' "$current" > "$file"
    chmod 600 "$file"
  else
    current="$(openssl rand -base64 "$bytes" | tr -d '\r\n')"
    printf '%s' "$current" > "$file"
    chmod 600 "$file"
  fi

  export "$var_name=$current"
}

load_or_seed_secret() {
  var_name="$1"
  file_name="$2"
  bytes="$3"
  default_value="${4:-}"
  eval "current=\${${var_name}:-}"
  file="$secrets_dir/$file_name"

  if [ -s "$file" ]; then
    current="$(cat "$file")"
  elif [ -n "$current" ]; then
    printf '%s' "$current" > "$file"
    chmod 600 "$file"
  elif [ -n "$default_value" ]; then
    current="$default_value"
    printf '%s' "$current" > "$file"
    chmod 600 "$file"
  else
    current="$(openssl rand -base64 "$bytes" | tr -d '\r\n')"
    printf '%s' "$current" > "$file"
    chmod 600 "$file"
  fi

  export "$var_name=$current"
}

load_or_create_secret FUSIONWEB_JWT_SECRET jwt_secret 48
load_or_seed_secret FUSIONWEB_BASIC_USER basic_user 4 'admin'
load_or_seed_secret FUSIONWEB_BASIC_PASS basic_pass 24 '$X5_fK8T+&%=U@X*5j|f'
printf 'FusionWeb Basic Auth: %s / %s\n' "$FUSIONWEB_BASIC_USER" "$FUSIONWEB_BASIC_PASS"

exec "$@"