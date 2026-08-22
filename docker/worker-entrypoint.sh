#!/bin/sh
set -eu
data_dir="${FUSIONWEB_DATA_DIR:-/app/data}"
mkdir -p "$data_dir"
if [ ! -d "$data_dir/pocs" ] && [ -d /opt/fusionweb-data/pocs ]; then cp -a /opt/fusionweb-data/. "$data_dir/"; fi
exec "$@"
