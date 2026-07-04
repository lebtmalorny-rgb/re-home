#!/usr/bin/env bash
set -euo pipefail
# Skeleton only. Review and extend for your exact Nova/Neutron/Cinder schemas.
# Usage: make_host_scoped_dump.sh /root/.my.cnf compute-023 /var/tmp/rehome-sql
MYSQL_DEFAULTS=${1:?mysql defaults file}
HOST=${2:?nova host}
OUT=${3:?output dir}
NOVA_CELL_DB=${NOVA_CELL_DB:-nova_cell0}
mkdir -p "$OUT"

mysql --defaults-extra-file="$MYSQL_DEFAULTS" --batch --raw <<SQL > "$OUT/instance_uuids.txt"
SELECT uuid FROM ${NOVA_CELL_DB}.instances WHERE host='${HOST}' AND deleted=0 ORDER BY uuid;
SQL

UUID_CSV=$(awk '{printf "%s%s",sep,"\047"$1"\047"; sep=","}' "$OUT/instance_uuids.txt")
if [ -z "$UUID_CSV" ]; then echo "No instances for host $HOST" >&2; exit 2; fi

# Examples: these are not complete for every deployment.
mariadb-dump --defaults-extra-file="$MYSQL_DEFAULTS" "$NOVA_CELL_DB" instances --where="uuid IN ($UUID_CSV)" > "$OUT/50-nova-cell-instances.sql"
mariadb-dump --defaults-extra-file="$MYSQL_DEFAULTS" "$NOVA_CELL_DB" instance_extra --where="instance_uuid IN ($UUID_CSV)" > "$OUT/51-nova-cell-instance-extra.sql"
mariadb-dump --defaults-extra-file="$MYSQL_DEFAULTS" "$NOVA_CELL_DB" instance_info_caches --where="instance_uuid IN ($UUID_CSV)" > "$OUT/52-nova-cell-info-cache.sql"
mariadb-dump --defaults-extra-file="$MYSQL_DEFAULTS" "$NOVA_CELL_DB" block_device_mapping --where="instance_uuid IN ($UUID_CSV)" > "$OUT/53-nova-cell-bdm.sql"
mariadb-dump --defaults-extra-file="$MYSQL_DEFAULTS" nova_api instance_mappings --where="instance_uuid IN ($UUID_CSV)" > "$OUT/40-nova-api-instance-mappings.sql"
mariadb-dump --defaults-extra-file="$MYSQL_DEFAULTS" nova_api request_specs --where="instance_uuid IN ($UUID_CSV)" > "$OUT/41-nova-api-request-specs.sql"

cat > "$OUT/README-review-required.txt" <<TXT
Generated skeleton dumps for host ${HOST}.
Nova cell DB: ${NOVA_CELL_DB}.
You must review schema, child tables, FK ordering, deleted flags, integer IDs,
compute_id/service_id mappings, Neutron ports/security groups, Cinder attachments,
and Keystone/project references before importing into target.
TXT
