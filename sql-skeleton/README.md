# SQL import skeleton

This directory is intentionally populated with empty placeholders.
For real use, generate a host-scoped, schema-aware import set from CP-A to CP-B.
Do not run these files directly.

Rules:

1. Never import whole Nova/Neutron/Cinder/Placement databases over a live target cloud.
2. Do not use `INSERT ... SELECT *` across different patch levels.
3. Compare `information_schema.COLUMNS`, `KEY_COLUMN_USAGE`, and schema-only dumps first.
4. Preserve UUIDs: instances, ports, volumes, attachments, request specs, instance mappings.
5. Rewrite auto-increment integer IDs where needed.
6. If the target Nova schema has `instances.compute_id`, map it to the target compute_nodes row for `rehome_host`.
7. Prefer letting target nova-compute create Placement providers, then run `nova-manage placement heal_allocations`.
8. Back up target DB before every import.
