# Warden ClamAV Bridge Protocol v1

`warden-clamav-bridge` accepts exactly one JSON request on stdin and writes exactly one JSON response on stdout.

## Request

```json
{
  "protocol_version": 1,
  "command": "scan_path",
  "payload": {}
}
```

Supported commands:

- `ping`
- `engine_status`
- `scan_path`
- `update_definitions`

## Response

```json
{
  "protocol_version": 1,
  "ok": true,
  "error": "",
  "payload": {}
}
```

## `scan_path` payload

```json
{
  "target_path": "/path/to/scan",
  "recursive": true,
  "include_hidden": false,
  "max_file_size_bytes": 268435456,
  "quarantine_directory": "/optional/quarantine/path"
}
```

## `scan_path` response payload

- `database`
- `stats`
- `warnings`
- `findings`

Each finding includes:

- `name`
- `path`
- `severity`
- `source`
- `recommended_action`
- `sha256`
- `description`

## `update_definitions` response payload

- `supported`
- `success`
- `updated_count`
- `database_directory`
- `updated_databases`
- `error`
