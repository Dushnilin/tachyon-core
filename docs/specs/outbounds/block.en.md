# Block Outbound

Silently drops all traffic matched to this outbound. Used as a blackhole to discard unwanted connections.

## Schema

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `"block"` | — | Must be `"block"`. |
| `tag` | string | — | Unique label for this outbound. |

## Example

```json
{
  "type": "block",
  "tag": "block"
}
```

## Notes

- All connections routed to this outbound are immediately terminated with no data exchanged.
- No dial fields, TLS, or transport options are applicable.
- Useful for blocking ads, malware domains, or any category of traffic via routing rules.
