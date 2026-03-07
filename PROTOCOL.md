# RP2350 Token Protocol

Protocol version: `1`

Transport:

- USB HID vendor-defined reports
- request size: `64` bytes
- response size: `64` bytes

## Request layout

Common header:

- byte `0`: protocol version
- byte `1`: command
- byte `2`: domain
- byte `3`: flags

### `CMD_SIGN = 1`

Request:

- bytes `4..35`: 32-byte challenge

Response:

- byte `0`: echoed version
- byte `1`: status
- byte `2`: echoed domain
- byte `3`: echoed flags
- bytes `4..35`: HMAC-SHA256
- bytes `36..39`: little-endian counter

Signed message format:

- `version(1) || domain(1) || counter_le32(4) || challenge(32)`

### `CMD_PROVISION = 2`

Request:

- bytes `4..35`: 32-byte master secret

Response:

- byte `4`: `1` if provisioning applied

Provisioning policy:

- allowed only when token is not yet provisioned
- after provisioning, reprovision is blocked until wipe

### `CMD_GET_STATE = 3`

Request:

- header only

Response payload:

- byte `4`: protocol version
- byte `5`: counter flush interval
- byte `6`: flags
- byte `7`: security mode
- bytes `8..11`: runtime counter
- bytes `12..15`: persisted counter checkpoint
- bytes `16..19`: state generation
- bytes `20..27`: device UID

`GET_STATE` flags:

- bit `0`: master secret provisioned
- bit `1`: counter dirty in RAM
- bit `2`: reprovision locked

Security modes:

- `1`: strict
- `2`: beta

Mode definition:

- strict: persist counter every signature
- beta: allow counter checkpoint batching

## Status codes

- `0`: success
- `1`: bad protocol version
- `2`: bad command
- `3`: bad domain
- `4`: user presence required or approval timeout
- `5`: crypto or state persistence error
- `6`: bad payload
- `7`: not provisioned
- `8`: provisioning locked

## Security properties

- per-device root keys are derived from provisioned master secret + board UID
- user presence is required for signing and provisioning
- secret is not baked into firmware
- wipe is required before reprovisioning
- `GET_STATE` exposes current security mode and replay-counter checkpoint state

## Non-properties

- no protection against physical flash extraction
- no secure boot or firmware authenticity chain
- beta mode permits rollback inside the checkpoint window after sudden power loss
- host trust is still required for correct intent display and command origin
