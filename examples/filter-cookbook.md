# Packet filter cookbook

Paste these expressions into the history expression filter or a Replace rule's
selector. The same grammar applies to MCP `expr`. Predicates need spaces around
the operator. Combine them with `&&`, `||`, `!` and parentheses; `*` matches all.

## Find client chat

```text
state == play && direction == client_to_server && name ~ chat
```

`~` means substring matching, not regular expressions. String equality and
substring matching fold ASCII case, including quoted values. Quote values with
spaces. Text ordering comparisons do not match.

## Isolate one plugin channel

```text
state == play && channel == mineburp:batch
```

`channel` is an expression field, not an MCP top-level filter key.

## Find large server packets on modern protocols

```text
direction == server_to_client && protocol >= 769 && size > 4096
```

Numeric fields are `size`, `protocol`, and `id`. Use decimal integers and
`==`, `!=`, `>`, `>=`, `<`, or `<=` for numeric comparisons.

## Review edits and drops

```text
disposition == edited || disposition == dropped
```

## Remove keep-alive noise

```text
!(name ~ keep_alive)
```

Missing optional values never match a predicate, even `name != keep_alive`.
Negating the positive predicate also retains rows with no packet name.

## Limit by connection and packet id

```text
connection == "FULL-CONNECTION-UUID" && state == play && id == 10
```

Replace the UUID with the actual complete connection id. Packet ids vary by
version, phase and direction; prefer names or channels when possible. Other
fields include `source` and `loader`. Use the MCP `filters` tool to validate an
expression before installing a live rule.

## Search payload bytes

Payload content search is a separate control from expressions. Choose hex mode,
contains scope, and enter `6d 69 6e 65 63 72 61 66 74` to find the UTF-8 bytes
of `minecraft`. Choose literal text mode for readable strings. One term per line
matches any term. Hex ranges such as `0c-0f` match byte values, not stable packet
names; do not assume they identify keep-alives across versions.
