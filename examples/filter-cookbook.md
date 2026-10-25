# Example: chat filter cookbook

# Filter expression `state == play && direction == client_to_server && name ~ chat`
# is three predicates:
# - state == play           — only play-phase packets
# - direction == client_to_server — only C→S
# - name ~ chat            — packet name contains "chat" (case-insensitive unless quoted)

# Replace rule: redact player positions in logs
# expression: state == play && name ~ player_position
# edit: { kind: "field", name: "x", value: "0" }

# Content search hex range: hide keep-alive noise
# mode: hex, scope: equals, term: 0c-0f (single-byte keep-alive IDs)
# or text mode: minecraft:brand
