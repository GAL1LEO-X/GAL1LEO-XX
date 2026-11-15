# Behavior and privacy

Each account has separate storage, encryption, provider session, queues and
authorization. Archive reads do not send read receipts. Sending a seen/read
action is a separate operation requiring owner instructions. Scope, owner,
audience, issuer and client validation apply independently of provider support.

Read `get_capabilities` and `get_operation_schema` before nontrivial actions.
Five operations are unsupported and eight require the paired provider
contract. A provider claim alone never authorizes an action. Poll creation
and voting are not exposed.

An accepted/queued/submitted send is not delivery. An uncertain outcome is
preserved for reconciliation; do not blindly repeat it under a new key.
For media, use prepare_file → get_transfer_status → send_media only once the
transfer is ready. Retrieve inbound attachments through their explicit
resource tools. The 512 MiB bridge limit is not an end-to-end client guarantee.

History acquisition is limited by linked-device availability. Inspect per-chat
requested/observed coverage and follow cursors; exhausting pages does not prove
the entire phone history was recovered. Revocations take precedence over late
originals. Cancelled/completed history jobs do not become active again.

MCP events include message.received, message.digest and whatsapp.event.
Authorization checks do not create monitors. Subscriptions use callbacks and
secrets supplied by the host and are distinct from trigger preferences and
host notification delivery. Preserve expiry, deduplication and consent.

Administrative operations have persistent IDs and exact confirmations. The
panel cannot grant itself host privileges or create its own approval. A lost
response requires reading the operation receipt before another attempt.
Optional local transcription is on explicit request only; it does not use
an OpenAI inference API or silently transfer recordings elsewhere.
