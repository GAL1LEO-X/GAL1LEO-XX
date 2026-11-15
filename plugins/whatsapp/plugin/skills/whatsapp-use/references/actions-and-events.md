# Actions, capabilities and notifications

For profiles, stars, invitations, reactions, groups and other operations, inspect
get_capabilities for the relevant family and get_operation_schema for the exact
operation. Use the declared path/query/body containers; the server supplies the
session. Do not invent operations from intuitive names. read_whatsapp handles
reads, write_whatsapp supported actions without required media, and send_media
supported media actions. Catalogue entries may be unsupported by the engine.
Missing scope, service policy, group role and engine support are distinct causes.
Report the returned cause rather than retrying OAuth or changing access/target
to bypass a restriction.

For a user-supplied file, call prepare_file with a file actually exposed by the
client; do not invent a URL for an inaccessible local path. For authorized
WhatsApp content use get_attachment. Wait for get_transfer_status=ready, then
use send_media with the transfer, exact schema and stable idempotency key.
A prepared transfer alone sends nothing and authorizes no publication.

For a known attempt use get_send_status(idempotency_key=KEY), without pagination.
For requested uncertain-outcome diagnosis use get_send_status(mode="uncertain",
limit=INTEGER, offset=INTEGER), without a key. These are unresolved historical
actions, not a resend queue. not_found or a missing response does not prove the
action never happened. Inspect evidence before proposing another attempt.
An authorized retry of the same attempt keeps its key; a new send needs new intent.

list_account_events/get_account_event read acquired events and create no monitor.
check_event_authorization checks scope only. For requested notifications establish
event, destination and duration if unclear. Use actual client-exposed native
subscription capabilities and their contract with host-supplied credentials.
Never invent subscribe tools or call endpoints using credentials found elsewhere.
Confirm an active monitor only from the creation receipt. If support is absent,
state that limit and offer on-demand reading. WORKING alone activates no monitor.
sync_chat/history-sync tools modify the local archive: use only for requested,
bounded recovery, never as an automatic prerequisite to read. They do not
guarantee complete phone history.
