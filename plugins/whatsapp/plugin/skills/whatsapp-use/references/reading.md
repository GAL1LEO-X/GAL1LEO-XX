# Sources, reactions and receipts

acquired_archive is a captured copy; live_gateway is a provider observation.
The phone, linked device and bridge archive may have different coverage. Linking
does not guarantee full history. An empty live list is not proof of deletion and
does not authorize automatic reconstruction from the archive. If live fails,
explain archive availability without presenting it as current state.

chat_type comes from the identifier, never name/content: private (PN/LID), group,
status (status@broadcast), channel (@newsletter), broadcast or unknown. Archive
list_chats/search_messages filter chat_type before limit/offset; all is the default.
Filtering does not imply complete phone coverage. list_live_chats reports observed
types without promising a live-directory filter. Unknown identifiers stay unknown.

read_conversation uses one chat ID; a supplied chat_type must match. PN forms @c.us
and @s.whatsapp.net are equivalent; map LID to PN only with explicit verification.
Live reads, including read_whatsapp, reject responses contradicting requested chat,
message key or explicit time range. They do not drop rows to fabricate a valid
page or fall back to archive. Provider errors do not prove message absence;
do not open attachments from a rejected page.

Archive cursors are opaque, expire and preserve all filters, including chat_type.
They exclude later insertions but honor observed edits/deletions. An expired
cursor requires a new observation; do not merge it into the old stable search.
Respect omitted content after revocation, deletion or unverifiable references.
content_state=clear_chat_coverage_uncertain has no text to recover. ClearChat
anchors and potential intervals do not prove definite deletion. With
clear_chat_coverage/boundary_unknown, residual data is archive with uncertain
current state. visible_acquired_only counts do not measure all phone messages.

For replies, inspect text, reply references and reactions on the exact message.
Report available emoji, author/time; temporal proximity alone is not association.
Acquired reaction additions/removals do not prove a complete current count.
If absent, say no reaction was observed in available data, not that none exists.

Webhook acceptance, processing, send acceptance, delivery, reading and playback
are separate. Use returned get_send_status evidence; a missing level is unknown,
not failed. submitted is not reading; download/transcription is not playback.
A partial group receipt does not prove all participants read a message.
Group metadata and participant lists can disagree. Preserve mismatch, provenance
and unknown current counts; do not replace ParticipantCount with list length or
silently correct WhatsApp state without a separate request and evidence.
