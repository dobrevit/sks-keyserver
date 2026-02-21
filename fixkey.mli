exception Bad_key
exception Bad_key_at of string
exception Key_too_large
exception Standalone_revocation_certificate
val key_serialized_size : Packet.packet list -> int
val check_key_size : Packet.packet list -> unit
val filters : unit -> string list
val get_keypacket : KeyMerge.pkey -> Packet.packet
val ( |= ) : ('a, 'b) PMap.Map.t -> 'a -> 'b
val ( |< ) : ('a, 'b) PMap.Map.t -> 'a * 'b -> ('a, 'b) PMap.Map.t
val join_by_keypacket : KeyMerge.pkey list -> KeyMerge.pkey list list
val merge_pkeys : KeyMerge.pkey list -> KeyMerge.pkey
val compute_merge_replacements :
  Packet.packet list list ->
  (Packet.packet list list * Packet.packet list) list
val canonicalize : Packet.packet list -> Packet.packet list
val good_key : Packet.packet -> bool
val good_signature : Packet.packet -> bool
val drop_bad_sigs : Packet.packet list -> Packet.packet list
val sig_filter_sigpair :
  'a * Packet.packet list -> ('a * Packet.packet list) option
val presentation_filter : Packet.packet list -> Packet.packet list option
val pre_filter : Packet.packet list -> Packet.packet list
val drop_uat : KeyMerge.pkey -> KeyMerge.pkey
val drop_unparseable : KeyMerge.pkey -> KeyMerge.pkey
val has_selfsig : string -> Packet.packet list -> bool
val drop_implausible : KeyMerge.pkey -> KeyMerge.pkey
val drop_invalid_selfsig : KeyMerge.pkey -> KeyMerge.pkey
val drop_unbound : KeyMerge.pkey -> KeyMerge.pkey
val has_hard_revocation : string -> Packet.packet list -> bool
val drop_hard_revoked_cruft : KeyMerge.pkey -> KeyMerge.pkey
