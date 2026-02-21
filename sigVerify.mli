type sig_target =
  | Uid_target of Packet.packet
  | Subkey_target of Packet.packet
  | Direct_key

val hash_for_alg : int -> Cryptokit.hash
val key_material_header : int -> int -> string
val uid_header : bool -> int -> string
val int32_be : int -> string

val check_hash_tag :
  primary_key:Packet.packet -> target:sig_target ->
  sig_pkt:Packet.packet -> bool

val verify_signature :
  primary_key:Packet.packet -> target:sig_target ->
  sig_pkt:Packet.packet -> bool
