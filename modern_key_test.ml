(***********************************************************************)
(* modern_key_test.ml - Unit tests for modern OpenPGP support          *)
(*   Tests v5/v6 fingerprints, new packet types, algorithm IDs,        *)
(*   poison key defense (truncation limits), and graceful fallbacks.    *)
(***********************************************************************)

open StdLabels
open MoreLabels
open Printf
open Common
open Packet

let ctr = ref 0

let test name cond =
  printf ".%!";
  incr ctr;
  if not cond then raise
    (Unit_test_failure (sprintf "Modern key test <%s:%d> failed" name !ctr))

(* Helper to create a list of n elements using a function *)
let list_make n f =
  let rec loop acc i =
    if i >= n then List.rev acc
    else loop (f i :: acc) (i + 1)
  in loop [] 0

(* Helper to construct a minimal packet *)
let make_packet ~content_tag ~packet_type ~body =
  { content_tag;
    packet_type;
    packet_length = String.length body;
    packet_body = body;
  }

(* Helper to construct a minimal public key packet body with given version *)
let make_pubkey_body version =
  let cout = Channel.new_buffer_outc 64 in
  cout#write_byte version;
  (* 4 bytes creation time *)
  cout#write_byte 0x60; cout#write_byte 0x00;
  cout#write_byte 0x00; cout#write_byte 0x00;
  (match version with
   | 2 | 3 ->
     (* 2 bytes days of validity *)
     cout#write_byte 0x00; cout#write_byte 0x00;
     (* algorithm: RSA *)
     cout#write_byte 1;
     (* minimal RSA MPI - modulus: 16 bits, 2 bytes data *)
     cout#write_byte 0x00; cout#write_byte 0x10;
     cout#write_byte 0x00; cout#write_byte 0x03;
     (* exponent: 16 bits, 2 bytes data *)
     cout#write_byte 0x00; cout#write_byte 0x10;
     cout#write_byte 0x00; cout#write_byte 0x01;
   | 4 ->
     (* algorithm: EdDSA (22) -- v4 uses algorithm 22 with MPI encoding *)
     cout#write_byte 22;
     (* OID for Ed25519: 1.3.6.1.4.1.11591.15.1 *)
     cout#write_byte 9; (* OID length *)
     cout#write_byte 0x2b; cout#write_byte 0x06;
     cout#write_byte 0x01; cout#write_byte 0x04;
     cout#write_byte 0x01; cout#write_byte 0xda;
     cout#write_byte 0x47; cout#write_byte 0x0f;
     cout#write_byte 0x01;
     (* MPI: 263 bits = 0x0107, followed by 0x40 prefix + 32 bytes *)
     cout#write_byte 0x01; cout#write_byte 0x07;
     cout#write_byte 0x40;
     for _i = 0 to 31 do cout#write_byte 0xAB done;
   | 5 | 6 ->
     (* algorithm: Ed25519 (27) *)
     cout#write_byte 27;
     (* 4-byte key material length *)
     cout#write_byte 0x00; cout#write_byte 0x00;
     cout#write_byte 0x00; cout#write_byte 0x20;
     (* 32 bytes of key material *)
     for _i = 0 to 31 do cout#write_byte 0xAB done;
   | _ ->
     (* unknown version, write some filler *)
     cout#write_byte 0xFF);
  cout#contents

let make_pubkey_packet version =
  let body = make_pubkey_body version in
  make_packet ~content_tag:6 ~packet_type:Public_Key_Packet ~body

let make_sig_packet () =
  (* Minimal v4 signature packet body *)
  let cout = Channel.new_buffer_outc 32 in
  cout#write_byte 4; (* version *)
  cout#write_byte 0x13; (* positive certification *)
  cout#write_byte 1; (* RSA *)
  cout#write_byte 8; (* SHA-256 *)
  (* hashed subpacket length: 0 *)
  cout#write_byte 0; cout#write_byte 0;
  (* unhashed subpacket length: 0 *)
  cout#write_byte 0; cout#write_byte 0;
  (* hash value preview: 2 bytes *)
  cout#write_byte 0xAA; cout#write_byte 0xBB;
  let body = cout#contents in
  make_packet ~content_tag:2 ~packet_type:Signature_Packet ~body

let make_uid_packet text =
  make_packet ~content_tag:13 ~packet_type:User_ID_Packet ~body:text

let make_subkey_packet version =
  let body = make_pubkey_body version in
  make_packet ~content_tag:14 ~packet_type:Public_Subkey_Packet ~body

(* ============================================================ *)
(* Fingerprint tests                                            *)
(* ============================================================ *)

(* Test: v5 fingerprint computation *)
let test_v5_fingerprint () =
  let packet = make_pubkey_packet 5 in
  let result = Fingerprint.from_packet packet in
  test "v5 fp length = 32" (String.length result.fp = 32);
  test "v5 keyid length = 8" (String.length result.keyid = 8);
  (* v5 keyid is first 8 bytes of fingerprint *)
  test "v5 keyid = fp prefix"
    (result.keyid = String.sub result.fp ~pos:0 ~len:8);
  (* fingerprint should be non-zero *)
  test "v5 fp non-zero" (result.fp <> String.make 32 '\000')

(* Test: v6 fingerprint computation *)
let test_v6_fingerprint () =
  let packet = make_pubkey_packet 6 in
  let result = Fingerprint.from_packet packet in
  test "v6 fp length = 32" (String.length result.fp = 32);
  test "v6 keyid length = 8" (String.length result.keyid = 8);
  (* v6 keyid is first 8 bytes of fingerprint *)
  test "v6 keyid = fp prefix"
    (result.keyid = String.sub result.fp ~pos:0 ~len:8);
  test "v6 fp non-zero" (result.fp <> String.make 32 '\000')

(* Test: v5 and v6 produce different fingerprints (different tag bytes) *)
let test_v5_v6_differ () =
  let p5 = make_pubkey_packet 5 in
  let p6 = make_pubkey_packet 6 in
  let r5 = Fingerprint.from_packet p5 in
  let r6 = Fingerprint.from_packet p6 in
  (* Same body but different version prefix bytes (0x9A vs 0x9B) *)
  test "v5 vs v6 fp differ" (r5.fp <> r6.fp)

(* Test: unknown version returns empty fingerprint, no crash *)
let test_unknown_version_fp () =
  let body = "\x07\x00\x00\x00\x00\x01" in
  let packet = make_packet ~content_tag:6 ~packet_type:Public_Key_Packet ~body in
  let result = Fingerprint.from_packet packet in
  test "unknown version fp empty" (result.fp = "");
  test "unknown version keyid 8 bytes" (String.length result.keyid = 8)

(* Test: fp_to_string handles 32-byte fingerprints *)
let test_fp_to_string_32 () =
  let fp = String.make 32 '\xAB' in
  let s = Fingerprint.fp_to_string fp in
  test "fp_to_string 32-byte non-empty" (String.length s > 0);
  (* 32 bytes = 64 hex chars, grouped by 4 = 16 groups *)
  test "fp_to_string 32-byte has spaces" (String.contains s ' ')

(* Test: fp_to_string handles 20-byte fingerprints *)
let test_fp_to_string_20 () =
  let fp = String.make 20 '\xCD' in
  let s = Fingerprint.fp_to_string fp in
  test "fp_to_string 20-byte non-empty" (String.length s > 0);
  test "fp_to_string 20-byte has spaces" (String.contains s ' ')

(* Test: v4 fingerprint still works correctly *)
let test_v4_fingerprint () =
  let packet = make_pubkey_packet 4 in
  let result = Fingerprint.from_packet packet in
  test "v4 fp length = 20" (String.length result.fp = 20);
  test "v4 keyid length = 8" (String.length result.keyid = 8);
  (* v4 keyid is LAST 8 bytes of fingerprint *)
  test "v4 keyid = fp suffix"
    (result.keyid = String.sub result.fp
       ~pos:(String.length result.fp - 8) ~len:8)

(* ============================================================ *)
(* Packet type and algorithm tests                              *)
(* ============================================================ *)

(* Test: ssp_type_to_string no longer crashes on unknown types *)
let test_ssp_type_robustness () =
  let s = Packet.ssp_type_to_string 255 in
  test "ssp unknown type no crash" (s = "unknown sigsubpacket type");
  let s33 = Packet.ssp_type_to_string 33 in
  test "ssp type 33 recognized" (s33 = "issuer fingerprint");
  let s37 = Packet.ssp_type_to_string 37 in
  test "ssp type 37 recognized" (s37 = "preferred AEAD ciphersuites")

(* Test: new packet types recognized *)
let test_new_packet_types () =
  test "tag 20 = AEAD"
    (content_tag_to_ptype 20 = AEAD_Encrypted_Data_Packet);
  test "tag 21 = Padding"
    (content_tag_to_ptype 21 = Padding_Packet);
  test "AEAD to_string"
    (ptype_to_string AEAD_Encrypted_Data_Packet = "AEAD Encrypted Data Packet");
  test "Padding to_string"
    (ptype_to_string Padding_Packet = "Padding Packet")

(* Test: new algorithm IDs *)
let test_new_algorithms () =
  test "alg 25 X25519" (pubkey_algorithm_string 25 = "X25519");
  test "alg 26 X448" (pubkey_algorithm_string 26 = "X448");
  test "alg 27 Ed25519" (pubkey_algorithm_string 27 = "Ed25519");
  test "alg 28 Ed448" (pubkey_algorithm_string 28 = "Ed448");
  test "pk_alg_to_ident 25" (pk_alg_to_ident 25 = "e");
  test "pk_alg_to_ident 27" (pk_alg_to_ident 27 = "E")

(* ============================================================ *)
(* Key merge grammar tests (v5/v6 parsing)                      *)
(* ============================================================ *)

(* Test: parse_keystr handles v5 key version *)
let test_parse_keystr_v5 () =
  let key_pack = make_pubkey_packet 5 in
  let uid_pack = make_uid_packet "Test User <test@example.com>" in
  let sig_pack = make_sig_packet () in
  let sub_pack = make_subkey_packet 5 in
  let key = [key_pack; sig_pack; uid_pack; sig_pack; sub_pack; sig_pack] in
  let pkey =
    (try Some (KeyMerge.key_to_pkey key)
     with KeyMerge.Unparseable_packet_sequence -> None
        | e -> printf "\n  unexpected exception in v5 parse: %s"
                 (Printexc.to_string e); None) in
  test "v5 parse_keystr succeeds" (pkey <> None);
  (match pkey with
   | Some pk ->
     test "v5 pkey has key"
       (pk.KeyMerge.key.packet_type = Public_Key_Packet);
     test "v5 pkey has uid" (List.length pk.KeyMerge.uids >= 1);
     test "v5 pkey has subkey" (List.length pk.KeyMerge.subkeys >= 1);
   | None -> ())

(* Test: parse_keystr handles v6 key version *)
let test_parse_keystr_v6 () =
  let key_pack = make_pubkey_packet 6 in
  let uid_pack = make_uid_packet "Test User v6 <v6@example.com>" in
  let sig_pack = make_sig_packet () in
  let key = [key_pack; sig_pack; uid_pack; sig_pack] in
  let pkey =
    (try Some (KeyMerge.key_to_pkey key)
     with KeyMerge.Unparseable_packet_sequence -> None
        | e -> printf "\n  unexpected exception in v6 parse: %s"
                 (Printexc.to_string e); None) in
  test "v6 parse_keystr succeeds" (pkey <> None);
  (match pkey with
   | Some pk ->
     test "v6 pkey has key"
       (pk.KeyMerge.key.packet_type = Public_Key_Packet);
     test "v6 pkey has uid" (List.length pk.KeyMerge.uids >= 1);
   | None -> ())

(* Test: parse_keystr rejects unknown version *)
let test_parse_keystr_unknown () =
  let body = "\x07\x00\x00\x00\x00\x01" in
  let key_pack = make_packet ~content_tag:6
      ~packet_type:Public_Key_Packet ~body in
  let result =
    (try ignore (KeyMerge.key_to_pkey [key_pack]); `no_exception
     with KeyMerge.Unparseable_packet_sequence -> `ok
        | e -> `wrong_exception e) in
  test "unknown version raises Unparseable" (result = `ok);
  (match result with
   | `wrong_exception e ->
     printf "\n  expected Unparseable_packet_sequence, got: %s"
       (Printexc.to_string e)
   | _ -> ())

(* ============================================================ *)
(* Poison key defense tests                                     *)
(* ============================================================ *)

(* Test: truncate_list *)
let test_truncate_list () =
  let lst = [1; 2; 3; 4; 5; 6; 7; 8; 9; 10] in
  let t5 = KeyMerge.truncate_list 5 lst in
  test "truncate to 5" (List.length t5 = 5);
  test "truncate preserves order" (t5 = [1; 2; 3; 4; 5]);
  let t20 = KeyMerge.truncate_list 20 lst in
  test "truncate no-op when under limit" (t20 = lst);
  let t0 = KeyMerge.truncate_list 0 lst in
  test "truncate to 0" (t0 = [])

(* Test: apply_limits enforces poison key defense *)
let test_apply_limits () =
  let key_pack = make_pubkey_packet 4 in
  let uid_pack_fn i = make_uid_packet (sprintf "uid%d" i) in
  let sig_pack = make_sig_packet () in
  (* Create many UIDs *)
  let many_uids = list_make 300 (fun i -> (uid_pack_fn i, [sig_pack])) in
  (* Create many subkeys *)
  let many_subkeys = list_make 100 (fun _i ->
    (make_subkey_packet 4, [sig_pack])) in
  (* Create many selfsigs *)
  let many_selfsigs = list_make 500 (fun _i -> sig_pack) in
  let pkey = { KeyMerge.key = key_pack;
               selfsigs = many_selfsigs;
               uids = many_uids;
               subkeys = many_subkeys; } in
  let limited = KeyMerge.apply_limits pkey in
  test "uids truncated"
    (List.length limited.KeyMerge.uids <= !Settings.max_uids_per_key);
  test "subkeys truncated"
    (List.length limited.KeyMerge.subkeys <= !Settings.max_subkeys_per_key);
  test "selfsigs truncated"
    (List.length limited.KeyMerge.selfsigs <= !Settings.max_selfsigs)

(* Test: Key_too_large exception *)
let test_key_too_large () =
  (* Create a key that exceeds max_key_size *)
  let big_body = String.make 300000 '\x00' in
  let big_pack = make_packet ~content_tag:6
      ~packet_type:Public_Key_Packet ~body:big_body in
  let result =
    (try Fixkey.check_key_size [big_pack]; false
     with Fixkey.Key_too_large -> true) in
  test "oversized key rejected" result;
  (* Small key should pass *)
  let small_pack = make_pubkey_packet 4 in
  let ok =
    (try Fixkey.check_key_size [small_pack]; true
     with Fixkey.Key_too_large -> false) in
  test "normal key accepted" ok

(* Test: signature truncation on UIDs *)
let test_sig_truncation () =
  let sig_pack = make_sig_packet () in
  let many_sigs = list_make 2000 (fun _i -> sig_pack) in
  let pairs = [(make_uid_packet "test", many_sigs)] in
  let truncated = KeyMerge.truncate_sigpairs 100 pairs in
  (match truncated with
   | [(_, sigs)] ->
     test "uid sigs truncated to 100" (List.length sigs = 100)
   | _ -> test "truncate_sigpairs structure" false)

(* ============================================================ *)
(* Main test runner                                             *)
(* ============================================================ *)

let run () =
  ctr := 0;
  (* Fingerprint tests *)
  test_v5_fingerprint ();
  test_v6_fingerprint ();
  test_v5_v6_differ ();
  test_unknown_version_fp ();
  test_fp_to_string_32 ();
  test_fp_to_string_20 ();
  test_v4_fingerprint ();
  (* Packet type and algorithm tests *)
  test_ssp_type_robustness ();
  test_new_packet_types ();
  test_new_algorithms ();
  (* Key merge grammar tests *)
  test_parse_keystr_v5 ();
  test_parse_keystr_v6 ();
  test_parse_keystr_unknown ();
  (* Poison key defense tests *)
  test_truncate_list ();
  test_apply_limits ();
  test_key_too_large ();
  test_sig_truncation ()
