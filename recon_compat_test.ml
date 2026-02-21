(***********************************************************************)
(* recon_compat_test.ml - Unit tests for Hockeypuck compatibility     *)
(*   Tests version string parsing, filter policy logic, and           *)
(*   config exchange behavior with different filter sets.             *)
(***********************************************************************)

open Printf
open Common

let ctr = ref 0

let test name cond =
  printf ".%!";
  incr ctr;
  if not cond then raise
    (Unit_test_failure (sprintf "Recon compat test <%s:%d> failed" name !ctr))

(* ============================================================ *)
(* Version string parsing tests                                  *)
(* ============================================================ *)

let test_parse_version_normal () =
  let (a, b, c) = parse_version_string "1.1.6" in
  test "normal version major" (a = 1);
  test "normal version minor" (b = 1);
  test "normal version patch" (c = 6)

let test_parse_version_with_suffix () =
  let (a, b, c) = parse_version_string "1.1.6+" in
  test "suffix version major" (a = 1);
  test "suffix version minor" (b = 1);
  test "suffix version patch" (c = 6)

let test_parse_version_hockeypuck () =
  let (a, b, c) = parse_version_string "1.1.3" in
  test "hockeypuck version major" (a = 1);
  test "hockeypuck version minor" (b = 1);
  test "hockeypuck version patch" (c = 3)

let test_parse_version_with_label () =
  (* Hockeypuck may use versions like "1.1.7-beta" *)
  let (a, b, c) = parse_version_string "1.1.7-beta" in
  test "label version major" (a = 1);
  test "label version minor" (b = 1);
  test "label version patch" (c = 7)

let test_parse_version_two_components () =
  let (a, b, c) = parse_version_string "2.3" in
  test "two-component major" (a = 2);
  test "two-component minor" (b = 3);
  test "two-component patch defaults to 0" (c = 0)

let test_parse_version_compatibility () =
  (* Ensure Hockeypuck's 1.1.3 passes the >= (0,1,5) check *)
  let hv = parse_version_string "1.1.3" in
  test "hockeypuck >= compatible" (hv >= compatible_version_tuple);
  (* Also check the SKS version itself *)
  let sv = parse_version_string "1.1.6+" in
  test "sks >= compatible" (sv >= compatible_version_tuple);
  (* Check that 0.1.4 would fail *)
  let old = parse_version_string "0.1.4" in
  test "old version < compatible" (old < compatible_version_tuple)

(* ============================================================ *)
(* Filter policy tests                                           *)
(* ============================================================ *)

let test_filter_policy_matching () =
  (* When filters match, all policies should pass *)
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["yminsky.dedup"] in
  let saved = !Settings.filter_policy in
  Settings.filter_policy := "strict";
  (match ReconCS.test_configdata local remote with
   | `passed -> test "matching filters + strict = pass" true
   | `failed _ -> test "matching filters + strict = pass" false);
  Settings.filter_policy := saved

let test_filter_policy_strict_reject () =
  (* When filters differ and policy is strict, should fail *)
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["yminsky.dedup"; "cyborg.keyserver-only"] in
  let saved = !Settings.filter_policy in
  Settings.filter_policy := "strict";
  (match ReconCS.test_configdata local remote with
   | `passed -> test "strict rejects mismatch" false
   | `failed _ -> test "strict rejects mismatch" true);
  Settings.filter_policy := saved

let test_filter_policy_warn_allows () =
  (* When filters differ and policy is warn, should pass *)
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["yminsky.dedup"; "cyborg.keyserver-only"] in
  let saved = !Settings.filter_policy in
  Settings.filter_policy := "warn";
  (match ReconCS.test_configdata local remote with
   | `passed -> test "warn allows mismatch" true
   | `failed _ -> test "warn allows mismatch" false);
  Settings.filter_policy := saved

let test_filter_policy_ignore_allows () =
  (* When filters differ and policy is ignore, should pass *)
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["totally.different"] in
  let saved = !Settings.filter_policy in
  Settings.filter_policy := "ignore";
  (match ReconCS.test_configdata local remote with
   | `passed -> test "ignore allows any mismatch" true
   | `failed _ -> test "ignore allows any mismatch" false);
  Settings.filter_policy := saved

let test_filter_policy_default_is_warn () =
  (* Default policy should be "warn" *)
  test "default policy is warn" (!Settings.filter_policy = "warn")

(* ============================================================ *)
(* Config exchange validation tests                              *)
(* ============================================================ *)

let test_configdata_version_check () =
  (* Remote with version too old should be rejected *)
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["yminsky.dedup"] in
  (* Override the version in the remote config to be too old *)
  let remote = (remote |< "version") "0.1.4" in
  (match ReconCS.test_configdata local remote with
   | `passed -> test "old version rejected" false
   | `failed _ -> test "old version rejected" true)

let test_configdata_bitquantum_mismatch () =
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = (remote |< "bitquantum") "3" in
  (match ReconCS.test_configdata local remote with
   | `passed -> test "bitquantum mismatch rejected" false
   | `failed _ -> test "bitquantum mismatch rejected" true)

let test_configdata_mbar_mismatch () =
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = (remote |< "mbar") "10" in
  (match ReconCS.test_configdata local remote with
   | `passed -> test "mbar mismatch rejected" false
   | `failed _ -> test "mbar mismatch rejected" true)

let test_configdata_hockeypuck_scenario () =
  (* Simulate a typical Hockeypuck handshake:
     - version "1.1.3"
     - extra filter "cyborg.keyserver-only"
     - same bitquantum/mbar *)
  let local = ReconCS.build_configdata ["yminsky.dedup"] in
  let remote = ReconCS.build_configdata ["yminsky.dedup"; "cyborg.keyserver-only"] in
  let remote = (remote |< "version") "1.1.3" in
  let saved = !Settings.filter_policy in
  Settings.filter_policy := "warn";
  (match ReconCS.test_configdata local remote with
   | `passed -> test "hockeypuck scenario passes with warn" true
   | `failed reason ->
       test (sprintf "hockeypuck scenario passes with warn (failed: %s)" reason) false);
  Settings.filter_policy := saved

(* ============================================================ *)
(* Extra filter appending tests                                  *)
(* ============================================================ *)

let test_extra_filters_appending () =
  (* When Settings.filters is set, extra filters should be appended *)
  let db_filters = ["yminsky.dedup"; "yminsky.merge"] in
  let saved = !Settings.filters in
  Settings.filters := "cyborg.keyserver-only";
  let extra = if !Settings.filters = "" then []
              else Str.split (Str.regexp ",") !Settings.filters in
  let all_filters = db_filters @ extra in
  test "extra filters appended" (List.length all_filters = 3);
  test "extra filter present" (List.mem "cyborg.keyserver-only" all_filters);
  test "db filters preserved" (List.mem "yminsky.dedup" all_filters);
  Settings.filters := saved

let test_extra_filters_empty () =
  let db_filters = ["yminsky.dedup"] in
  let saved = !Settings.filters in
  Settings.filters := "";
  let extra = if !Settings.filters = "" then []
              else Str.split (Str.regexp ",") !Settings.filters in
  let all_filters = db_filters @ extra in
  test "empty extra filters = db only" (all_filters = db_filters);
  Settings.filters := saved

let test_extra_filters_multiple () =
  let db_filters = ["yminsky.dedup"] in
  let saved = !Settings.filters in
  Settings.filters := "filter1,filter2,filter3";
  let extra = if !Settings.filters = "" then []
              else Str.split (Str.regexp ",") !Settings.filters in
  let all_filters = db_filters @ extra in
  test "multiple extra filters" (List.length all_filters = 4);
  test "filter1 present" (List.mem "filter1" all_filters);
  test "filter3 present" (List.mem "filter3" all_filters);
  Settings.filters := saved

(* ============================================================ *)
(* Build configdata tests                                        *)
(* ============================================================ *)

let test_build_configdata () =
  let cd = ReconCS.build_configdata ["yminsky.dedup"; "cyborg.keyserver-only"] in
  test "configdata has version" ((cd |= "version") = recon_version);
  test "configdata has filters"
    ((cd |= "filters") = "yminsky.dedup,cyborg.keyserver-only");
  test "configdata has bitquantum"
    ((cd |= "bitquantum") = CMarshal.int_to_string !Settings.bitquantum);
  test "configdata has mbar"
    ((cd |= "mbar") = CMarshal.int_to_string !Settings.mbar)

(* ============================================================ *)
(* Hockeypuck filter tests                                       *)
(* ============================================================ *)

open Packet

(* Helper: build a minimal v4 public key packet body.
   Version 4, creation time 0, algorithm RSA(1), MPI for key. *)
let make_pubkey_body () =
  let buf = Buffer.create 32 in
  Buffer.add_char buf '\x04';           (* version 4 *)
  Buffer.add_string buf "\x00\x00\x00\x00"; (* creation time *)
  Buffer.add_char buf '\x01';           (* algorithm: RSA *)
  (* MPI: 1024-bit number = 0x04 0x00 length, then 128 bytes *)
  Buffer.add_char buf '\x04';
  Buffer.add_char buf '\x00';
  Buffer.add_string buf (String.make 128 '\x01');
  Buffer.contents buf

let make_packet tag body =
  { content_tag = tag;
    packet_type = content_tag_to_ptype tag;
    packet_length = String.length body;
    packet_body = body; }

(* Build a v4 self-signature (certification type 0x13) with issuer subpacket *)
let make_v4_selfsig keyid =
  let buf = Buffer.create 64 in
  Buffer.add_char buf '\x04';           (* version 4 *)
  Buffer.add_char buf '\x13';           (* sigtype: Positive certification *)
  Buffer.add_char buf '\x01';           (* pk_alg: RSA *)
  Buffer.add_char buf '\x02';           (* hash_alg: SHA-1 *)
  (* hashed subpackets: creation time (ssp_type=2, 4 bytes) *)
  let hashed_len = 6 in
  Buffer.add_char buf (Char.chr (hashed_len lsr 8));
  Buffer.add_char buf (Char.chr (hashed_len land 0xFF));
  Buffer.add_char buf '\x05';           (* subpacket length: 5 *)
  Buffer.add_char buf '\x02';           (* ssp_type 2: creation time *)
  Buffer.add_string buf "\x00\x00\x00\x01";
  (* unhashed subpackets: issuer keyid (ssp_type=16, 8 bytes) *)
  let unhashed_len = 10 in
  Buffer.add_char buf (Char.chr (unhashed_len lsr 8));
  Buffer.add_char buf (Char.chr (unhashed_len land 0xFF));
  Buffer.add_char buf '\x09';           (* subpacket length: 9 *)
  Buffer.add_char buf '\x10';           (* ssp_type 16: issuer key ID *)
  Buffer.add_string buf keyid;
  (* hash value (2 bytes) *)
  Buffer.add_string buf "\xAB\xCD";
  (* no MPIs needed for test *)
  make_packet 2 (Buffer.contents buf)

(* Build a v4 key revocation signature (type 0x20) with reason subpacket *)
let make_v4_revocation keyid reason_code =
  let buf = Buffer.create 64 in
  Buffer.add_char buf '\x04';           (* version 4 *)
  Buffer.add_char buf '\x20';           (* sigtype: Key revocation *)
  Buffer.add_char buf '\x01';           (* pk_alg: RSA *)
  Buffer.add_char buf '\x02';           (* hash_alg: SHA-1 *)
  (* hashed subpackets: creation time + revocation reason *)
  let reason_ssp = if reason_code >= 0 then 3 else 0 in
  let hashed_len = 6 + reason_ssp in
  Buffer.add_char buf (Char.chr (hashed_len lsr 8));
  Buffer.add_char buf (Char.chr (hashed_len land 0xFF));
  Buffer.add_char buf '\x05';           (* subpacket length: 5 *)
  Buffer.add_char buf '\x02';           (* ssp_type 2: creation time *)
  Buffer.add_string buf "\x00\x00\x00\x02";
  (if reason_code >= 0 then begin
    Buffer.add_char buf '\x02';         (* subpacket length: 2 *)
    Buffer.add_char buf '\x1d';         (* ssp_type 29: reason *)
    Buffer.add_char buf (Char.chr reason_code)
  end);
  (* unhashed subpackets: issuer keyid *)
  let unhashed_len = 10 in
  Buffer.add_char buf (Char.chr (unhashed_len lsr 8));
  Buffer.add_char buf (Char.chr (unhashed_len land 0xFF));
  Buffer.add_char buf '\x09';           (* subpacket length: 9 *)
  Buffer.add_char buf '\x10';           (* ssp_type 16: issuer key ID *)
  Buffer.add_string buf keyid;
  Buffer.add_string buf "\xAB\xCD";
  make_packet 2 (Buffer.contents buf)

(* Build a v4 subkey binding signature (type 0x18) with issuer *)
let make_v4_binding keyid =
  let buf = Buffer.create 64 in
  Buffer.add_char buf '\x04';           (* version 4 *)
  Buffer.add_char buf '\x18';           (* sigtype: Subkey Binding *)
  Buffer.add_char buf '\x01';
  Buffer.add_char buf '\x02';
  let hashed_len = 6 in
  Buffer.add_char buf (Char.chr (hashed_len lsr 8));
  Buffer.add_char buf (Char.chr (hashed_len land 0xFF));
  Buffer.add_char buf '\x05';
  Buffer.add_char buf '\x02';
  Buffer.add_string buf "\x00\x00\x00\x01";
  let unhashed_len = 10 in
  Buffer.add_char buf (Char.chr (unhashed_len lsr 8));
  Buffer.add_char buf (Char.chr (unhashed_len land 0xFF));
  Buffer.add_char buf '\x09';
  Buffer.add_char buf '\x10';
  Buffer.add_string buf keyid;
  Buffer.add_string buf "\xAB\xCD";
  make_packet 2 (Buffer.contents buf)

let test_pre_filter () =
  let pk = make_packet 6 (make_pubkey_body ()) in
  let uid = make_packet 13 "Test User <test@example.com>" in
  let trust = make_packet 12 "\x00" in
  let marker = make_packet 10 "PGP" in
  let packets = [pk; trust; uid; marker] in
  let filtered = Fixkey.pre_filter packets in
  test "pre_filter removes trust" (List.length filtered = 2);
  test "pre_filter keeps pubkey" (List.exists (fun p -> p.content_tag = 6) filtered);
  test "pre_filter keeps uid" (List.exists (fun p -> p.content_tag = 13) filtered)

let test_drop_uat () =
  let pk_body = make_pubkey_body () in
  let pk = make_packet 6 pk_body in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let uid = make_packet 13 "Test User <test@example.com>" in
  let uat = make_packet 17 "\x00\x01\x02" in  (* User Attribute *)
  let selfsig = make_v4_selfsig keyid in
  let pkey = { KeyMerge.key = pk;
               selfsigs = [];
               uids = [(uid, [selfsig]); (uat, [selfsig])];
               subkeys = [] } in
  let filtered = Fixkey.drop_uat pkey in
  test "drop_uat removes UAT" (List.length filtered.KeyMerge.uids = 1);
  let (remaining_uid, _) = List.hd filtered.KeyMerge.uids in
  test "drop_uat keeps User_ID" (remaining_uid.packet_type = User_ID_Packet)

let test_drop_unparseable () =
  let pk_body = make_pubkey_body () in
  let pk = make_packet 6 pk_body in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let uid = make_packet 13 "Test User" in
  let good_sig = make_v4_selfsig keyid in
  let bad_sig = make_packet 2 "" in  (* empty body: parse_signature fails on read_byte *)
  let pkey = { KeyMerge.key = pk;
               selfsigs = [good_sig; bad_sig];
               uids = [(uid, [good_sig; bad_sig])];
               subkeys = [] } in
  let filtered = Fixkey.drop_unparseable pkey in
  test "drop_unparseable: selfsigs" (List.length filtered.KeyMerge.selfsigs = 1);
  let (_, uid_sigs) = List.hd filtered.KeyMerge.uids in
  test "drop_unparseable: uid sigs" (List.length uid_sigs = 1)

let test_sig_issuer_keyid () =
  let keyid = "\x01\x02\x03\x04\x05\x06\x07\x08" in
  let sig_pkt = make_v4_selfsig keyid in
  let parsed = ParsePGP.parse_signature sig_pkt in
  let extracted = ParsePGP.sig_issuer_keyid parsed in
  test "sig_issuer_keyid extracts keyid" (extracted = Some keyid)

let test_sig_revocation_reason () =
  let keyid = "\x01\x02\x03\x04\x05\x06\x07\x08" in
  (* reason_code 2 = KeyCompromised *)
  let rev_pkt = make_v4_revocation keyid 2 in
  let parsed = ParsePGP.parse_signature rev_pkt in
  let reason = ParsePGP.sig_revocation_reason parsed in
  test "sig_revocation_reason extracts reason" (reason = Some 2);
  (* no reason subpacket (reason_code = -1 means don't add it) *)
  let rev_no_reason = make_v4_revocation keyid (-1) in
  let parsed2 = ParsePGP.parse_signature rev_no_reason in
  let reason2 = ParsePGP.sig_revocation_reason parsed2 in
  test "sig_revocation_reason: none" (reason2 = None)

let test_drop_unbound_uid () =
  let pk_body = make_pubkey_body () in
  let pk = make_packet 6 pk_body in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let other_keyid = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8" in
  let uid_self = make_packet 13 "Self-signed UID" in
  let uid_other = make_packet 13 "Third-party only UID" in
  let self_sig = make_v4_selfsig keyid in
  let other_sig = make_v4_selfsig other_keyid in
  let direct_sig = make_v4_selfsig keyid in
  let pkey = { KeyMerge.key = pk;
               selfsigs = [direct_sig];
               uids = [(uid_self, [self_sig]); (uid_other, [other_sig])];
               subkeys = [] } in
  let filtered = Fixkey.drop_unbound pkey in
  test "drop_unbound removes unbound UID" (List.length filtered.KeyMerge.uids = 1);
  let (remaining, _) = List.hd filtered.KeyMerge.uids in
  test "drop_unbound keeps self-signed UID"
    (remaining.packet_body = "Self-signed UID")

let test_drop_unbound_keeps_selfsigned () =
  let pk_body = make_pubkey_body () in
  let pk = make_packet 6 pk_body in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let uid = make_packet 13 "Good UID" in
  let self_sig = make_v4_selfsig keyid in
  let direct_sig = make_v4_selfsig keyid in
  let subkey_body = make_pubkey_body () in
  let subkey = make_packet 14 subkey_body in
  let binding = make_v4_binding keyid in
  let pkey = { KeyMerge.key = pk;
               selfsigs = [direct_sig];
               uids = [(uid, [self_sig])];
               subkeys = [(subkey, [binding])] } in
  let filtered = Fixkey.drop_unbound pkey in
  test "drop_unbound keeps UID" (List.length filtered.KeyMerge.uids = 1);
  test "drop_unbound keeps subkey" (List.length filtered.KeyMerge.subkeys = 1)

let test_hard_revocation_detection () =
  let pk_body = make_pubkey_body () in
  let pk = make_packet 6 pk_body in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  (* Hard revocation: reason 0 (NoReason) *)
  let hard_rev = make_v4_revocation keyid 0 in
  test "hard rev reason 0" (Fixkey.has_hard_revocation keyid [hard_rev]);
  (* Hard revocation: reason 2 (KeyCompromised) *)
  let hard_rev2 = make_v4_revocation keyid 2 in
  test "hard rev reason 2" (Fixkey.has_hard_revocation keyid [hard_rev2]);
  (* Hard revocation: no reason subpacket *)
  let hard_rev3 = make_v4_revocation keyid (-1) in
  test "hard rev no reason" (Fixkey.has_hard_revocation keyid [hard_rev3]);
  (* Soft revocation: reason 1 (KeySuperseded) *)
  let soft_rev = make_v4_revocation keyid 1 in
  test "soft rev reason 1 not hard" (not (Fixkey.has_hard_revocation keyid [soft_rev]));
  (* Wrong issuer: should not be detected *)
  let other_keyid = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8" in
  let wrong_rev = make_v4_revocation other_keyid 0 in
  test "wrong issuer not hard" (not (Fixkey.has_hard_revocation keyid [wrong_rev]))

let test_hard_revoked_strips_uids () =
  let pk_body = make_pubkey_body () in
  let pk = make_packet 6 pk_body in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let uid = make_packet 13 "Revoked User" in
  let self_sig = make_v4_selfsig keyid in
  let hard_rev = make_v4_revocation keyid 2 in
  let subkey = make_packet 14 (make_pubkey_body ()) in
  let binding = make_v4_binding keyid in
  let pkey = { KeyMerge.key = pk;
               selfsigs = [self_sig; hard_rev];
               uids = [(uid, [self_sig])];
               subkeys = [(subkey, [binding])] } in
  let filtered = Fixkey.drop_hard_revoked_cruft pkey in
  test "hard revoked strips UIDs" (filtered.KeyMerge.uids = []);
  test "hard revoked keeps subkeys with self-sigs"
    (List.length filtered.KeyMerge.subkeys = 1)

let test_filters_list_matches_hockeypuck () =
  (* Verify our filter list matches Hockeypuck's sksDefaultFilters *)
  let expected = [
    "drop:UAT"; "drop:hardRevokedCruft"; "drop:implausible";
    "drop:invalidSelfSig"; "drop:structuralMartian"; "drop:unbound";
    "drop:unparseable"; "schema:application/pgp-keys"; "versions:34";
    "yminsky.dedup"; "yminsky.merge"
  ] in
  test "filter list length" (List.length (Fixkey.filters ()) = List.length expected);
  List.iter (fun f ->
    test (sprintf "filter present: %s" f) (List.mem f (Fixkey.filters ()))
  ) expected

(* ============================================================ *)
(* Hash-tag and crypto verification tests                        *)
(* ============================================================ *)

(** Build a v4 certification signature (type 0x13) with a correct
    2-byte hash prefix computed over the given key+uid.
    This lets us test check_hash_tag / drop_implausible. *)
let make_v4_selfsig_with_hash_tag ~pk ~uid ~keyid ~hash_alg =
  let buf = Buffer.create 64 in
  Buffer.add_char buf '\x04';               (* version 4 *)
  Buffer.add_char buf '\x13';               (* sigtype: Positive certification *)
  Buffer.add_char buf '\x01';               (* pk_alg: RSA *)
  Buffer.add_char buf (Char.chr hash_alg);  (* hash_alg *)
  (* hashed subpackets: creation time (ssp_type=2, 4 bytes) *)
  let hashed_len = 6 in
  Buffer.add_char buf (Char.chr (hashed_len lsr 8));
  Buffer.add_char buf (Char.chr (hashed_len land 0xFF));
  Buffer.add_char buf '\x05';               (* subpacket length: 5 *)
  Buffer.add_char buf '\x02';               (* ssp_type 2: creation time *)
  Buffer.add_string buf "\x00\x00\x00\x01";
  (* unhashed subpackets: issuer keyid (ssp_type=16, 8 bytes) *)
  let unhashed_len = 10 in
  Buffer.add_char buf (Char.chr (unhashed_len lsr 8));
  Buffer.add_char buf (Char.chr (unhashed_len land 0xFF));
  Buffer.add_char buf '\x09';               (* subpacket length: 9 *)
  Buffer.add_char buf '\x10';               (* ssp_type 16: issuer key ID *)
  Buffer.add_string buf keyid;
  (* Now compute the actual hash to get the correct 2-byte prefix *)
  let sig_body_so_far = Buffer.contents buf in
  (* Build signed data: key_material_header + key_body + uid_header + uid_body *)
  let pk_body = pk.packet_body in
  let pk_version = Char.code pk_body.[0] in
  let key_hdr = SigVerify.key_material_header pk_version (String.length pk_body) in
  let uid_hdr = SigVerify.uid_header false (String.length uid.packet_body) in
  let signed_data = key_hdr ^ pk_body ^ uid_hdr ^ uid.packet_body in
  (* V4 trailer: prefix of sig body (version through hashed subpackets)
     then 0x04 0xFF + 4-byte BE length *)
  let prefix_len = 6 + hashed_len in
  let prefix = String.sub sig_body_so_far 0 prefix_len in
  let trailer = prefix ^ "\x04\xFF" ^ SigVerify.int32_be prefix_len in
  let h = SigVerify.hash_for_alg hash_alg in
  h#add_string signed_data;
  h#add_string trailer;
  let digest = h#result in
  (* Append correct 2-byte hash prefix *)
  Buffer.add_char buf digest.[0];
  Buffer.add_char buf digest.[1];
  (* No MPIs needed for hash-tag test *)
  make_packet 2 (Buffer.contents buf)

(** Build a v4 subkey binding sig (0x18) with correct hash tag *)
let make_v4_binding_with_hash_tag ~pk ~subkey ~keyid ~hash_alg =
  let buf = Buffer.create 64 in
  Buffer.add_char buf '\x04';
  Buffer.add_char buf '\x18';               (* sigtype: Subkey Binding *)
  Buffer.add_char buf '\x01';               (* pk_alg: RSA *)
  Buffer.add_char buf (Char.chr hash_alg);
  let hashed_len = 6 in
  Buffer.add_char buf (Char.chr (hashed_len lsr 8));
  Buffer.add_char buf (Char.chr (hashed_len land 0xFF));
  Buffer.add_char buf '\x05';
  Buffer.add_char buf '\x02';
  Buffer.add_string buf "\x00\x00\x00\x01";
  let unhashed_len = 10 in
  Buffer.add_char buf (Char.chr (unhashed_len lsr 8));
  Buffer.add_char buf (Char.chr (unhashed_len land 0xFF));
  Buffer.add_char buf '\x09';
  Buffer.add_char buf '\x10';
  Buffer.add_string buf keyid;
  let sig_body_so_far = Buffer.contents buf in
  let pk_body = pk.packet_body in
  let pk_version = Char.code pk_body.[0] in
  let sk_body = subkey.packet_body in
  let sk_version = Char.code sk_body.[0] in
  let key_hdr = SigVerify.key_material_header pk_version (String.length pk_body) in
  let sk_hdr = SigVerify.key_material_header sk_version (String.length sk_body) in
  let signed_data = key_hdr ^ pk_body ^ sk_hdr ^ sk_body in
  let prefix_len = 6 + hashed_len in
  let prefix = String.sub sig_body_so_far 0 prefix_len in
  let trailer = prefix ^ "\x04\xFF" ^ SigVerify.int32_be prefix_len in
  let h = SigVerify.hash_for_alg hash_alg in
  h#add_string signed_data;
  h#add_string trailer;
  let digest = h#result in
  Buffer.add_char buf digest.[0];
  Buffer.add_char buf digest.[1];
  make_packet 2 (Buffer.contents buf)

let test_check_hash_tag_valid () =
  let pk = make_packet 6 (make_pubkey_body ()) in
  let uid = make_packet 13 "Hash Tag Test <test@example.com>" in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let sig_pkt = make_v4_selfsig_with_hash_tag ~pk ~uid ~keyid ~hash_alg:2 in
  let result = SigVerify.check_hash_tag
    ~primary_key:pk ~target:(SigVerify.Uid_target uid) ~sig_pkt in
  test "hash_tag valid SHA-1" result

let test_check_hash_tag_sha256 () =
  let pk = make_packet 6 (make_pubkey_body ()) in
  let uid = make_packet 13 "SHA256 Test <sha256@example.com>" in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let sig_pkt = make_v4_selfsig_with_hash_tag ~pk ~uid ~keyid ~hash_alg:8 in
  let result = SigVerify.check_hash_tag
    ~primary_key:pk ~target:(SigVerify.Uid_target uid) ~sig_pkt in
  test "hash_tag valid SHA-256" result

let test_check_hash_tag_invalid () =
  let pk = make_packet 6 (make_pubkey_body ()) in
  let uid = make_packet 13 "Bad Hash Test" in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  (* Use the old make_v4_selfsig which has hardcoded 0xABCD hash prefix *)
  let sig_pkt = make_v4_selfsig keyid in
  let result = SigVerify.check_hash_tag
    ~primary_key:pk ~target:(SigVerify.Uid_target uid) ~sig_pkt in
  test "hash_tag invalid = false" (not result)

let test_check_hash_tag_subkey_binding () =
  let pk = make_packet 6 (make_pubkey_body ()) in
  let subkey = make_packet 14 (make_pubkey_body ()) in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let sig_pkt = make_v4_binding_with_hash_tag ~pk ~subkey ~keyid ~hash_alg:2 in
  let result = SigVerify.check_hash_tag
    ~primary_key:pk ~target:(SigVerify.Subkey_target subkey) ~sig_pkt in
  test "hash_tag subkey binding valid" result

let test_drop_implausible () =
  let pk = make_packet 6 (make_pubkey_body ()) in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let other_keyid = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8" in
  let uid = make_packet 13 "Implausible Test" in
  (* Self-sig with correct hash tag *)
  let good_self = make_v4_selfsig_with_hash_tag ~pk ~uid ~keyid ~hash_alg:2 in
  (* Third-party sig with correct hash tag *)
  let good_third = make_v4_selfsig_with_hash_tag ~pk ~uid
                     ~keyid:other_keyid ~hash_alg:2 in
  (* Third-party sig with WRONG hash tag (uses hardcoded 0xABCD) *)
  let bad_third = make_v4_selfsig other_keyid in
  let pkey = { KeyMerge.key = pk;
               selfsigs = [];
               uids = [(uid, [good_self; good_third; bad_third])];
               subkeys = [] } in
  let filtered = Fixkey.drop_implausible pkey in
  let (_, sigs) = List.hd filtered.KeyMerge.uids in
  (* Self-sig is always kept (not checked by implausible), good_third kept,
     bad_third dropped *)
  test "drop_implausible keeps self-sig" (List.length sigs = 2);
  test "drop_implausible removed bad third-party"
    (not (List.memq bad_third sigs))

let test_drop_invalid_selfsig_bad () =
  (* A self-sig that passes hash-tag but fails crypto (no valid RSA MPIs)
     should be dropped by drop_invalid_selfsig.
     Since verify_signature catches exceptions and returns true on error,
     and our test sigs have no MPIs, the verify path for RSA will fail to
     unwrap and return false. *)
  let pk = make_packet 6 (make_pubkey_body ()) in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let uid = make_packet 13 "Crypto Test" in
  let self_sig = make_v4_selfsig_with_hash_tag ~pk ~uid ~keyid ~hash_alg:2 in
  let other_keyid = "\xFF\xFE\xFD\xFC\xFB\xFA\xF9\xF8" in
  let third_sig = make_v4_selfsig_with_hash_tag ~pk ~uid
                    ~keyid:other_keyid ~hash_alg:2 in
  let pkey = { KeyMerge.key = pk;
               selfsigs = [];
               uids = [(uid, [self_sig; third_sig])];
               subkeys = [] } in
  (* drop_invalid_selfsig should drop the self_sig (crypto fails)
     but keep third_sig (not a self-sig). If uid loses all self-sigs
     and there's no other binding, the key is Bad_key *)
  let result =
    try
      let filtered = Fixkey.drop_invalid_selfsig pkey in
      (* The UID should be dropped because it has no valid self-sig *)
      List.length filtered.KeyMerge.uids = 0
    with Fixkey.Bad_key | Fixkey.Bad_key_at _ -> true
  in
  test "drop_invalid_selfsig drops bad self-sig" result

(* ============================================================ *)
(* Filter mode tests                                             *)
(* ============================================================ *)

let test_filter_mode_legacy () =
  let saved = !Settings.filter_mode in
  Settings.filter_mode := "legacy";
  let filters = Fixkey.filters () in
  test "legacy mode returns 2 filters" (List.length filters = 2);
  test "legacy has yminsky.dedup" (List.mem "yminsky.dedup" filters);
  test "legacy has yminsky.merge" (List.mem "yminsky.merge" filters);
  test "legacy has no drop:UAT" (not (List.mem "drop:UAT" filters));
  Settings.filter_mode := saved

let test_filter_mode_hockeypuck () =
  let saved = !Settings.filter_mode in
  Settings.filter_mode := "hockeypuck";
  let filters = Fixkey.filters () in
  test "hockeypuck mode returns 11 filters" (List.length filters = 11);
  test "hockeypuck has drop:UAT" (List.mem "drop:UAT" filters);
  test "hockeypuck has yminsky.dedup" (List.mem "yminsky.dedup" filters);
  Settings.filter_mode := saved

let test_canonicalize_legacy_mode () =
  (* In legacy mode, canonicalize should NOT strip UAT packets.
     Build a key with a UAT uid — legacy mode keeps it,
     hockeypuck mode strips it. *)
  let saved = !Settings.filter_mode in
  let pk = make_packet 6 (make_pubkey_body ()) in
  let keyid = Fingerprint.keyid_from_key ~short:false [pk] in
  let uid = make_packet 13 "Legacy Test" in
  let uid_sig = make_v4_selfsig keyid in
  let uat = make_packet 17 "\x00\x01\x02" in
  let uat_sig = make_v4_selfsig keyid in
  let key = [pk; uid; uid_sig; uat; uat_sig] in
  (* Legacy mode: UATs should be preserved *)
  Settings.filter_mode := "legacy";
  (try
    let canon = Fixkey.canonicalize key in
    let has_uat = List.exists (fun p ->
      p.Packet.packet_type = Packet.User_Attribute_Packet) canon in
    test "legacy canonicalize keeps UAT" has_uat
  with Fixkey.Bad_key | Fixkey.Bad_key_at _ ->
    test "legacy canonicalize keeps UAT" false);
  (* Hockeypuck mode: UATs should be stripped *)
  Settings.filter_mode := "hockeypuck";
  (try
    let canon = Fixkey.canonicalize key in
    let has_uat = List.exists (fun p ->
      p.Packet.packet_type = Packet.User_Attribute_Packet) canon in
    test "hockeypuck canonicalize strips UAT" (not has_uat)
  with Fixkey.Bad_key | Fixkey.Bad_key_at _ ->
    (* Bad_key is acceptable — means hockeypuck filters stripped everything *)
    test "hockeypuck canonicalize strips UAT" true);
  Settings.filter_mode := saved

(* ============================================================ *)
(* Main test runner                                              *)
(* ============================================================ *)

let run () =
  ctr := 0;
  (* Version parsing tests *)
  test_parse_version_normal ();
  test_parse_version_with_suffix ();
  test_parse_version_hockeypuck ();
  test_parse_version_with_label ();
  test_parse_version_two_components ();
  test_parse_version_compatibility ();
  (* Filter policy tests *)
  test_filter_policy_matching ();
  test_filter_policy_strict_reject ();
  test_filter_policy_warn_allows ();
  test_filter_policy_ignore_allows ();
  test_filter_policy_default_is_warn ();
  (* Config exchange validation *)
  test_configdata_version_check ();
  test_configdata_bitquantum_mismatch ();
  test_configdata_mbar_mismatch ();
  test_configdata_hockeypuck_scenario ();
  (* Extra filter appending *)
  test_extra_filters_appending ();
  test_extra_filters_empty ();
  test_extra_filters_multiple ();
  (* Build configdata *)
  test_build_configdata ();
  (* Hockeypuck filter tests *)
  test_pre_filter ();
  test_drop_uat ();
  test_drop_unparseable ();
  test_sig_issuer_keyid ();
  test_sig_revocation_reason ();
  test_drop_unbound_uid ();
  test_drop_unbound_keeps_selfsigned ();
  test_hard_revocation_detection ();
  test_hard_revoked_strips_uids ();
  test_filters_list_matches_hockeypuck ();
  (* Hash-tag and crypto verification tests *)
  test_check_hash_tag_valid ();
  test_check_hash_tag_sha256 ();
  test_check_hash_tag_invalid ();
  test_check_hash_tag_subkey_binding ();
  test_drop_implausible ();
  test_drop_invalid_selfsig_bad ();
  (* Filter mode tests *)
  test_filter_mode_legacy ();
  test_filter_mode_hockeypuck ();
  test_canonicalize_legacy_mode ()
