(***********************************************************************)
(* fixkey.ml                                                           *)
(*                                                                     *)
(* Copyright (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010, *)
(*               2011, 2012, 2013  Yaron Minsky and Contributors       *)
(*                                                                     *)
(* This file is part of SKS.  SKS is free software; you can            *)
(* redistribute it and/or modify it under the terms of the GNU General *)
(* Public License as published by the Free Software Foundation; either *)
(* version 2 of the License, or (at your option) any later version.    *)
(*                                                                     *)
(* This program is distributed in the hope that it will be useful, but *)
(* WITHOUT ANY WARRANTY; without even the implied warranty of          *)
(* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU   *)
(* General Public License for more details.                            *)
(*                                                                     *)
(* You should have received a copy of the GNU General Public License   *)
(* along with this program; if not, write to the Free Software         *)
(* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 *)
(* USA or see <http://www.gnu.org/licenses/>.                          *)
(***********************************************************************)

open StdLabels
open MoreLabels
open Common
open Packet

module Map = PMap.Map

exception Bad_key
exception Bad_key_at of string
exception Key_too_large
exception Standalone_revocation_certificate


(** Filter lists for each mode.  Filter names are advertised during
    reconciliation config exchange and must match exactly.
    - hockeypuck: full Hockeypuck sksDefaultFilters (hkp/sks/recon.go)
    - legacy: original SKS filters (yminsky.dedup + yminsky.merge)
*)
let legacy_filters = ["yminsky.dedup"; "yminsky.merge"]

let hockeypuck_filters = [
  "drop:UAT"; "drop:hardRevokedCruft"; "drop:implausible";
  "drop:invalidSelfSig"; "drop:structuralMartian"; "drop:unbound";
  "drop:unparseable"; "schema:application/pgp-keys"; "versions:34";
  "yminsky.dedup"; "yminsky.merge"
]

let filters () =
  match !Settings.filter_mode with
  | "legacy" -> legacy_filters
  | _ -> hockeypuck_filters

(**********************************************************************)
(***  Key Merging  ****************************************************)
(**********************************************************************)

let get_keypacket pkey = pkey.KeyMerge.key

let ( |= ) map key = Map.find key map
let ( |< ) map (key,data) = Map.add ~key ~data map

let rec join_by_keypacket map keylist = match keylist with
  | [] -> map
  | key::tl ->
      let keypacket = get_keypacket key in
      let map =
        try
          let keylist_ref = map |= keypacket in
          keylist_ref := key::!keylist_ref;
          map
        with
            Not_found ->
              map |< (keypacket,ref [key])
      in
      join_by_keypacket map tl

(** Given a list of parsed keys, returns a list of parsed key lists,
  grouped by keypacket *)
let join_by_keypacket keys =
  Map.fold ~f:(fun ~key ~data list -> !data::list) ~init:[]
    (join_by_keypacket Map.empty keys)


(** merges a list of pkeys, throwing a failure if the merge cannot procede *)
let merge_pkeys pkeys = match pkeys with
  | [] -> failwith "Attempt to merge empty list of keys"
  | hd::tl ->
      List.fold_left ~init:hd tl
      ~f:(fun key1 key2 ->
            match KeyMerge.merge_pkeys key1 key2 with
                None -> failwith "PKey merge failed"
              | Some key -> key
         )

(** Accepts collection of keys, which should comprise all keys in the
  database with the same keyid.  Returns list of pairs, first part of pair
  being a list of keys to delete, last part being a list of keys to add
*)
let compute_merge_replacements keys =
  let pkeys = List.map ~f:KeyMerge.key_to_pkey keys in
  (* put parsed keys into list of lists, grouped by key packet *)
  let kp_list = join_by_keypacket pkeys in
  let replacements =
    List.fold_left ~init:[] kp_list
      ~f:(fun list pkeys ->
            if List.length pkeys > 1 then
              (Some (List.map ~f:KeyMerge.flatten pkeys,
                     KeyMerge.flatten (merge_pkeys pkeys)))::list
            else
              None::list
         )
  in
  strip_opt replacements


(**********************************************************************)
(***  Key Canonicalization  *******************************************)
(**********************************************************************)

(** Returns canonicalized version of key.  Raises Bad_key if key should simply
  be discarded
*)
let is_revocation_signature pack =
   match pack.packet_type with
    | Signature_Packet ->
      let parsed_signature = ParsePGP.parse_signature pack in
      let sigtype = match parsed_signature with
       | V3sig s -> s.v3s_sigtype
       | V4sig s -> s.v4s_sigtype
     in
     let result =  match (int_to_sigtype sigtype) with
           | Key_revocation_signature | Subkey_revocation_signature
             | Certification_revocation_signature -> true
           | _ -> false
     in
     result
    | _ -> false

let key_serialized_size key =
  (* +6 is a conservative upper bound for packet header overhead:
     1 byte tag + up to 5 bytes for new-format length encoding.
     This slightly overestimates but ensures we never undercount. *)
  List.fold_left ~init:0 ~f:(fun acc pack ->
    acc + String.length pack.packet_body + 6
  ) key

let check_key_size key =
  let size = key_serialized_size key in
  if size > !Settings.max_key_size then begin
    plerror 3 "Rejecting key: serialized size %d exceeds limit %d"
      size !Settings.max_key_size;
    raise Key_too_large
  end

open KeyMerge

let good_key pack =
  try ignore (ParsePGP.parse_pubkey_info pack); true
  with _ -> false

let good_signature pack =
  try ignore (ParsePGP.parse_signature pack); true
  with _ -> false

(**********************************************************************)
(***  Hockeypuck-compatible filters  **********************************)
(**********************************************************************)

(** drop:structuralMartian — keep only valid key material packet types.
    Hockeypuck only handles tags 6,14,13,2 during parsing (io.go:Parse).
    We also keep tag 17 (UAT) here; it's removed later by drop_uat. *)
let pre_filter packets =
  List.filter packets ~f:(fun p ->
    match p.packet_type with
    | Public_Key_Packet | Public_Subkey_Packet
    | User_ID_Packet | User_Attribute_Packet
    | Signature_Packet -> true
    | _ -> false)

(** drop:UAT — remove User Attribute packets (tag 17) and their sigs.
    Hockeypuck silently ignores tag 17 during parsing. *)
let drop_uat pkey =
  { pkey with uids = List.filter pkey.uids
      ~f:(fun (uid, _) -> uid.packet_type <> User_Attribute_Packet) }

(** drop:unparseable — remove signatures and subkeys that fail to parse.
    Hockeypuck drops packets that fail Parse (io.go:180-215). *)
let drop_unparseable pkey =
  let filter_sigs sigs = List.filter sigs ~f:good_signature in
  { pkey with
    selfsigs = filter_sigs pkey.selfsigs;
    uids = Utils.filter_map pkey.uids ~f:(fun (uid, sigs) ->
      let sigs = filter_sigs sigs in
      if sigs = [] then None else Some (uid, sigs));
    subkeys = Utils.filter_map pkey.subkeys ~f:(fun (sk, sigs) ->
      if not (good_key sk) then None
      else let sigs = filter_sigs sigs in
           if sigs = [] then None else Some (sk, sigs));
  }

(** Check if any signature in the list has an issuer keyid matching
    the primary key.  This is the same check Hockeypuck uses to
    distinguish self-sigs from third-party sigs (userid.go:133). *)
let has_selfsig primary_keyid sigs =
  List.exists sigs ~f:(fun sig_pkt ->
    try
      let parsed = ParsePGP.parse_signature sig_pkt in
      (match ParsePGP.sig_issuer_keyid parsed with
       | Some issuer -> issuer = primary_keyid
       | None -> false)
    with _ -> false)

(** drop:implausible — remove third-party sigs that fail the 2-byte
    hash-tag check.  This recomputes the hash over RFC 4880 signed data
    and compares the first 2 bytes against the signature's hash_value field.
    Self-sigs are left for drop:invalidSelfSig.
    Note: Hockeypuck's SigInfo() methods classify sig types internally
    but do NOT remove sigs based on type in the canonical representation.
    See Hockeypuck verify.go hash-tag functions. *)
let drop_implausible pkey =
  let primary_keyid = Fingerprint.keyid_from_key ~short:false [pkey.key] in
  let keyid_hex = Utils.hexstring primary_keyid in
  let is_selfsig sig_pkt =
    try match ParsePGP.sig_issuer_keyid
              (ParsePGP.parse_signature sig_pkt) with
        | Some issuer -> issuer = primary_keyid
        | None -> false
    with _ -> false
  in
  let n_dropped = ref 0 in
  let filter_sigs target_label target sigs =
    List.filter sigs ~f:(fun sig_pkt ->
      if is_selfsig sig_pkt then true  (* leave for invalidSelfSig *)
      else
        let hash_ok =
          SigVerify.check_hash_tag ~primary_key:pkey.key ~target ~sig_pkt in
        if not hash_ok then begin
          incr n_dropped;
          if !Settings.debuglevel >= 6 then begin
            let (sig_ver, sigtype, hash_alg, issuer_hex) = try
              let parsed = ParsePGP.parse_signature sig_pkt in
              let ver = match parsed with
                | V3sig _ -> 3 | V4sig _ -> 4 in
              let st = match parsed with
                | V3sig s -> s.v3s_sigtype | V4sig s -> s.v4s_sigtype in
              let ha = match parsed with
                | V3sig s -> s.v3s_hash_alg | V4sig s -> s.v4s_hash_alg in
              let iss = match ParsePGP.sig_issuer_keyid parsed with
                | Some k -> Utils.hexstring k | None -> "unknown" in
              (ver, st, ha, iss)
            with _ -> (0, 0, 0, "parse-error") in
            plerror 6
              "implaus-drop key=%s target=%s sigv=%d type=0x%02X \
               hash_alg=%d issuer=%s"
              keyid_hex target_label sig_ver sigtype
              hash_alg issuer_hex
          end
        end;
        hash_ok)
  in
  let result =
    { pkey with
      selfsigs = filter_sigs "direct" SigVerify.Direct_key pkey.selfsigs;
      uids = List.map pkey.uids ~f:(fun (uid, sigs) ->
        (uid, filter_sigs "uid" (SigVerify.Uid_target uid) sigs));
      subkeys = List.map pkey.subkeys ~f:(fun (sk, sigs) ->
        (sk, filter_sigs "subkey" (SigVerify.Subkey_target sk) sigs));
    } in
  if !n_dropped > 0 && !Settings.debuglevel >= 4 then
    plerror 4 "implaus key=%s dropped=%d" keyid_hex !n_dropped;
  result

(** drop:invalidSelfSig — remove self-sigs that fail full cryptographic
    verification.  If a UID/subkey loses all self-sigs, it is dropped.
    If the entire key has no valid self-sigs, raise Bad_key.
    See Hockeypuck resolve.go:37-142. *)
let drop_invalid_selfsig pkey =
  let primary_keyid = Fingerprint.keyid_from_key ~short:false [pkey.key] in
  let is_selfsig sig_pkt =
    try match ParsePGP.sig_issuer_keyid
              (ParsePGP.parse_signature sig_pkt) with
        | Some issuer -> issuer = primary_keyid
        | None -> false
    with _ -> false
  in
  (* Track self-sig failures by algo for diagnostics *)
  let failed_algos = Hashtbl.create 8 in
  let total_selfsigs = ref 0 in
  let filter_sigs target sigs =
    List.filter sigs ~f:(fun sig_pkt ->
      if not (is_selfsig sig_pkt) then true  (* third-party — keep *)
      else begin
        incr total_selfsigs;
        let result =
          SigVerify.verify_signature ~primary_key:pkey.key ~target ~sig_pkt in
        if not result then begin
          let algo = try
            let parsed = ParsePGP.parse_signature sig_pkt in
            match parsed with
            | V3sig s -> s.v3s_pk_alg | V4sig s -> s.v4s_pk_alg
          with _ -> -1 in
          let n = try Hashtbl.find failed_algos algo with Not_found -> 0 in
          Hashtbl.replace failed_algos ~key:algo ~data:(n + 1)
        end;
        result
      end)
  in
  let selfsigs = filter_sigs SigVerify.Direct_key pkey.selfsigs in
  let uids = Utils.filter_map pkey.uids ~f:(fun (uid, sigs) ->
    let sigs = filter_sigs (SigVerify.Uid_target uid) sigs in
    if has_selfsig primary_keyid sigs then Some (uid, sigs) else None) in
  let subkeys = Utils.filter_map pkey.subkeys ~f:(fun (sk, sigs) ->
    let sigs = filter_sigs (SigVerify.Subkey_target sk) sigs in
    if has_selfsig primary_keyid sigs then Some (sk, sigs) else None) in
  if uids = [] && subkeys = []
     && not (has_selfsig primary_keyid selfsigs)
  then begin
    (* Key is about to be dropped — log self-sig failure breakdown *)
    let key_algo = try int_of_char pkey.key.packet_body.[0 + (
      (* v4+: algo at offset 5; v2/v3: algo at offset 7 *)
      let version = int_of_char pkey.key.packet_body.[0] in
      if version >= 4 then 5 else 7)]
    with _ -> -1 in
    let keyid_hex = Utils.hexstring primary_keyid in
    let buf = Buffer.create 64 in
    Buffer.add_string buf (Printf.sprintf
      "Dropping key %s (algo=%d, %d self-sigs failed): "
      keyid_hex key_algo !total_selfsigs);
    Hashtbl.iter failed_algos ~f:(fun ~key:algo ~data:n ->
      Buffer.add_string buf (Printf.sprintf "algo%d=%d " algo n));
    (* Diagnostic: when no self-sigs found, log why *)
    if !total_selfsigs = 0 then begin
      let total_sigs = ref 0 in
      let no_issuer = ref 0 in
      let mismatched = ref 0 in
      let example_issuer = ref "" in
      let check_sig sig_pkt =
        incr total_sigs;
        try match ParsePGP.sig_issuer_keyid
                  (ParsePGP.parse_signature sig_pkt) with
            | Some issuer ->
                if issuer <> primary_keyid then begin
                  incr mismatched;
                  if !example_issuer = "" then
                    example_issuer := Utils.hexstring issuer
                end
            | None -> incr no_issuer
        with _ -> incr no_issuer in
      List.iter pkey.selfsigs ~f:check_sig;
      List.iter pkey.uids ~f:(fun (_, sigs) ->
        List.iter sigs ~f:check_sig);
      List.iter pkey.subkeys ~f:(fun (_, sigs) ->
        List.iter sigs ~f:check_sig);
      Buffer.add_string buf (Printf.sprintf
        "[sigs=%d no_issuer=%d mismatched=%d example=%s]"
        !total_sigs !no_issuer !mismatched
        (if !example_issuer = "" then "none" else !example_issuer))
    end;
    plerror 3 "%s" (Buffer.contents buf);
    raise Bad_key
  end;
  { pkey with selfsigs; uids; subkeys }

(** drop:unbound — remove UIDs and subkeys that have no self-certification.
    Hockeypuck drops these in resolve.go:79-134 after crypto verification.
    We check issuer keyid match (structural check after crypto filtering). *)
let drop_unbound pkey =
  let primary_keyid = Fingerprint.keyid_from_key ~short:false [pkey.key] in
  let uids = List.filter pkey.uids
    ~f:(fun (_uid, sigs) -> has_selfsig primary_keyid sigs) in
  let subkeys = List.filter pkey.subkeys
    ~f:(fun (_sk, sigs) -> has_selfsig primary_keyid sigs) in
  if uids = [] && subkeys = []
     && not (has_selfsig primary_keyid pkey.selfsigs)
  then raise Bad_key;
  { pkey with uids; subkeys }

(** Check if key has a hard revocation (reason nil, 0=NoReason, or
    2=KeyCompromised).  See resolve.go:45-61 and RFC 4880 sec 5.2.3.23 *)
let has_hard_revocation primary_keyid selfsigs =
  List.exists selfsigs ~f:(fun sig_pkt ->
    try
      let parsed = ParsePGP.parse_signature sig_pkt in
      let sigtype = match parsed with
        | V3sig s -> s.v3s_sigtype | V4sig s -> s.v4s_sigtype in
      if int_to_sigtype sigtype <> Key_revocation_signature then false
      else match ParsePGP.sig_issuer_keyid parsed with
        | Some issuer when issuer = primary_keyid ->
            (match ParsePGP.sig_revocation_reason parsed with
             | None -> true     (* no reason subpacket = hard *)
             | Some 0 -> true   (* NoReason *)
             | Some 2 -> true   (* KeyCompromised *)
             | Some _ -> false) (* soft revocation *)
        | _ -> false
    with _ -> false)

(** drop:hardRevokedCruft — on hard-revoked keys, drop all UIDs and
    keep only self-sigs on primary key and subkeys.
    See resolve.go:45-61, 74-76. *)
let drop_hard_revoked_cruft pkey =
  let primary_keyid = Fingerprint.keyid_from_key ~short:false [pkey.key] in
  if not (has_hard_revocation primary_keyid pkey.selfsigs) then pkey
  else
    let is_selfsig sig_pkt =
      try match ParsePGP.sig_issuer_keyid
                  (ParsePGP.parse_signature sig_pkt) with
          | Some issuer -> issuer = primary_keyid
          | None -> true  (* keep if can't determine issuer *)
      with _ -> false
    in
    let selfsigs = List.filter pkey.selfsigs ~f:is_selfsig in
    let subkeys = Utils.filter_map pkey.subkeys ~f:(fun (sk, sigs) ->
      let self_sigs = List.filter sigs ~f:is_selfsig in
      if self_sigs = [] then None
      else Some (sk, self_sigs)) in
    { pkey with selfsigs; uids = []; subkeys }

(**********************************************************************)
(***  Key Canonicalization  *******************************************)
(**********************************************************************)

(** Returns canonicalized version of key.  Raises Bad_key if the key
    should be discarded.
    - In hockeypuck mode: applies the full Hockeypuck-compatible filter
      pipeline (drop:UAT, drop:unbound, crypto verification, etc.)
    - In legacy mode: applies only yminsky.dedup + yminsky.merge
      (original SKS behavior, compatible with legacy SKS servers). *)
let tag_bad_key name f x =
  try f x with Bad_key -> raise (Bad_key_at name)

let pkey_packet_count pkey =
  1 + List.length pkey.selfsigs
  + List.fold_left pkey.uids ~init:0
      ~f:(fun acc (_uid, sigs) -> acc + 1 + List.length sigs)
  + List.fold_left pkey.subkeys ~init:0
      ~f:(fun acc (_sk, sigs) -> acc + 1 + List.length sigs)

let canonicalize key =
  if is_revocation_signature (List.hd key)
    then raise Standalone_revocation_certificate;
  check_key_size key;
  try
    match !Settings.filter_mode with
    | "legacy" ->
        let pkey = key_to_pkey key in
        dedup_key_from_pkey pkey
    | _ ->
        let raw_count = List.length key in
        let packets = pre_filter key in
        let pkey = key_to_pkey packets in
        let c0 = pkey_packet_count pkey in
        let pkey = drop_uat pkey in
        let c1 = pkey_packet_count pkey in
        let pkey = drop_unparseable pkey in
        let c2 = pkey_packet_count pkey in
        let pkey = tag_bad_key "drop_implausible" drop_implausible pkey in
        let c3 = pkey_packet_count pkey in
        let pkey = tag_bad_key "drop_invalid_selfsig" drop_invalid_selfsig pkey in
        let c4 = pkey_packet_count pkey in
        let pkey = tag_bad_key "drop_unbound" drop_unbound pkey in
        let c5 = pkey_packet_count pkey in
        let pkey = drop_hard_revoked_cruft pkey in
        let c6 = pkey_packet_count pkey in
        let result = dedup_key_from_pkey pkey in
        let c7 = List.length result in
        if c7 <> raw_count && !Settings.debuglevel >= 5 then
          plerror 5
            "  filter-trace raw=%d pre=%d uat=%d unparse=%d \
             implaus=%d selfsig=%d unbound=%d revcruf=%d dedup=%d"
            raw_count c0 c1 c2 c3 c4 c5 c6 c7;
        result
  with Unparseable_packet_sequence -> raise (Bad_key_at "unparseable_sequence")

(**********************************************************************)
(***  Presentation Filter  ********************************************)
(**********************************************************************)

let drop_bad_sigs packlist =
  List.filter ~f:good_signature packlist

let sig_filter_sigpair (pack,sigs) =
  let sigs = List.filter ~f:good_signature sigs in
  if sigs = [] then None
  else Some (pack,sigs)

let presentation_filter key =
  let pkey = key_to_pkey key in
  if not (good_key pkey.key)
  then None
  else
    let selfsigs = drop_bad_sigs pkey.selfsigs in
    let subkeys = Utils.filter_map ~f:sig_filter_sigpair pkey.subkeys in
    let uids = Utils.filter_map ~f:sig_filter_sigpair pkey.uids in
    let subkeys = List.filter ~f:(fun (key,_) -> good_key key) subkeys in
    Some (flatten { pkey with
                      selfsigs = selfsigs;
                      uids = uids;
                      subkeys = subkeys;
                  })
