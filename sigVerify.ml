(***********************************************************************)
(* sigVerify.ml - RFC 4880 signature verification for Hockeypuck      *)
(*               filter compatibility (drop:implausible,               *)
(*               drop:invalidSelfSig)                                  *)
(***********************************************************************)

open StdLabels
open Packet

(** Raised when verification cannot proceed due to unsupported key/curve
    parameters (not an invalid signature).  Propagates to the outer handler
    in verify_signature which returns [true] (keep conservative). *)
exception Unsupported_params

(** Return a Cryptokit hash object for the given PGP hash algorithm code.
    See RFC 4880 Section 9.4. *)
let hash_for_alg = function
  | 1  -> Cryptokit.Hash.md5 ()
  | 2  -> Cryptokit.Hash.sha1 ()
  | 3  -> Cryptokit.Hash.ripemd160 ()
  | 8  -> Cryptokit.Hash.sha256 ()
  | 9  -> Cryptokit.Hash.sha384 ()
  | 10 -> Cryptokit.Hash.sha512 ()
  | 11 -> Cryptokit.Hash.sha224 ()
  | _  -> raise (Invalid_argument "unsupported hash algorithm")

(** Hash digest size in bytes for a PGP hash algorithm code. *)
let hash_digest_size = function
  | 1  -> 16  (* MD5 *)
  | 2  -> 20  (* SHA-1 *)
  | 3  -> 20  (* RIPEMD-160 *)
  | 8  -> 32  (* SHA-256 *)
  | 9  -> 48  (* SHA-384 *)
  | 10 -> 64  (* SHA-512 *)
  | 11 -> 28  (* SHA-224 *)
  | _  -> 0

(**********************************************************************)
(***  RFC 4880 Signed Data Reconstruction  ****************************)
(**********************************************************************)

(** Build key material header per RFC 4880 Section 5.2.4.
    V3/V4: 0x99 + 2-byte BE length.
    V5/V6: 0x9B + 4-byte BE length. *)
let key_material_header version body_len =
  let buf = Buffer.create 5 in
  (match version with
   | 5 | 6 ->
     Buffer.add_char buf '\x9B';
     Buffer.add_char buf (Char.chr ((body_len lsr 24) land 0xFF));
     Buffer.add_char buf (Char.chr ((body_len lsr 16) land 0xFF));
     Buffer.add_char buf (Char.chr ((body_len lsr 8) land 0xFF));
     Buffer.add_char buf (Char.chr (body_len land 0xFF))
   | _ ->
     Buffer.add_char buf '\x99';
     Buffer.add_char buf (Char.chr ((body_len lsr 8) land 0xFF));
     Buffer.add_char buf (Char.chr (body_len land 0xFF)));
  Buffer.contents buf

(** Build UID/UAT header per RFC 4880 Section 5.2.4.
    User ID: 0xB4 + 4-byte BE length.
    User Attribute: 0xD1 + 4-byte BE length. *)
let uid_header is_uat body_len =
  let buf = Buffer.create 5 in
  Buffer.add_char buf (if is_uat then '\xD1' else '\xB4');
  Buffer.add_char buf (Char.chr ((body_len lsr 24) land 0xFF));
  Buffer.add_char buf (Char.chr ((body_len lsr 16) land 0xFF));
  Buffer.add_char buf (Char.chr ((body_len lsr 8) land 0xFF));
  Buffer.add_char buf (Char.chr (body_len land 0xFF));
  Buffer.contents buf

(** 4-byte big-endian encoding of an integer *)
let int32_be n =
  let buf = Bytes.create 4 in
  Bytes.set buf 0 (Char.chr ((n lsr 24) land 0xFF));
  Bytes.set buf 1 (Char.chr ((n lsr 16) land 0xFF));
  Bytes.set buf 2 (Char.chr ((n lsr 8) land 0xFF));
  Bytes.set buf 3 (Char.chr (n land 0xFF));
  Bytes.to_string buf

(** Extract V4 signature trailer from raw sig packet body.
    The trailer = bytes from version through hashed subpackets,
    then 0x04 0xFF + 4-byte BE length of that prefix.
    Returns: (hash_alg, trailer_bytes) *)
let v4_sig_trailer sig_body =
  (* V4 sig layout: version(1) sigtype(1) pk_alg(1) hash_alg(1)
     hashed_len(2) hashed_subpackets(hashed_len) ... *)
  let hash_alg = Char.code sig_body.[3] in
  let hashed_len =
    (Char.code sig_body.[4] lsl 8) lor (Char.code sig_body.[5]) in
  let prefix_len = 6 + hashed_len in  (* version..end of hashed subpackets *)
  let prefix = String.sub sig_body ~pos:0 ~len:prefix_len in
  let trailer = prefix ^ "\x04\xFF" ^ int32_be prefix_len in
  (hash_alg, trailer)

(** Extract V3 signature trailer from a parsed V3 signature.
    V3 trailer = sigtype(1) + ctime(4) = 5 bytes. *)
let v3_sig_trailer (s : v3sig) =
  let buf = Buffer.create 5 in
  Buffer.add_char buf (Char.chr s.v3s_sigtype);
  let ctime = Int64.to_int s.v3s_ctime in
  Buffer.add_string buf (int32_be ctime);
  (s.v3s_hash_alg, Buffer.contents buf)

(** Type describing what a signature is over *)
type sig_target =
  | Uid_target of packet     (** UID or UAT packet *)
  | Subkey_target of packet  (** Subkey packet *)
  | Direct_key               (** Direct key signature / key revocation *)

(** Build the signed data for a given signature type and target.
    Returns the data that gets hashed (before the trailer).
    See RFC 4880 Section 5.2.4. *)
let build_signed_data ~primary_key ~target sigtype =
  let pk_body = primary_key.packet_body in
  let pk_version = Char.code pk_body.[0] in
  let key_hdr = key_material_header pk_version (String.length pk_body) in
  match sigtype with
  | 0x10 | 0x11 | 0x12 | 0x13 | 0x30 ->
    (* UID certification or cert revocation *)
    (match target with
     | Uid_target uid_pkt ->
       let is_uat = uid_pkt.packet_type = User_Attribute_Packet in
       let uid_hdr = uid_header is_uat (String.length uid_pkt.packet_body) in
       key_hdr ^ pk_body ^ uid_hdr ^ uid_pkt.packet_body
     | _ -> raise Exit)
  | 0x18 | 0x19 | 0x28 ->
    (* Subkey binding / primary key binding / subkey revocation *)
    (match target with
     | Subkey_target sk_pkt ->
       let sk_version = Char.code sk_pkt.packet_body.[0] in
       let sk_hdr = key_material_header sk_version
                      (String.length sk_pkt.packet_body) in
       key_hdr ^ pk_body ^ sk_hdr ^ sk_pkt.packet_body
     | _ -> raise Exit)
  | 0x1F | 0x20 ->
    (* Direct key signature / key revocation *)
    key_hdr ^ pk_body
  | _ -> raise Exit  (* unsupported sigtype *)


(**********************************************************************)
(***  Hash-Tag Check (drop:implausible)  ******************************)
(**********************************************************************)

(** Check if a signature's 2-byte hash prefix matches the actual hash
    computed over the signed data + trailer.
    Returns true if plausible (hash tag matches or can't be checked). *)
let check_hash_tag ~primary_key ~target ~sig_pkt =
  try
    let parsed = ParsePGP.parse_signature sig_pkt in
    let hash_value = match parsed with
      | V3sig s -> s.v3s_hash_value | V4sig s -> s.v4s_hash_value in
    let sigtype = match parsed with
      | V3sig s -> s.v3s_sigtype | V4sig s -> s.v4s_sigtype in
    let signed_data = build_signed_data ~primary_key ~target sigtype in
    let (hash_alg, trailer) = match parsed with
      | V3sig s -> v3_sig_trailer s
      | V4sig _ -> v4_sig_trailer sig_pkt.packet_body
    in
    let h = hash_for_alg hash_alg in
    h#add_string signed_data;
    h#add_string trailer;
    let digest = h#result in
    Char.code digest.[0] = Char.code hash_value.[0]
    && Char.code digest.[1] = Char.code hash_value.[1]
  with _ -> true  (* if we can't check, keep the sig *)


(**********************************************************************)
(***  Full Signature Verification (drop:invalidSelfSig)  **************)
(**********************************************************************)

(** Extract key material MPIs from a public key packet body.
    Returns (algorithm, cin positioned after algorithm byte).
    For V4 keys: skip version(1) + ctime(4) + algorithm(1) = 6 bytes
    For V3 keys: skip version(1) + ctime(4) + expiration(2) + algorithm(1) = 8 bytes
    For V5/V6: skip version(1) + ctime(4) + algorithm(1) + key_material_len(4) = 10 bytes *)
let key_material_reader key_pkt =
  let cin = new Channel.string_in_channel key_pkt.packet_body 0 in
  let version = cin#read_byte in
  let _ctime = cin#read_int64_size 4 in
  (match version with
   | 2 | 3 -> ignore (cin#read_int_size 2)  (* expiration *)
   | 5 | 6 -> ()
   | _ -> ());
  let algorithm = cin#read_byte in
  (match version with
   | 5 | 6 -> ignore (cin#read_int_size 4)  (* key material length *)
   | _ -> ());
  (version, algorithm, cin)

(** PKCS#1 v1.5 DigestInfo OID prefixes for RSA signature verification.
    See RFC 3447 Section 9.2 and RFC 4880 Section 5.2.2. *)
let pkcs1_digest_info_prefix = function
  | 1  -> (* MD5 *)
    "\x30\x20\x30\x0c\x06\x08\x2a\x86\x48\x86\xf7\x0d\x02\x05\x05\x00\x04\x10"
  | 2  -> (* SHA-1 *)
    "\x30\x21\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14"
  | 8  -> (* SHA-256 *)
    "\x30\x31\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x01\x05\x00\x04\x20"
  | 9  -> (* SHA-384 *)
    "\x30\x41\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x02\x05\x00\x04\x30"
  | 10 -> (* SHA-512 *)
    "\x30\x51\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x03\x05\x00\x04\x40"
  | 11 -> (* SHA-224 *)
    "\x30\x2d\x30\x0d\x06\x09\x60\x86\x48\x01\x65\x03\x04\x02\x04\x05\x00\x04\x1c"
  | 3  -> (* RIPEMD-160 *)
    "\x30\x21\x30\x09\x06\x05\x2b\x24\x03\x02\x01\x05\x00\x04\x14"
  | _  -> raise (Invalid_argument "unsupported hash for PKCS1")

(** Verify RSA signature (PKCS#1 v1.5) using cryptokit.
    Unwraps the signature with the public key and checks the DigestInfo encoding. *)
let verify_rsa ~key_pkt ~hash_alg ~digest ~sig_mpis =
  try
    let (_version, _algorithm, cin) = key_material_reader key_pkt in
    let n_mpi = ParsePGP.read_mpi cin in
    let e_mpi = ParsePGP.read_mpi cin in
    let pub_key = { Cryptokit.RSA.size = n_mpi.mpi_bits;
                    n = n_mpi.mpi_data; e = e_mpi.mpi_data } in
    let sig_mpi = List.hd sig_mpis in
    let unwrapped = Cryptokit.RSA.unwrap_signature pub_key sig_mpi.mpi_data in
    (* Check PKCS#1 v1.5 format: 0x00 0x01 [0xFF...] 0x00 DigestInfo digest *)
    (* Layout: [0x00] [0x01] [FF padding] [0x00] [T = DigestInfo || digest]
       where |T| = suffix_len, so separator is at ulen - suffix_len - 1 *)
    let ulen = String.length unwrapped in
    if ulen < 11 then false
    else if Char.code unwrapped.[0] <> 0 || Char.code unwrapped.[1] <> 1 then false
    else
      let prefix = pkcs1_digest_info_prefix hash_alg in
      let dlen = hash_digest_size hash_alg in
      let expected_suffix = prefix ^ digest in
      let suffix_len = String.length expected_suffix in
      if suffix_len + 3 > ulen then false
      else begin
        let sep_pos = ulen - suffix_len - 1 in
        if Char.code unwrapped.[sep_pos] <> 0 then false
        else
          let actual_suffix = String.sub unwrapped ~pos:(sep_pos + 1)
                                ~len:suffix_len in
          (* Verify all padding bytes are 0xFF *)
          let padding_ok = ref true in
          for i = 2 to sep_pos - 1 do
            if Char.code unwrapped.[i] <> 0xFF then padding_ok := false
          done;
          !padding_ok && actual_suffix = expected_suffix
            && dlen > 0  (* sanity check *)
      end
  with _ -> false

(** Verify DSA signature using mirage-crypto-pk.
    Raises Unsupported_params if DSA key parameters are rejected by
    mirage-crypto (e.g. non-standard sizes).  This propagates to the
    outer handler in verify_signature which returns true (keep sig). *)
let verify_dsa ~key_pkt ~digest ~sig_mpis =
  try
    let (_version, _algorithm, cin) = key_material_reader key_pkt in
    let p_mpi = ParsePGP.read_mpi cin in
    let q_mpi = ParsePGP.read_mpi cin in
    let g_mpi = ParsePGP.read_mpi cin in
    let y_mpi = ParsePGP.read_mpi cin in
    let p = Z.of_bits (String.init (String.length p_mpi.mpi_data)
              ~f:(fun i -> p_mpi.mpi_data.[String.length p_mpi.mpi_data - 1 - i])) in
    let q = Z.of_bits (String.init (String.length q_mpi.mpi_data)
              ~f:(fun i -> q_mpi.mpi_data.[String.length q_mpi.mpi_data - 1 - i])) in
    let gg = Z.of_bits (String.init (String.length g_mpi.mpi_data)
               ~f:(fun i -> g_mpi.mpi_data.[String.length g_mpi.mpi_data - 1 - i])) in
    let y = Z.of_bits (String.init (String.length y_mpi.mpi_data)
              ~f:(fun i -> y_mpi.mpi_data.[String.length y_mpi.mpi_data - 1 - i])) in
    match Mirage_crypto_pk.Dsa.pub ~p ~q ~gg ~y () with
    | Error _ -> raise Unsupported_params
    | Ok pub ->
      let r_mpi = List.nth sig_mpis 0 in
      let s_mpi = List.nth sig_mpis 1 in
      Mirage_crypto_pk.Dsa.verify ~key:pub
        (r_mpi.mpi_data, s_mpi.mpi_data) digest
  with
  | Unsupported_params -> raise Unsupported_params
  | _ -> false

(** Convert big-endian MPI data to Z.t *)
let z_of_mpi_data data =
  (* Z.of_bits expects little-endian, so reverse *)
  let len = String.length data in
  Z.of_bits (String.init len ~f:(fun i -> data.[len - 1 - i]))

(** Parse ECDSA OID from key packet body.
    Returns the OID bytes (without length prefix). *)
let parse_ecdsa_oid cin =
  let oid_len = cin#read_byte in
  cin#read_string oid_len

(** Known ECDSA curve OIDs *)
let oid_p256 = "\x2a\x86\x48\xce\x3d\x03\x01\x07"  (* 1.2.840.10045.3.1.7 *)
let oid_p384 = "\x2b\x81\x04\x00\x22"                (* 1.3.132.0.34 *)
let oid_p521 = "\x2b\x81\x04\x00\x23"                (* 1.3.132.0.35 *)

(** Verify ECDSA signature using mirage-crypto-ec.
    The public key is in uncompressed point format (0x04 || x || y).
    Raises Unsupported_params for curves outside {P-256, P-384, P-521}. *)
let verify_ecdsa ~key_pkt ~digest ~sig_mpis =
  try
    let (_version, _algorithm, cin) = key_material_reader key_pkt in
    let oid = parse_ecdsa_oid cin in
    (* Read the public key point MPI *)
    let point_mpi = ParsePGP.read_mpi cin in
    let point_data = point_mpi.mpi_data in
    let r_mpi = List.nth sig_mpis 0 in
    let s_mpi = List.nth sig_mpis 1 in
    if oid = oid_p256 then
      (match Mirage_crypto_ec.P256.Dsa.pub_of_octets point_data with
       | Ok pub -> Mirage_crypto_ec.P256.Dsa.verify ~key:pub
                     (r_mpi.mpi_data, s_mpi.mpi_data) digest
       | Error _ -> false)
    else if oid = oid_p384 then
      (match Mirage_crypto_ec.P384.Dsa.pub_of_octets point_data with
       | Ok pub -> Mirage_crypto_ec.P384.Dsa.verify ~key:pub
                     (r_mpi.mpi_data, s_mpi.mpi_data) digest
       | Error _ -> false)
    else if oid = oid_p521 then
      (match Mirage_crypto_ec.P521.Dsa.pub_of_octets point_data with
       | Ok pub -> Mirage_crypto_ec.P521.Dsa.verify ~key:pub
                     (r_mpi.mpi_data, s_mpi.mpi_data) digest
       | Error _ -> false)
    else raise Unsupported_params  (* unsupported curve — keep conservative *)
  with
  | Unsupported_params -> raise Unsupported_params
  | _ -> false

(** Known EdDSA curve OIDs *)
let oid_ed25519 = "\x2b\x06\x01\x04\x01\xda\x47\x0f\x01"  (* 1.3.6.1.4.1.11591.15.1 *)

(** Verify EdDSA (Ed25519) signature using mirage-crypto-ec.
    OpenPGP EdDSA (draft-koch-eddsa-for-openpgp) signs the hash digest,
    NOT the raw message: "The input to the signing function is the hash
    value that has been calculated according to the hash algorithm."
    Raises Unsupported_params for non-Ed25519 curves (e.g. Ed448). *)
let verify_ed25519 ~key_pkt ~digest ~sig_mpis =
  try
    let (_version, algorithm, cin) = key_material_reader key_pkt in
    let key_bytes = match algorithm with
      | 27 ->
        (* RFC 9580 Ed25519: 32 raw bytes, no OID *)
        cin#read_string 32
      | 22 ->
        (* Legacy EdDSA (algorithm 22): OID + MPI *)
        let oid = parse_ecdsa_oid cin in
        if oid <> oid_ed25519 then raise Unsupported_params;
        let point_mpi = ParsePGP.read_mpi cin in
        (* EdDSA MPI: 0x40 prefix byte + 32 bytes = 263 bits *)
        let data = point_mpi.mpi_data in
        if String.length data = 33 && Char.code data.[0] = 0x40
        then String.sub data ~pos:1 ~len:32
        else if String.length data = 32 then data
        else raise Exit
      | _ -> raise Unsupported_params
    in
    let r_mpi = List.nth sig_mpis 0 in
    let s_mpi = List.nth sig_mpis 1 in
    (* EdDSA signature = r (32 bytes) || s (32 bytes) *)
    let sig_bytes =
      let r = r_mpi.mpi_data in
      let s = s_mpi.mpi_data in
      (* Pad/truncate r and s to exactly 32 bytes each *)
      let pad32 d =
        let len = String.length d in
        if len >= 32 then String.sub d ~pos:(len - 32) ~len:32
        else String.make (32 - len) '\x00' ^ d
      in
      pad32 r ^ pad32 s
    in
    (match Mirage_crypto_ec.Ed25519.pub_of_octets key_bytes with
     | Ok pub -> Mirage_crypto_ec.Ed25519.verify ~key:pub sig_bytes ~msg:digest
     | Error _ -> false)
  with
  | Unsupported_params -> raise Unsupported_params
  | _ -> false

(** Verify a self-signature cryptographically.
    Returns true if the signature is valid or uses unsupported params. *)
let verify_signature ~primary_key ~target ~sig_pkt =
  try
    let parsed = ParsePGP.parse_signature sig_pkt in
    let sigtype = match parsed with
      | V3sig s -> s.v3s_sigtype | V4sig s -> s.v4s_sigtype in
    let pk_alg = match parsed with
      | V3sig s -> s.v3s_pk_alg | V4sig s -> s.v4s_pk_alg in
    let hash_alg = match parsed with
      | V3sig s -> s.v3s_hash_alg | V4sig s -> s.v4s_hash_alg in
    let sig_mpis = match parsed with
      | V3sig s -> s.v3s_mpis | V4sig s -> s.v4s_mpis in

    let signed_data = build_signed_data ~primary_key ~target sigtype in
    let (_, trailer) = match parsed with
      | V3sig s -> v3_sig_trailer s
      | V4sig _ -> v4_sig_trailer sig_pkt.packet_body
    in

    let result = match pk_alg with
    | 1 | 2 | 3 ->
      (* RSA: hash the data, then verify PKCS#1 v1.5 *)
      let h = hash_for_alg hash_alg in
      h#add_string signed_data;
      h#add_string trailer;
      let digest = h#result in
      verify_rsa ~key_pkt:primary_key ~hash_alg ~digest ~sig_mpis
    | 17 ->
      (* DSA: hash the data, then verify *)
      let h = hash_for_alg hash_alg in
      h#add_string signed_data;
      h#add_string trailer;
      let digest = h#result in
      verify_dsa ~key_pkt:primary_key ~digest ~sig_mpis
    | 19 ->
      (* ECDSA: hash the data, then verify *)
      let h = hash_for_alg hash_alg in
      h#add_string signed_data;
      h#add_string trailer;
      let digest = h#result in
      verify_ecdsa ~key_pkt:primary_key ~digest ~sig_mpis
    | 22 | 27 ->
      (* EdDSA / Ed25519: hash first, then verify (OpenPGP EdDSA signs the digest) *)
      let h = hash_for_alg hash_alg in
      h#add_string signed_data;
      h#add_string trailer;
      let digest = h#result in
      verify_ed25519 ~key_pkt:primary_key ~digest ~sig_mpis
    | _ ->
      (* Unsupported algorithm — keep the signature *)
      true
    in
    if not result then
      Common.plerror 6 "SigVerify: failed algo=%d hash=%d sigtype=0x%02x"
        pk_alg hash_alg sigtype;
    result
  with
  | Unsupported_params ->
    (* Unsupported curve/params — keep conservative (same as unsupported algo) *)
    Common.plerror 5 "SigVerify: unsupported params, keeping sig";
    true
  | _ -> true  (* if verification fails to run, keep the sig *)
