(***********************************************************************)
(* parallel.ml - Fork-based parallel map for CPU-bound work.           *)
(*               Uses Unix.fork + Marshal over pipes for IPC.          *)
(*               Workers call _exit to avoid at_exit handlers.         *)
(*                                                                     *)
(* Copyright (C) 2026  Contributors                                    *)
(*                                                                     *)
(* This file is part of SKS.  SKS is free software; you can            *)
(* redistribute it and/or modify it under the terms of the GNU General *)
(* Public License as published by the Free Software Foundation; either *)
(* version 2 of the License, or (at your option) any later version.    *)
(***********************************************************************)

open StdLabels
open MoreLabels
module Unix = UnixLabels

let detect_cpu_count () =
  try
    let ic = Unix.open_process_in "nproc" in
    let n = int_of_string (input_line ic) in
    ignore (Unix.close_process_in ic);
    max 1 n
  with _ -> 1

(** Split a list into [n] roughly equal chunks. *)
let split_into_chunks n list =
  let len = List.length list in
  if len = 0 || n <= 1 then [list]
  else
    let chunk_size = (len + n - 1) / n in
    let rec split acc current count = function
      | [] ->
        let acc = if current <> [] then (List.rev current) :: acc else acc in
        List.rev acc
      | x :: rest ->
        if count >= chunk_size then
          split ((List.rev current) :: acc) [x] 1 rest
        else
          split acc (x :: current) (count + 1) rest
    in
    split [] [] 0 list

(** Write a value to a file descriptor using Marshal with length prefix. *)
let write_marshal fd value =
  let data = Marshal.to_string value [] in
  let len = String.length data in
  let header = Bytes.create 4 in
  Bytes.set header 0 (Char.chr ((len lsr 24) land 0xFF));
  Bytes.set header 1 (Char.chr ((len lsr 16) land 0xFF));
  Bytes.set header 2 (Char.chr ((len lsr 8) land 0xFF));
  Bytes.set header 3 (Char.chr (len land 0xFF));
  ignore (Unix.write fd ~buf:header ~pos:0 ~len:4);
  ignore (Unix.write fd ~buf:(Bytes.unsafe_of_string data) ~pos:0 ~len)

(** Read a marshalled value from a file descriptor. *)
let read_marshal fd =
  let header = Bytes.create 4 in
  let rec read_all buf pos remaining =
    if remaining > 0 then begin
      let n = Unix.read fd ~buf ~pos ~len:remaining in
      if n = 0 then raise End_of_file;
      read_all buf (pos + n) (remaining - n)
    end
  in
  read_all header 0 4;
  let len = (Char.code (Bytes.get header 0) lsl 24)
        lor (Char.code (Bytes.get header 1) lsl 16)
        lor (Char.code (Bytes.get header 2) lsl 8)
        lor Char.code (Bytes.get header 3) in
  let data = Bytes.create len in
  read_all data 0 len;
  Marshal.from_bytes data 0

let parallel_map ~workers f items =
  if workers <= 1 then
    (* Sequential: no fork *)
    List.fold_left items ~init:[] ~f:(fun acc item ->
      match f item with Some r -> r :: acc | None -> acc)
  else
    let chunks = split_into_chunks workers items in
    let children = List.map chunks ~f:(fun chunk ->
      let (rd, wr) = Unix.pipe () in
      match Unix.fork () with
      | 0 ->
        (* Worker process *)
        (try
           Unix.close rd;
           Sys.set_signal Sys.sigint Sys.Signal_default;
           Sys.set_signal Sys.sigterm Sys.Signal_default;
           let results = List.fold_left chunk ~init:[]
             ~f:(fun acc item ->
               match (try f item with _ -> None) with
               | Some r -> r :: acc
               | None -> acc) in
           write_marshal wr results;
           Unix.close wr;
           (* _exit avoids at_exit handlers — critical for BDB safety *)
           exit 0
         with _ ->
           (try Unix.close wr with _ -> ());
           exit 1)
      | pid ->
        Unix.close wr;
        (pid, rd)
    ) in
    (* Collect results: read from pipe BEFORE waitpid to avoid deadlock *)
    let all_results = List.fold_left children ~init:[]
      ~f:(fun acc (pid, rd) ->
        let results =
          (try (read_marshal rd : 'b list)
           with _ ->
             Common.plerror 2 "Worker %d: failed to read results" pid;
             [])
        in
        Unix.close rd;
        let (_wpid, status) = Unix.waitpid ~mode:[] pid in
        (match status with
         | Unix.WEXITED 0 -> ()
         | Unix.WEXITED n ->
           Common.plerror 2 "Worker %d exited with code %d" pid n
         | Unix.WSIGNALED s ->
           Common.plerror 2 "Worker %d killed by signal %d" pid s
         | Unix.WSTOPPED s ->
           Common.plerror 2 "Worker %d stopped by signal %d" pid s);
        List.rev_append results acc
    ) in
    all_results
