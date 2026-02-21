(***********************************************************************)
(* build.ml - Executable: Builds up the key database from a multi-file *)
(*            database dump.                                           *)
(*            Dump files are taken from the command-line.              *)
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

module F(M:sig end) = struct
  open StdLabels
  open MoreLabels
  open Printf
  open Arg
  open Common
  module Set = PSet.Set
  open Packet
  let settings = {
    Keydb.withtxn = false;
    Keydb.cache_bytes = !Settings.cache_bytes;
    Keydb.pagesize = !Settings.pagesize;
    Keydb.keyid_pagesize = !Settings.keyid_pagesize;
    Keydb.meta_pagesize = !Settings.meta_pagesize;
    Keydb.subkeyid_pagesize = !Settings.subkeyid_pagesize;
    Keydb.time_pagesize = !Settings.time_pagesize;
    Keydb.tqueue_pagesize = !Settings.tqueue_pagesize;
    Keydb.word_pagesize = !Settings.word_pagesize;
    Keydb.dbdir = Lazy.force Settings.dbdir;
    Keydb.dumpdir = Lazy.force Settings.dumpdir;
  }

  module Keydb = Keydb.Safe

  (* max_keys: 0 = unlimited (load all keys per file), >0 = batch size *)
  let max_keys = !Settings.n
  let fnames = !Settings.anonlist

  let num_workers =
    let n = !Settings.build_workers in
    if n <= 0 then Parallel.detect_cpu_count ()
    else n

  type canon_result =
    | Canonicalized of Packet.packet list
    | Drop_bad_key of string   (* filter name that raised Bad_key *)
    | Drop_too_large
    | Drop_standalone_revoc

  (** Canonicalize a single key, tagging the rejection reason on failure. *)
  let try_canonicalize key =
    try Some (Canonicalized (Fixkey.canonicalize key))
    with
      | Fixkey.Bad_key -> Some (Drop_bad_key "unknown")
      | Fixkey.Bad_key_at stage -> Some (Drop_bad_key stage)
      | Fixkey.Key_too_large -> Some Drop_too_large
      | Fixkey.Standalone_revocation_certificate -> Some Drop_standalone_revoc

  (** Read raw (uncanonicalized) keys from [nextkey].  When [max_keys] > 0,
      reads at most [max_keys] keys.  When [max_keys] = 0, reads all. *)
  let get_raw_keys nextkey ~max_keys =
    let rec loop acc count = match nextkey () with
        Some key ->
          if max_keys > 0 && count >= max_keys then key :: acc
          else loop (key :: acc) (count + 1)
      | None -> acc
    in
    loop [] 0

  let timestr sec =
    sprintf "%.2f min" (sec /. 60.)

  let dbtimer = MTimer.create ()
  let timer = MTimer.create ()

  (** Create a key stream that spans multiple dump files sequentially.
      Returns (nextkey, close) where nextkey returns keys across all files
      and close releases the currently open file handle. *)
  let next_of_files fnames =
    let remaining = ref fnames in
    let cin = ref None in
    let nextkey = ref (fun () -> None) in
    let close_current () =
      match !cin with Some c -> c#close; cin := None | None -> ()
    in
    let rec next () =
      match !nextkey () with
      | Some _ as result -> result
      | None ->
        close_current ();
        match !remaining with
        | [] -> None
        | fname :: rest ->
          remaining := rest;
          let c = new Channel.sys_in_channel (open_in fname) in
          cin := Some c;
          nextkey := Key.next_of_channel c;
          next ()
    in
    (next, close_current)

  (** Canonicalize raw keys using parallel workers, returning keys and
      printing a breakdown of dropped keys by reason. *)
  let canonicalize_keys raw_keys =
    let results =
      Parallel.parallel_map ~workers:num_workers try_canonicalize raw_keys in
    let bad_counts = Hashtbl.create 8 in
    let n_large = ref 0 and n_revoc = ref 0 in
    let bump tbl ~key =
      let n = try Hashtbl.find tbl key with Not_found -> 0 in
      Hashtbl.replace tbl ~key ~data:(n + 1)
    in
    let keys = List.fold_left results ~init:[] ~f:(fun acc r ->
      match r with
      | Canonicalized key -> key :: acc
      | Drop_bad_key stage -> bump bad_counts ~key:stage; acc
      | Drop_too_large -> incr n_large; acc
      | Drop_standalone_revoc -> incr n_revoc; acc) in
    let dropped = List.length raw_keys - List.length keys in
    if dropped > 0 then begin
      let total_bad = Hashtbl.fold bad_counts ~init:0
        ~f:(fun ~key:_ ~data:n acc -> acc + n) in
      printf "\n  dropped %d: %d bad_key" dropped total_bad;
      Hashtbl.iter bad_counts
        ~f:(fun ~key:stage ~data:n -> printf " [%s:%d]" stage n);
      printf ", %d too_large, %d standalone_revoc\n  "
        !n_large !n_revoc
    end;
    keys

  (** Batch mode: stream keys across all files, inserting in batches
      of [max_keys]. Keys accumulate across file boundaries.
      Canonicalization is parallelized across worker processes. *)
  let process_batched fnames ~max_keys =
    let (nextkey, close) = next_of_files fnames in
    protect
      ~f:(fun () ->
            let batch = ref 0 in
            let continue = ref true in
            while !continue do
              incr batch;
              MTimer.start timer;
              printf "Loading raw keys (batch %d)..." !batch;
              flush stdout;
              let raw_keys = get_raw_keys nextkey ~max_keys in
              if raw_keys = [] then (
                printf "no more keys\n"; flush stdout;
                continue := false
              ) else (
                printf "%d read, " (List.length raw_keys); flush stdout;
                let keys = canonicalize_keys raw_keys in
                printf "%d after canonicalization\n"
                  (List.length keys); flush stdout;
                MTimer.start dbtimer;
                Keydb.add_keys keys;
                MTimer.stop dbtimer;
                MTimer.stop timer;
                printf "DB time:  %s.  Total time: %s.\n"
                  (timestr (MTimer.read dbtimer))
                  (timestr (MTimer.read timer));
                flush stdout
              )
            done
         )
      ~finally:close

  (** Unlimited mode: process each file fully, one at a time.
      Canonicalization is parallelized across worker processes. *)
  let process_file fname =
    let cin = new Channel.sys_in_channel (open_in fname) in
    protect
      ~f:(fun () ->
            let nextkey = Key.next_of_channel cin in
            MTimer.start timer;
            printf "Loading raw keys (file %s)..." fname;
            flush stdout;
            let raw_keys = get_raw_keys nextkey ~max_keys:0 in
            printf "%d read, " (List.length raw_keys); flush stdout;
            let keys = canonicalize_keys raw_keys in
            printf "%d after canonicalization\n"
              (List.length keys); flush stdout;
            MTimer.start dbtimer;
            Keydb.add_keys keys;
            MTimer.stop dbtimer;
            MTimer.stop timer;
            printf "DB time:  %s.  Total time: %s.\n"
              (timestr (MTimer.read dbtimer))
              (timestr (MTimer.read timer));
            flush stdout
         )
      ~finally:(fun () -> cin#close)

  (***************************************************************)

  let () = Sys.set_signal Sys.sigusr1 Sys.Signal_ignore
  let () = Sys.set_signal Sys.sigusr2 Sys.Signal_ignore

  (***************************************************************)
  let run () =
    set_logfile "build";
        perror "Running SKS %s%s" Common.version Common.version_suffix;

    if max_keys > 0
    then perror "Batch mode: processing %d keys at a time" max_keys
    else perror "Loading all keys per file (use -n to limit batch size)";

    if num_workers > 1
    then perror "Parallel canonicalization with %d workers" num_workers
    else perror "Sequential canonicalization (use -build_workers N to parallelize)";

    let dbdir = Lazy.force Settings.dbdir in
    if Sys.file_exists dbdir then (
      if Utils.dir_has_db_files dbdir then (
        printf "KeyDB directory already contains database files.  Exiting.\n";
        exit (-1)
      )
      (* directory exists but only has DB_CONFIG — safe to proceed *)
    ) else
      Unix.mkdir dbdir 0o700;
    Utils.initdbconf !Settings.basedir dbdir;

    Keydb.open_dbs settings;
    Keydb.set_meta ~key:"filters"
      ~data:(String.concat ~sep:"," (Fixkey.filters ()));

    protect
      ~f:(fun () ->
            if max_keys > 0 then
              process_batched fnames ~max_keys
            else
              List.iter fnames ~f:process_file
         )
      ~finally:(fun () -> Keydb.close_dbs ())

end
