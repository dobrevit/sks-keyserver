(***********************************************************************)
(* sks.ml - Executable: Ueber-executable replacing all others          *)
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
open Printf
open Scanf
open Common

type command =
    { name: string;
      usage: string;
      desc: string;
      func: unit -> unit
    }

let usage command =
  sprintf "Usage: sks %s %s" command.name command.usage

let space = Str.regexp " ";;

let rec commands = [
  { name = "db";
    usage = "";
    desc = "Initiates database server";
    func = (fun () ->
              let module M = Dbserver.F(struct end) in
              M.run ()
           )
  };
  { name = "recon";
    usage = "";
    desc = "Initiates reconciliation server";
    func = (fun () ->
              let module M = Reconserver.F(struct end) in
              M.run ()
           )
  };
  { name = "cleandb";
    usage = "";
    desc = "Apply filters to all keys in database, fixing some common problems";
    func = (fun () ->
              let module M = Clean_keydb.F(struct end) in
              M.run ()
           )
  };
  { name = "build";
    usage = "";
    desc = "Build key database, including body of keys directly in database";
    func = (fun () ->
              let module M = Build.F(struct end) in
              M.run ()
           )
  };
  { name = "fastbuild";
    usage = "-n [size] -cache [mbytes]";
    desc = "Build key database, doesn't include keys directly in database, " ^
           "faster than build . -n specifies the number of keydump files to " ^
           "read per pass when used with build and the multiple of 15,000 " ^
           "keys to be read per pass when used with fastbuild. " ^
           " -cache specifies the database cache to use in megabytes.";
    func = (fun () ->
              let module M = Fastbuild.F(struct end) in
              M.run ()
           )
  };
  { name = "pbuild";
    usage = "-cache [mbytes] -ptree_cache [mbytes]";
    desc = "Build prefix-tree database, used by reconciliation server, " ^
           "from key database.  Allows for specification of cache for " ^
           "key database and for ptree database.";
    func = (fun () ->
              let module M = Pbuild.F(struct end) in
              M.run ()
           )
  };
  { name = "dump";
    usage = "numkeys dumpdir [prefix]";
    desc = "Create a raw dump of the keys in the database. " ^
           "The dump is split into multiple files containing numkeys " ^
           "keys per file. Optional prefix is added to each dump filename.";
    func = (fun () ->
              let module M = Sksdump.F(struct end) in
              M.run ()
           )
  };
  { name = "merge";
    usage = "";
    desc = "Adds key from key files to existing database";
    func = (fun () ->
              let module M = Merge_keyfiles.F(struct end) in
              M.run ()
           )
  };
  { name = "drop";
    usage = "";
    desc = "Drops key from database.  Requires running sks db.";
    func = Sks_do.drop;
  };
  { name = "update_subkeys";
    usage = "[-n # of updates / 1000]";
    desc = "Updates subkey keyid index to include all current keys.  " ^
           "Only useful when upgrading versions 1.0.4 or before of sks.";
    func = Update_subkeys.run;
  };
  { name = "incdump";
    usage = "timestamp(seconds since 1970) [dumpname]";
    desc = "Create a raw dump of the keys in the database that got" ^
           "updated after timestamp";
    func = Incdump.run;
  };
  { name = "unit_test";
    usage = "";
    desc = "Runs basic unit tests and reporst results";
    func = Unit_tests.run;
  };
  { name = "set_filters";
    usage = "filter1,filter2,...";
    desc = "Update the filters metadata in the key database without rebuilding";
    func = (fun () ->
              match !Settings.anonlist with
              | [filters_str] ->
                  let settings = {
                    Keydb.withtxn = true;
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
                  } in
                  let module KDB = Keydb.Safe in
                  KDB.open_dbs settings;
                  protect ~f:(fun () ->
                    KDB.set_meta ~key:"filters" ~data:filters_str;
                    printf "Filters set to: %s\n" filters_str)
                  ~finally:(fun () -> KDB.close_dbs ())
              | _ ->
                  eprintf "Usage: sks set_filters filter1,filter2,...\n";
                  exit (-1)
           )
  };
  { name = "mark_no_modify";
    usage = "<hash_hex>";
    desc = "Mark a key as no-modify (prevents merging/updating via recon or HKP)";
    func = (fun () ->
              match !Settings.anonlist with
              | [hash_hex] ->
                  let settings = {
                    Keydb.withtxn = true;
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
                  } in
                  let module KDB = Keydb.Safe in
                  KDB.open_dbs settings;
                  protect ~f:(fun () ->
                    let hash = KeyHash.dehexify hash_hex in
                    KDB.mark_no_modify ~hash;
                    printf "Key %s marked as no-modify\n" hash_hex)
                  ~finally:(fun () -> KDB.close_dbs ())
              | _ ->
                  eprintf "Usage: sks mark_no_modify <hash_hex>\n";
                  exit (-1)
           )
  };
  { name = "unmark_no_modify";
    usage = "<hash_hex>";
    desc = "Remove no-modify mark from a key (allows merging/updating again)";
    func = (fun () ->
              match !Settings.anonlist with
              | [hash_hex] ->
                  let settings = {
                    Keydb.withtxn = true;
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
                  } in
                  let module KDB = Keydb.Safe in
                  KDB.open_dbs settings;
                  protect ~f:(fun () ->
                    let hash = KeyHash.dehexify hash_hex in
                    KDB.unmark_no_modify ~hash;
                    printf "Key %s no-modify mark removed\n" hash_hex)
                  ~finally:(fun () -> KDB.close_dbs ())
              | _ ->
                  eprintf "Usage: sks unmark_no_modify <hash_hex>\n";
                  exit (-1)
           )
  };
  { name = "help";
    usage = "";
    desc = "Prints this message";
    func = help;
  };
  { name = "version";
    usage = "";
    desc = "Show version information";
    func = Version.run;
  };
]

and help () =
  printf "This is a list of the available commands\n\n";
  List.iter commands
    ~f:(fun c ->
          Format.open_box 3;
          Format.print_string "sks ";
          Format.print_string c.name;
          if c.usage <> "" then (
            Format.print_string " ";
            Format.print_string c.usage);
          Format.print_string ":  ";
          List.iter ~f:(fun s ->
                       Format.print_string s;
                       Format.print_space ();)
            (Str.split space c.desc);
          Format.close_box ();
          Format.print_newline ();
       );
printf "\n"


(****************************************************)

let rec find name commands = match commands with
  | [] -> raise Not_found
  | hd::tl ->
      if hd.name = name
      then hd else find name tl


let () =
  match !Settings.anonlist with
    | [] ->
        eprintf "No command specified\n";
        exit (-1)
    | name::tl ->
        let command =
          try find name commands
             with Not_found ->
            eprintf "Unknown command %s\n" name;
            exit (-1)
        in
        Settings.anonlist := tl;
        try command.func ()
        with
            Argument_error s ->
              eprintf "Argument error: %s\n" s;
              eprintf "Usage: sks %s %s\n%!" command.name command.usage;
              exit (-1)
