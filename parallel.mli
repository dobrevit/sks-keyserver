(** Fork-based parallel map for OCaml 4.14.1 (GIL prevents Thread parallelism).

    Distributes work across child processes via Unix.fork, collecting results
    through pipes using Marshal.  Workers call _exit to avoid triggering
    at_exit handlers (safe for use when parent has open BDB handles). *)

(** [detect_cpu_count ()] returns the number of available CPUs via nproc.
    Falls back to 1 on any error. *)
val detect_cpu_count : unit -> int

(** [parallel_map ~workers f items] applies [f] to each element of [items],
    distributing work across [workers] forked child processes.

    - When [workers <= 1]: runs sequentially in the current process (no fork).
    - When [workers > 1]: splits [items] into chunks, forks a child per chunk,
      each child applies [f] and marshals results back via a pipe.

    Items for which [f] returns [None] are dropped.
    If a worker dies abnormally, its chunk is lost (logged as warning).
    Result order is not guaranteed to match input order. *)
val parallel_map : workers:int -> ('a -> 'b option) -> 'a list -> 'b list
