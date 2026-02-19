type 'a sstream = { mutable first : 'a option; next : unit -> 'a option; }
val make : ?first:'a -> (unit -> 'a option) -> 'a sstream
val next : 'a sstream -> 'a option
val peek : 'a sstream -> 'a option
val junk : 'a sstream -> unit
val of_list : 'a list -> 'a sstream
val is_empty : 'a sstream -> bool
