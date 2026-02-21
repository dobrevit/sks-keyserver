#!/bin/bash

# SKS build script.
# cd to directory with "dump" subdirectory, and run
# You might want to edit this file to reduce or increase memory usage
# depending on your system

SKS=__BINDIR__/sks

trap ignore_signal USR1 USR2

ignore_signal() {
    echo "Caught user signal 1 or 2, ignoring"
}

ask_mode() {
    echo "Please select the mode in which you want to import the keydump:"
    echo ""
    echo "1 - fastbuild"
    echo "    only an index of the keydump is created and the keydump cannot be"
    echo "    removed."
    echo ""
    echo "2 - normalbuild"
    echo ""
    echo "    all the keydump will be imported in a new database. It takes longer"
    echo "    time and more disk space, but the server will run faster (depending"
    echo "    from the source/age of the keydump)."
    echo "    The keydump can be removed after the import."
    echo ""
    echo -n "Enter enter the mode (1/2): "
    read
    case "$REPLY" in
     1)
        # fastbuild: -n 10 means 10 * 15000 = 150K keys per batch
        mode="fastbuild -n 10"
     ;;
     2)
        # normalbuild: -n 100000 processes 100K keys per batch.
        # Reduce for memory-constrained systems (e.g. -n 10000 for 1GB RAM)
        mode="build /var/lib/sks/dump/*.pgp -n 100000"
     ;;
     *)
        echo "Option unknown. bye!"
        exit 1
     ;;
    esac
}

fail() { echo Command failed unexpectedly.  Bailing out; exit -1; }

ask_mode

echo "=== Running (fast)build... ==="
if ! $SKS $mode -cache 100; then fail; fi
echo === Cleaning key database... ===
if ! $SKS cleandb; then fail; fi
echo === Building ptree database... ===
if ! $SKS pbuild -cache 20 -ptree_cache 70; then fail; fi
echo === Done! ===
