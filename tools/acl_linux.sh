#!/bin/sh
# Apply only to the explicit runtime directory, using an existing dedicated account.
# Run: sudo sh tools/acl_linux.sh /absolute/path/runtime secureharbor
set -eu
test "$#" -eq 2 || { echo 'Usage: acl_linux.sh ABSOLUTE_RUNTIME EXISTING_SERVICE_USER'; exit 2; }
case "$1" in /*) ;; *) echo 'Absolute runtime path required'; exit 2;; esac
runtime=$(realpath -- "$1")
test "$runtime" != / && test -f "$runtime/server.json" && test -d "$runtime/data" && test -d "$runtime/certs"
id "$2" >/dev/null
command -v setfacl >/dev/null
# Private state only: service account owns runtime; others have no filesystem access.
chown -R "$2":"$(id -gn "$2")" -- "$runtime"
find "$runtime" -type d -exec chmod 700 {} +
find "$runtime" -type f -exec chmod 600 {} +
setfacl -m u::rwx,g::---,m::rwx,o::--- "$runtime/data"
setfacl -d -m u::rwx,g::---,m::rwx,o::--- "$runtime/data"
getfacl "$runtime/data"
