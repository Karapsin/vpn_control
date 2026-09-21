#!/bin/sh
# Run one supplied native-fixture command and leave fresh PID/exit receipts.
#
# This intentionally has no retry, cleanup, signal, or command-string handling.
# ``wait`` is kept outside set -e semantics so a failing fixture still receives a
# terminal exit marker.
set -u

usage() {
    echo "usage: $0 --pid-file PATH --exit-file PATH -- COMMAND [ARG ...]" >&2
    exit 64
}

[ "$#" -ge 6 ] || usage
[ "$1" = "--pid-file" ] || usage
pid_file=$2
[ "$3" = "--exit-file" ] || usage
exit_file=$4
[ "$5" = "--" ] || usage
shift 5
[ "$#" -gt 0 ] || usage

[ -n "$pid_file" ] && [ -n "$exit_file" ] && [ "$pid_file" != "$exit_file" ] || usage

# A pre-existing regular file, directory, dangling link, or symlink is never a
# receipt this runner may replace.  noclobber below is the write-time backstop.
for receipt in "$pid_file" "$exit_file"; do
    if [ -e "$receipt" ] || [ -L "$receipt" ]; then
        echo "fixture receipt already exists: $receipt" >&2
        exit 64
    fi
done

# Reserve the PID receipt before launching.  Keep the resulting descriptor so
# the later PID write cannot reopen or replace a path selected by another run.
set -C
exec 3> "$pid_file"
pid_reservation_status=$?
set +C
if [ "$pid_reservation_status" -ne 0 ]; then
    echo "could not reserve fixture PID receipt: $pid_file" >&2
    exit 64
fi

"$@" &
child_pid=$!
printf '%s\n' "$child_pid" >&3
exec 3>&-

# Capture the exact status, including a nonzero fixture.
wait "$child_pid"
child_status=$?

if ! (set -C; printf '%s\n' "$child_status" > "$exit_file"); then
    echo "could not write terminal fixture exit receipt: $exit_file" >&2
    exit 125
fi
exit "$child_status"
