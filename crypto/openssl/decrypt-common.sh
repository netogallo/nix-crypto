echo_verbose() {
    if $verbose; then
        echo "[$verbose_name]> " "$@"
    fi
}

exec_verbose() {
    echo_verbose "$@"
    "$@"
}

WORKDIR=$(mktemp -dp /dev/shm)

cleanup() {
	rm -rf "$WORKDIR"
}

if ! $skip_cleanup; then
    trap "cleanup" EXIT
fi

