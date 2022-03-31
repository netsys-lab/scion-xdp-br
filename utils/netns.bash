#!/bin/bash

# References:
# https://unix.stackexchange.com/questions/362055/bind-mounts-get-removed-with-network-namespaces
# https://github.com/xdp-project/xdp-tutorial/tree/master/basic04-pinning-maps


# Preparation: Needed only once after reboot
ns_prepare() {
    mount --make-shared /sys/fs/bpf
    mkdir /run/mntns && mount --bind --make-private /run/mntns /run/mntns
}

# Create a new network namespace with access to the BPF file system
ns_add() {
    local NSNAME=$1

    # Create namespace with ip command and make mounts persistent
    # ip netns add $NSNAME \
    #     && touch "/run/mntns/$NSNAME" \
    #     && ip netns exec "$NSNAME" \
    #         sh -x -c "nsenter -t $$ --mount mount --bind /proc/\$\$/ns/mnt '/run/mntns/$NSNAME' && :"

    # Mount BPF file system (not shared with other namespaces)
    # nsenter --net=/run/netns/$NSNAME --mount=/run/mntns/$NSNAME \
    #     mount -t bpf bpf /sys/fs/bpf

    # Manually create network and mount namespace
    # BPF file system is shared with other namespaces including the global namespace
    touch /run/netns/$NSNAME /run/mntns/$NSNAME \
        && unshare --net=/run/netns/$NSNAME --mount=/run/mntns/$NSNAME --propagation shared \
        mount --bind /sys/fs/bpf /sys/fs/bpf
}

# Delete a network namespace created by ns_add.
ns_delete() {
    local NSNAME=$1

    # Unmount BPF file system
    # umount --namespace "/run/mntns/$NSNAME" /sys/fs/bpf

    # Delete namespaces
    umount "/run/netns/$NSNAME" "/run/mntns/$NSNAME" \
        && rm "/run/netns/$NSNAME" "/run/mntns/$NSNAME"
}

# Execute a command in a network namespace.
# nsenter has to be used instead of "ip netns exec" is access to the shared BPF file system is
# required.
ns_exec() {
    local NSNAME=$1
    shift
    local COMMAND="$@"
    local WORKDIR=$PWD

    nsenter --net=/run/netns/$NSNAME --mount=/run/mntns/$NSNAME \
        sh -c "cd $WORKDIR && $COMMAND"
}

if (( $EUID != 0 )); then
    echo "Must be run as root"
    exit
fi

COMMAND=$1
shift
case "$COMMAND" in
    prepare|add|delete|exec) "ns_$COMMAND" "$@" ;;
    *) echo "Invalid command"; exit 1;;
esac
