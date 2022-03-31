# Copyright (c) 2022 Lars-Christian Schulz
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

######################
## Helper functions ##
######################

# Set the underlay IP and port of a SCION link.
set_link_underlay() {
    local as_a=$1
    local underlay_a=$2
    local as_b=$3
    local underlay_b=$4
    local as_a_config=$(isd_as_to_conf_dir $as_a)
    local as_b_config=$(isd_as_to_conf_dir $as_b)
    jq "(.border_routers[].interfaces[] | select(.\"isd_as\" == \"$as_b\") | .underlay) = {\"public\": \"$underlay_a\", \"remote\": \"$underlay_b\"}" \
    ${SCION_ROOT}/gen/$as_a_config/topology.json | sponge ${SCION_ROOT}/gen/$as_a_config/topology.json
    jq "(.border_routers[].interfaces[] | select(.\"isd_as\" == \"$as_a\") | .underlay) = {\"public\": \"$underlay_b\", \"remote\": \"$underlay_a\"}" \
    ${SCION_ROOT}/gen/$as_b_config/topology.json | sponge ${SCION_ROOT}/gen/$as_b_config/topology.json
}

# Set the address of the SCION control and discovery services.
set_control_addr() {
    local as=$1
    local address=$2
    local as_config=$(isd_as_to_conf_dir $as)
    cat ${SCION_ROOT}/gen/$as_config/topology.json | jq ".control_service[].addr=\"$address\"" \
    | jq ".discovery_service[].addr=\"$address\"" | sponge ${SCION_ROOT}/gen/$as_config/topology.json
}

# Set the internal address of a border router.
set_br_internal_addr() {
    local as=$1
    local br=$2
    local address=$3
    local as_config=$(isd_as_to_conf_dir $as)
    jq ".border_routers.\"$br\".internal_addr = \"$address\"" \
    ${SCION_ROOT}/gen/$as_config/topology.json | sponge ${SCION_ROOT}/gen/$as_config/topology.json
}

# Set the IP address of the SCION daemon.
set_scion_daemon_address() {
    local as_config=$1
    local sd_address=$2
    tomlq -t ".sd.address=\"$sd_address\"" ${SCION_ROOT}/gen/$as_config/sd.toml | sponge ${SCION_ROOT}/gen/$as_config/sd.toml
}

# Convert an ISD-AS pair (e.g., "1-ff00:0:1") to the corresponding configuration directory
# (e.g., "ASff00_0_1").
isd_as_to_conf_dir() {
    echo $1 | sed -r 's/[0-9]-([0-9a-f]+):([0-9a-f]+):([0-9a-f]+)/AS\1_\2_\3/' -
}

# Makes the network namespace of a docker container visible to 'ip netns'.
mount_netns() {
    local cntr=$1
    local pid=$(docker inspect -f '{{.State.Pid}}' $cntr)
    sudo mkdir -p /var/run/netns
    sudo touch /var/run/netns/$cntr
    sudo mount --bind /proc/$pid/ns/net /var/run/netns/$cntr
}

# Cleans up the bind mount created by mount_netns.
umount_netns(){
    local cntr=$1
    sudo umount /var/run/netns/$cntr
    sudo rm /var/run/netns/$cntr
}

# Create a veth pair connecting two network namespaces.
create_veth() {
    local veth0=$1
    local ns0=$2
    local ip0=$3
    local veth1=$4
    local ns1=$5
    local ip1=$6
    sudo ip link add $veth0 netns $ns0 type veth peer name $veth1 netns $ns1
    sudo ip netns exec $ns0 ip add add dev $veth0 $ip0
    sudo ip netns exec $ns0 ip link set dev $veth0 up
    sudo ip netns exec $ns1 ip add add dev $veth1 $ip1
    sudo ip netns exec $ns1 ip link set dev $veth1 up
}

# Create a veth pair connection the global namespace to another namespace.
create_veth_global_ns() {
    local veth0=$1
    local veth1=$2
    local ns1=$3
    local ip1=$4
    sudo ip link add $veth0 type veth peer name $veth1 netns $ns1
    sudo ip netns exec $ns1 ip add add dev $veth1 $ip1
    sudo ip netns exec $ns1 ip link set dev $veth1 up
    sudo ip link set dev $veth0 up
}

# Delete a veth pair.
delete_veth() {
    sudo ip link del $1
}

# Configure iptables to always compute UDP/TCP checksum for outgoing packets on the given interface.
force_chksum_update() {
    local cntr=$1
    local interface=$2
    docker exec -u root $cntr \
    iptables -t mangle -A POSTROUTING -o $interface -p udp -m udp -j CHECKSUM --checksum-fill
    docker exec -u root $cntr \
    iptables -t mangle -A POSTROUTING -o $interface -p tcp -m tcp -j CHECKSUM --checksum-fill
}
