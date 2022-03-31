#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_DIR=$(readlink -f "$SCRIPT_DIR/../../..")
NETNS="$PROJECT_DIR/utils/netns.bash"

# Remove network namespaces
sudo "$NETNS" delete sw0
sudo "$NETNS" delete sw1
sudo "$NETNS" delete sw2
