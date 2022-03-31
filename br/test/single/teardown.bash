#!/bin/bash

SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
PROJECT_DIR=$(readlink -f "$SCRIPT_DIR/../../..")
NETNS="$PROJECT_DIR/utils/netns.bash"

# Remove network namespace
sudo "$NETNS" delete sw0
