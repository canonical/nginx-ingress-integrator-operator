#!/bin/bash
# Copyright 2022 Canonical Ltd.
# See LICENSE file for licensing details.

# Check we have the 'woke' snap installed, or error out. If we do have it
# installed, run the 'woke' command against this branch.

/usr/bin/snap list woke > /dev/null
if [ $? != 0 ]; then
    echo "Please install woke ('sudo snap install woke') and rerun"
    exit 1
fi
/snap/bin/woke
