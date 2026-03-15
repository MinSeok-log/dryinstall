#!/bin/bash
unshare --mount --pid --fork bash -c "
  mount --bind /dev/null /etc/passwd &&
  mount --bind /dev/null /etc/shadow &&
  node /home/vboxuser/dryinstall/test-malicious/index.js
"
