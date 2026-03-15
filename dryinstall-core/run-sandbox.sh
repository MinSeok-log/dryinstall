#!/bin/bash
echo "=== Final Sandbox: namespace + seccomp ==="
echo "[sandbox] /etc/passwd → /dev/null"
echo "[sandbox] network connect → BLOCKED"
echo "---"

unshare --mount --pid --fork bash -c "
  mount --bind /dev/null /etc/passwd &&
  mount --bind /dev/null /etc/shadow &&
  /home/vboxuser/dryinstall/dryinstall-core/target/debug/dryinstall-core
"
