for i in $(seq 1 12); do swift test 2>&1 | grep -E "Test run with|signal|exited with unexpected" | sed "s/^/run $i: /"; done
