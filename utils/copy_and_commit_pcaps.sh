#!/bin/bash

# Directory containing the pcap files
directory="/dumps"

PATTERNS=("2025-02-21T14" "2025-02-21T15" "2025-02-21T16" "2025-02-21T17" "2025-02-21T18" "2025-02-21T19" "2025-02-21T20" "2025-02-21T21")
for pattern in "${PATTERNS[@]}"; do
    cp /dumps/$pattern-*.pcap ./
    git add .
    git commit -m "dumps: add pcap dumps from host1 $pattern"
    git push
done
