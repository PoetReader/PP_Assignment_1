#!/bin/bash
# collect lscpu from every node in hostfile

HOSTFILE=${1:-hostfile}

HOSTS=$(awk 'NF && $1 !~ /^#/ {print $1}' "$HOSTFILE" | sort -u)

mkdir -p reports
for h in $HOSTS; do
    echo "Querying $h..."
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$h" 'lscpu' > "reports/$h.lscpu" 2>/dev/null &
done
wait
echo "Done. Reports in reports/"
