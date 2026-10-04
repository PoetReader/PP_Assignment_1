#!/bin/bash
# reduce lscpu reports
# ./summarize.sh reports

DIR=${1:-reports}

if [[ ! -d "$DIR" ]]; then
    echo "Error: directory '$DIR' not found" >&2
    exit 1
fi

# Count number of 
tmp=$(mktemp)
for f in "$DIR"/*.lscpu; do
    [[ -f "$f" ]] || continue
    type=$(grep -E 'Model name|Socket\(s\)|Core\(s\) per socket|Thread\(s\) per core|NUMA node\(s\)' "$f" \
                  | sed 's/^[[:space:]]*//; s/[[:space:]]\+/ /g' \
                  | tr '\n' '|')
    echo "$type"
done > "$tmp"

total=$(wc -l < "$tmp")
echo "Total nodes: $total"
echo

# Show counts per unique type, sorted by count descending.
sort "$tmp" | uniq -c | sort -rn | while read -r count type; do
    echo "--- $count node(s) ---"
    echo "$type" | tr '|' '\n' | sed '/^$/d'
    echo
done

rm -f "$tmp"
