#!/bin/bash

times=()

for i in {1..100}; do
  echo "Run $i:"
  output=$(sudo ./ih_app 10.9.65.55 sctp 38472)
  time=$(echo "$output" | grep "Total Connection Setup Time" | grep -oP '[0-9.]+(?= ms)')
  echo "Setup Time: $time ms"
  times+=("$time")
  sleep 3m
done

echo
echo "CSV Output:"
IFS=,; echo "${times[*]}"



