#!/bin/bash
for i in {1..100}
do
  #cargo t simple_threaded --features verbose -- --nocapture 2> log
  cargo t simple_threaded &> /dev/null
  status=$?
  if [ $status -ne 0 ]; then
    exit
  fi
done
echo "Done"
