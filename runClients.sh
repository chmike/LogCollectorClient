#!/bin/bash

echo "starting $1 LogCollector clients"
for ((i=0; i < $1; i++)); do 
    ./LogCollectorClient.py ${@:2} > /dev/null &
done
echo "All $1 LogCollector clients started"


# wait for all child processes to end
wait  && echo "all done"