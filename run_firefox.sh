#!/bin/bash

echo "Select strategy (1-3):"
read -p "Strategy [1-3]: " strategy

STRATEGY=$strategy DEBUG=1 LD_PRELOAD=./nethook.so firefox