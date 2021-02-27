#!/bin/bash

DIR=$(dirname $0)
gdb-multiarch --batch -ex "source $DIR/run_gdb_tests.py"
coverage html