#!/bin/bash

DIR=$(dirname $0)
pytest --cov=$DIR/megastone --cov-branch --cov-report= -s $@ $DIR/tests
gdb-multiarch --batch -ex "source $DIR/run_gdb_tests.py"
coverage html