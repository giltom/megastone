#!/bin/bash

DIR=$(dirname $0)
pytest --cov=$DIR/megastone --cov-branch -s $@ $DIR/tests -x -k 'not test_gdb_binary'
coverage html