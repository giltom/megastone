#!/bin/bash

DIR=$(dirname $0)
pytest --cov=$DIR/megastone --cov-branch -s $@ $DIR/tests
coverage html