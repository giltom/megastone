#!/bin/bash

set -ex

EXAMPLES=$(dirname $0)/examples
for SCRIPT in $(find $EXAMPLES -name "*.py")
do
    python $SCRIPT
done