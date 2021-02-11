#!/bin/bash

pytest --cov=megastone --cov-branch -s tests
coverage html