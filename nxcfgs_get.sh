#!/bin/bash

find /etc/nginx/sites-enabled/* -print0 | xargs -0 egrep '^(\s|\t)*server_name' | sed 's/.*server_name \(.*\);.*$/\1/g' | sort | uniq
