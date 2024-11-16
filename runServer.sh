#!/bin/bash
port="$1"
rmiregistry "$port" &
java server.PPServer -port "$@" &
