#!/bin/bash

go build -o $1
sudo setcap cap_net_raw,cap_net_admin=eip ./$1