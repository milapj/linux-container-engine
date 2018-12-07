#!/bin/sh

# NOTE: must be run as root

BASE=/sys/fs/cgroup
USER=$(whoami)

sudo mkdir $BASE/cpu/hawker
sudo mkdir $BASE/memory/hawker
sudo mkdir $BASE/cpuset/hawker

sudo chown -R $USER:$USER $BASE/cpu/hawker
sudo chown -R $USER:$USER $BASE/memory/hawker
sudo chown -R $USER:$USER $BASE/cpuset/hawker
