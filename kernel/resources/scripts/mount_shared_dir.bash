#/bin/bash

sudo mkdir -p /mnt/shared
sudo mount -t 9p -o trans=virtio,version=9p2000.L shared_mod /mnt/shared
