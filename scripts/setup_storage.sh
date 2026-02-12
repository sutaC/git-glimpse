#!/bin/bash
# setup_storage.sh - creates restricted mount directory for prod storage
set -e

IMAGE_PATH="/mnt/git-glimpse-data.img"
MOUNT_PATH="/mnt/git-glimpse-data"
SIZE="5G"

echo "Creating disk image..."

sudo fallocate -l $SIZE $IMAGE_PATH
sudo mkfs.ext4 $IMAGE_PATH

echo "Creating mount directory..."

sudo mkdir -p $MOUNT_PATH

echo "Mounting..."

sudo mount -o loop /mnt/git-glimpse-data.img /mnt/git-glimpse-data

echo "Setting ownership..."

sudo chown 1000:1000 $MOUNT_PATH

echo "Adding to /etc/fstab..."

echo "$IMAGE_PATH  $MOUNT_PATH  ext4  loop  0  0" | sudo tee -a /etc/fstab

echo "Done."
