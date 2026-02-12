#!/bin/bash
# remove_storage.sh - remove mount directory for prod storage
set -e

IMAGE_PATH="/mnt/git-glimpse-data.img"
MOUNT_PATH="/mnt/git-glimpse-data"

echo "Stopping containers..."

docker compose down

echo "Unmounting..."

sudo umount -l $MOUNT_PATH

echo "Removing fstab entry..."

sudo sed -i "\|$IMAGE_PATH|d" /etc/fstab

echo "Removing files..."

sudo rm -rf $IMAGE_PATH
sudo rm -rf $MOUNT_PATH

echo "Done."