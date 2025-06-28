#!/bin/bash
set -e

# Wait for MySQL to be available
until mysqladmin ping -h db --silent; do
  echo 'Waiting for MySQL...'
  sleep 2
done

# Start Apache
apache2-foreground 