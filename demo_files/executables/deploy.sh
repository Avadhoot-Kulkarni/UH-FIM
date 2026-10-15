#!/bin/bash
echo 'Deploying application...'
cd /var/www && git pull origin main
systemctl restart app
