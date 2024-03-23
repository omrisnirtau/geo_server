#!/bin/bash

# Update package lists
sudo apt update

# Install system-level dependencies
sudo apt install curl jq

# Install Python packages from requirements.txt
pip install -r requirements.txt