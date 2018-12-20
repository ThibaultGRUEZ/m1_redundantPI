#!/bin/bash
echo "Shutting down all clients..."
sshpass -p raspberry ssh pi@192.168.1.1 pkill -f client.py
sshpass -p raspberry ssh pi@192.168.1.2 pkill -f client.py
echo "Finished !"