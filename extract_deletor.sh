#!/bin/bash
cd /opt/bro/logs/extracted_files
find ./*.* -type f -mmin +1 -exec rm {} \;
