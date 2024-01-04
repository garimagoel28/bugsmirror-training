#!/bin/bash

# Task 1: Create a directory named 'TrainingDay2'
mkdir TrainingDay2

# Task 2: Download files from the drive and save them to the folder

# Task 3: Retrieve and put system information into a text file
# Creating a file named 'system_info.txt' in the 'TrainingDay2' folder
output_file="TrainingDay2/system_info.txt"

# Retrieving system information and appending it to the text file
echo "Hostname: $(hostname)" > "$output_file"
echo -e "\nCPU Information:" >> "$output_file"
lscpu | grep -E 'Model name|Architecture' >> "$output_file"
echo -e "\nRAM Information:" >> "$output_file"
free -h | grep -E 'Mem:|total' >> "$output_file"
echo -e "\nDisk Space Information:" >> "$output_file"
df -h / | grep -E 'Filesystem|Size|Used|Avail' >> "$output_file"

echo "Script execution completed. System information saved to $output_file"