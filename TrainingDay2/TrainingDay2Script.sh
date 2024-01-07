#!/bin/bash

# Task 1: Create a directory named 'TrainingDay2'
directory_name="TrainingDay2"

# Check if the directory already exists
if [ -d "${directory_name}" ]; then
    echo "Directory '${directory_name}' already exists. Skipping creation."
else
    # If the directory doesn't exist, proceed with the creation
    mkdir "${directory_name}"

    # Check if the creation was successful
    if [ $? -eq 0 ]; then
        echo "Directory '${directory_name}' created successfully!"
    else
        echo "Failed to create directory."
    fi
fi


# Task 2: Download files from the drive and save them to the folder 'TrainingDay2'
file_id="1Xe5etJN_YXHBcWDhaRed5EbNYpyWr8hL"
downloaded_file="TrainingDay2/sample.txt"

gdown "https://drive.google.com/uc?id=${file_id}" -O "${downloaded_file}"

# Task 3: Retrieve and put system information into a text file
# Creating a file named 'system_info.txt' in the 'TrainingDay2 folder'
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