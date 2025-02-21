import os
import glob
from datetime import datetime

def rename_pcaps(directory):
    # Search for files with the pattern *.pcap[any_number]
    files = glob.glob(os.path.join(directory, '*.pcap*'))
    
    for file_path in files:

        if file_path.endswith('.pcap'):
            continue

        # Get the file creation time
        creation_time = os.path.getctime(file_path)
        creation_date = datetime.fromtimestamp(creation_time).strftime('%Y-%m-%dT%H-%M-%S.%f')[:-3]
        
        # Create the new file name
        new_file_name = f"{creation_date}.pcap"
        new_file_path = os.path.join(directory, new_file_name)
        
        # Rename the file
        os.rename(file_path, new_file_path)
        print(f"Renamed {file_path} to {new_file_path}")

# Example usage
if __name__ == "__main__":
    directory = "/dumps/"
    rename_pcaps(directory)
