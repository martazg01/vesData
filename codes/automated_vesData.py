import subprocess

# Specify the file to run
file_1 = "collect_CPEs_updates.py"
file_2 = "collect_CVES.py"
file_3 = "collect_exploits.py"
file_4 = "collect_solutions.py"
file_5 = "collect_products.py"

# Specify the input as a command line argument
input_name = input("Enter input: ")

# Run the file with the specified input
subprocess.run(["python", file_1], input=input_name, text=True, check=True)
subprocess.run(["python", file_2], input=input_name, text=True, check=True)
subprocess.run(["python", file_3], input=input_name, text=True, check=True)
subprocess.run(["python", file_4], input=input_name, text=True, check=True)
subprocess.run(["python", file_5], input=input_name, text=True, check=True)
