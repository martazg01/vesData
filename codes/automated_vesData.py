import collect_CPEs
import collect_CVEs
import collect_exploits
import collect_products
import collect_sols

# Run the files in the desired order
collect_CPEs.run()
collect_CVEs.run()
collect_exploits.run()
collect_products.run()
collect_sols.run()

# collect_CPEs.py
def run():
    # Code to be executed for file1
    print("Running collect_CPEsfile1.py")

# collect_CVEs.py
def run():
    # Code to be executed for file2
    print("Running collect_CVEs.py")

# collect_exploits.py
def run():
    # Code to be executed for file3
    print("collect_exploits.py")

# collect_products.py
def run():
    # Code to be executed for file3
    print("collect_products.py")

# collect_solutions.py
def run():
    # Code to be executed for file3
    print("collect_sols.py")
