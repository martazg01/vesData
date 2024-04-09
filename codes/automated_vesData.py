import os
import subprocess

def run_collect_CPEs_updates(product_name):
    print("Running collect_CPEs_updates.py...")
    subprocess.run(["python3", "collect_CPEs_updates.py", product_name])
    print("collect_CPEs_updates.py completed.")

def run_collect_CVEs(product_name):
    print("Running collect_CVEs.py...")
    subprocess.run(["python3", "collect_CVEs.py", product_name])
    print("collect_CVEs.py completed.")

def run_collect_exploits(product_name):
    print("Running collect_exploits.py...")
    subprocess.run(["python3", "collect_exploits.py", product_name])
    print("collect_exploits.py completed.")

def run_collect_solutions(product_name):
    print("Running collect_solutions.py...")
    subprocess.run(["python3", "collect_solutions.py", product_name])
    print("collect_solutions.py completed.")

def run_collect_products(product_name):
    print("Running collect_products.py...")
    subprocess.run(["python3", "collect_products.py", product_name])
    print("collect_products.py completed.")

def main():
    if not os.path.exists("results"):
        os.makedirs("results")

    product_name = input("Enter the product name: ")

    run_collect_CPEs_updates(product_name)
    run_collect_CVEs(product_name)
    run_collect_exploits(product_name)
    run_collect_solutions(product_name)
    run_collect_products(product_name)

if __name__ == "__main__":
    main()