import subprocess
import sys

# List of packages to install
packages = [
    'scrapy',
    'html',
    'requests',
    'beautifulsoup4',
    'lxml',
    'htmldate'
]

# Function to install a package
def install_package(package):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except subprocess.CalledProcessError:
        print(f"Failed to install {package}")

# Install each package
for package in packages:
    install_package(package)

print("All required packages installed successfully!")