# Execution Steps for Crawling and Storing Vulnerability, Exploit & Solution data of products

This repository contains a set of Python scripts to crawl Common Vulnerabilities and Exposures (CVEs) for a given product name. Follow the steps below to execute the crawling process:

### Step 1: Get CPEs for a Given Product Name
Run `collect_CPEs.py` to fetch the CPEs (Common Platform Enumeration) for the specified product name. When running `collect_CPEs.py`, provide the product name as input in the terminal. The CPE results will be saved in the `results` folder with the filename "product name_CPEs.json".

```bash
python collect_CPEs.py
```

### Step 2: Get CVEs for a Given Product Name
Run `collect_CVEs.py` to retrieve the CVEs for the saved CPEs in the `results` folder corresponding to the given product. Input the product name on the terminal when running `collect_CVEs.py`. The CVE results will be saved in the `results` folder with the filename "product name_CVEs.json".

```bash
python collect_CVEs.py
```

### Step 3: Get Exploits for Saved CVEs
Execute `collect_exploits.py` to obtain the exploits for the saved CPEs in the `results` folder associated with the given product. Input the product name on the terminal when running `collect_exploits.py`. The exploit results will be saved in the `results` folder with the filename "product name_data.json".

```bash
python collect_exploits.py
```

### Step 4: Get Solutions for Saved CVEs
Run `collect_solutions.py` to fetch the solutions for the saved CVEs in the `results` folder for the given product. Input the product name on the terminal when executing `collect_solutions.py`. The solution results will be saved in the `results` folder with the filename "product name_data.json".

```bash
python collect_solutions.py
```

### Step 5: Restructure the Product Data
Use `collect_products.py` to restructure the product information from the CPEs. The restructured data will be saved in the `results` folder as "product name_vd.json".

```bash
python collect_products.py
```

Follow the above steps in order to efficiently crawl vulnerability data for your desired product. 

### Alternative Execution: Automated running file
Run 'automated_vesData.py' to jointly run all required collection files. Input the product name on the terminal and the structured data will be saved in the `results` folder as "product name_vd.json".

```bash
python automated_vesData.py
```
