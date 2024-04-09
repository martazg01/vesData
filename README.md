# vesData 

This tool takes a user-specified IoT product name (e.g., "Amazon Echo") as input, extracts relevant cyber risk data from chosen public repositories using its web crawler and scraper modules. The tool compiles this information into a JSON-formatted text file (illustrated below) as output.

<img width="1805" alt="vesDATA" src="https://github.com/martazg01/vesData/assets/11307175/366403ca-93da-49ed-b733-e0780ba76d4c">

The proof-of-concept implementation of vesData leverages the most widely-used repository in each of the three categories (CVE for vulnerability, Exploit-DB for exploit, and NVD for solution). Scaling up the proof-of-concept is deferred to future work.

## Description
The data collection process is organized into distinct modules that operate sequentially, each fulfilling a specific purpose. The output JSON file is dynamically constructed on the fly as records are retrieved from repositories instead of being assembled only at the conclusion of the process. The process commences with the “Product Identifier” module, which utilizes the provided product name to retrieve the product identity (CPE) from the NVD database, completing section 1 in our data schema. The subsequent module, the “Vulnerability Extractor”, fetches vulnerability records (CVE) and related metrics associated with the product identifier from CVE and NVD databases, populating section 2 in our schema. The third module, “Exploit Collector” within VESDATA, uses extracted vulnerability IDs to gather the corresponding exploit
records from Exploit-DB, completing section 3. Lastly, the “Solution Finder” module searches NVD databases for solution records aligned with product name, vulnerability names/IDs, or exploit names, concluding the construction of section 4.

Considering the diverse access modes provided by different public repositories—such as web-based browsing for CVE and NVD and script-based APIs for Exploit-DB—our tool incorporates tailored functions to facilitate data retrieval. It can either crawl/scrape HTML webpages using HTTP tags or make direct
API calls. To optimize the efficiency of the data-gathering process and mitigate the risk of database blocking resulting from frequent connections, we implement batch requests (e.g., 100 individual requests in a batch) with reasonable time gaps (e.g., a minute) between two successive batches. This approach
is particularly emphasized for repositories that support bulk operations, such as NVD and Exploit-DB.

The tool is written in Python for ease of development and extension.


## Setup Guide
Requires Python 3.8-3.11

Multiple packages need to be installed so a python package installer is helpful, I recommend pip.

The python packages required are
- scrapy
- html
- requests
- beautifulsoup4
- lxml
- htmldate

These are listed in library_requirements.py and can all be installed with pip running this module
  ```bash
python3 library_requirements.py
```
Alternatively, you can install these individually like
```bash
pip install scrapy
```


## Usage
To run the tool, execute automated_vesData.py. This jointly runs all required collection files. Input the product name on the terminal and the structured data will be saved in the `results` folder as "product name_vd.json".

```bash
python3 automated_vesData.py
```


## Cite Our Tool
<a id="1">[1]</a> 
Marta Zumaquero Gil, Zhibo Hu, Minzhao Lyu, Gustavo Batista and Hassan Habibi Gharakheili, "Systematic Mapping and Temporal Reasoning of IoT Cyber Risks using Structured Data", IFIP Networking, Thessaloniki, Greece, Jun 2024. 
