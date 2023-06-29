import requests
from requests.exceptions import SSLError

from bs4 import BeautifulSoup
import json
import os

from htmldate import find_date
import time


def get_nvd_references(cve_id):
    # Construct the URL for the NVD page for the given CVE-ID

    url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    r = requests.get(url)
    soup = BeautifulSoup(r.content, "html.parser")
    #print(soup.prettify())

    initial_analysis_date = "N/A"
    #accesing 'vulnerability change history tables' to later acces date data 
    change_history_table = soup.find_all('table', {"data-testid": "vuln-change-history-table"})
    if len(change_history_table) == 2:
        #NVD updates table
        cve_modified_table = change_history_table[0]
        cve_modified_date = soup.find('span', {"data-testid": "vuln-change-history-date-0"})
        cve_modified_date = cve_modified_date.string
        # Convert to datetime object and convert to desired format
        date_obj = datetime.strptime(cve_modified_date, "%m/%d/%Y %I:%M:%S %p")
        cve_modified_date = date_obj.strftime("%a, %d %b %Y %H:%M:%S GMT")
        #NVD Initial Analysis table
        initial_analysis_table = change_history_table[1]
        initial_analysis_date = soup.find('span', {"data-testid": "vuln-change-history-date-1"})
        initial_analysis_date = initial_analysis_date.string
        # Convert to datetime object and convert to desired format
        date_obj = datetime.strptime(initial_analysis_date, "%m/%d/%Y %I:%M:%S %p")
        initial_analysis_date = date_obj.strftime("%a, %d %b %Y %H:%M:%S GMT")
    if len(change_history_table) == 1:
        initial_analysis_table = change_history_table[0]
        initial_analysis_date = soup.find('span', {"data-testid": "vuln-change-history-date-0"})
        initial_analysis_date = initial_analysis_date.string
        # Convert to datetime object and convert to desired format
        date_obj = datetime.strptime(initial_analysis_date, "%m/%d/%Y %I:%M:%S %p")
        initial_analysis_date = date_obj.strftime("%a, %d %b %Y %H:%M:%S GMT")

    


    #accesing references table in NVD's HTML structure and counting number of references
    vuln_hyperlinks_table = soup.find('table', {"data-testid": "vuln-hyperlinks-table"})
    ref_rows = vuln_hyperlinks_table.find_all('tr')
    ref_num = len(ref_rows)
    #don't count title row
    ref_num = ref_num - 1

    # Extract the references from the section
    references = []
    #specifying cve of which following solutions belong to
    #references.append(cve_id)

    ref_counter = 1
    for num in range(1, ref_num + 1):
        #accesing current reference row
        current_ref = ref_rows[ref_counter]
        print(current_ref)
        #extracting hyperlink
        link = current_ref.find('a')
        ref_url = link.get("href")


        #solution reference's date data

        #when was this reference/solution source latest modified
        last_modified = "N/A"
        page_creation = "N/A"
        #latest update 
        try:
            response = requests.head(ref_url)
            last_modified = response.headers.get("Last-Modified")
        #Errors with Certificate hostname mismatch may occur, last-modified header cannot be collected, so this info is not available.
        except:
            pass  # Ignore the SSL error and continue running the code

        #creation date
        try:
            page_creation = find_date(ref_url)
            if page_creation != None:
                # Convert to datetime object and convert to desired format
                date_obj = datetime.strptime(page_creation, "%Y-%m-%d")
                page_creation = date_obj.strftime("%a, %d %b %Y")


        #Errors with url not reachable occur
        except:
            pass  # Ignore the ValueError error and continue running the code

        if last_modified == None:
            last_modified = "N/A"
        if page_creation == None:
            page_creation = "N/A"


        #creation date, latest update date utilising 'Internet Archive Wayback Machine' database
        url_dates = f"https://archive.org/wayback/available?url={url}"   
        dates = requests.get(url_dates)
        dates_data = dates.json()
        
        #YYYYMMDDHHMMSS, first 8 characters represent the date, remaining characters represent the time
        if 'archived_snapshots' in dates_data and 'closest' in dates_data['archived_snapshots']:
            snapshot = dates_data['archived_snapshots']['closest']
            creation_date = convert_date(snapshot['timestamp'])
            last_updated_date = convert_date(snapshot['timestamp'])
            #print("Creation Date:", creation_date)
            #print("Last Updated Date:", last_updated_date)
        else:
            creation_date = "No data found"
            last_updated_date = "No data found"

        #check if this reference/solution was updated since NVD's initial analysis
        nvd_update = "N/A" #initializing variable
        if len(change_history_table) == 2:
            ref_change_rows = cve_modified_table.find_all('tr')
            change_num = len(ref_change_rows) - 1 #-1 for index purposes
            change_counter = 0
            for num2 in range(1, change_num+1):
                current_change = cve_modified_table.find('td', {"data-testid" : f"vuln-change-history-{change_counter}-new"})
                if current_change == None:
                    continue
                else:
                    change_url = current_change.pre.string
                    #separating table string to get url only
                    index = change_url.find('[')
                    change_url = change_url[:index].strip()
                    #checking if current url was included in updates table
                    if change_url == ref_url:
                        nvd_update = cve_modified_date
                    change_counter += 1



        #accesing badges column of current row
        ref_badges_td = current_ref.find_all('td') 
        ref_badges = ref_badges_td[1]
        #loop to go through source types of resource/hyperlink

        ref_type = []
        for badge in ref_badges.find_all('span', {"class": "badge"}):
            ref_type.append(badge.text)
        #no type specified case
        if len(ref_type) == 0:
            ref_type.append('N/A')
        
        delimiter = ', '
        clean_ref_type = delimiter.join(ref_type)

        #checking if this soluttion reference contains a Patch
        ref_patch = "Patch" in ref_type
        if ref_patch == True:
            patch = "Yes"
        else:
            patch = "No"

        #index = ref_counter+1
        #curr_sol = "solution_" + str(index)
        #references.append(curr_sol)
        #store all dates
        #dates = []
        #dates.append({"create-self": page_creation, "create-archive": creation_date, "last-update-self": last_modified, "latest-update-archive": last_updated_date, "NVD-indexed": initial_analysis_date, "NVD-update": nvd_update})
        dates = ({"created": page_creation, "last-updated": last_modified, "nvd-indexed": initial_analysis_date, "nvd-updated": nvd_update})
        #adding all solution parameters to data structure
        references.append({"url": ref_url, "type": clean_ref_type, "isPatch:": patch, "timestamps": dates})
        ref_counter += 1


    return references


#date format changer
from datetime import datetime

def convert_date(date_string):
    # Convert the input string to a datetime object
    date_obj = datetime.strptime(date_string, "%Y%m%d%H%M%S")
    
    # Format the datetime object to the desired output format
    formatted_date = date_obj.strftime("%A, %d-%b-%Y %H:%M:%S GMT")
    
    return formatted_date


#main


#product CVE search
input_name = input()
judge_file_exist = os.path.exists("./results/"+input_name+'_CVEs.json')
if judge_file_exist:
    cve_store = open("./results/"+input_name+'_CVEs.json', encoding='utf-8')
    data = json.load(cve_store)
else:
    print("Not exist such file!")
    exit(1)

# Check if the JSON file exists
#file_path = f"{product}_data.json"
file_path = "./results/"+input_name+"_data.json"
#file_path = "./results/bosch night camera_data.json"


for cve in data["vd"]["vd:vulnerbility"]: 

    #collecting solutions of cve specified 
    solutions = get_nvd_references(cve)


    #write new CVE's references to json structure
    # Read the existing JSON file
    with open(file_path, "r") as json_file:
        existing_data = json.load(json_file)
        #sols_text["vd:solutions"] = existing_data

    # Create a dictionary for the current CVE if it doesn't exist
    if cve not in existing_data["vd"]["vd:solution"]:
        existing_data["vd"]["vd:solution"][cve] = {}

    # Create a new dictionary for the solutions
    solution_dict = {}
    for i, solution in enumerate(solutions):
        solution_key = f"solution_{i+1}"
        solution_dict[solution_key] = solution

    # Assign the solution dictionary to the existing data
    existing_data["vd"]["vd:solution"][cve] = solution_dict


    # Write the modified JSON data back to the JSON file
    with open(file_path, "w") as json_file:
        json.dump(existing_data, json_file, indent=8)
        #json.dump(sols_text, json_file, indent=8)

    #print data structure
    print(json.dumps(solutions, indent=8))

    #nvd public rate limit (without an API key) is 5 requests in a rolling 30 second window
    time.sleep(6)