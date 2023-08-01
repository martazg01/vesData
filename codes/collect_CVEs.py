import scrapy, html
import time

from scrapy.crawler import CrawlerProcess 
from multiprocessing import Queue
from multiprocessing import Process, get_context

from scrapy import signals
#from scrapy.conf import settings
from scrapy.crawler import CrawlerProcess
#from scrapy.xlib.pydispatch import dispatcher

import requests
from bs4 import BeautifulSoup
from lxml import etree
import json
import os

#date format changer
from datetime import datetime



title = 'https://nvd.nist.gov/'

input_name = input()

start_time_total = time.time()  # Record the start time
# Variables to keep track of request statistics
total_requests = 0
request_times = []

judge_file_exist = os.path.exists("./results/"+input_name+'_CPEs.json')
if judge_file_exist:
    cve_store = open("./results/"+input_name+'_CPEs.json', encoding='utf-8')
    cpe_cves = json.load(cve_store)
else:
    print("Not exist such file!")
    exit(1)

judge_file_exist = os.path.exists("./results/"+input_name+"_CVEs.json")
if not judge_file_exist:
    json_object = {}
    with open("./results/"+input_name+"_CVEs.json", "w") as outfile:
        json.dump(json_object, outfile)
CVE_dict =  open("./results/"+input_name+"_CVEs.json")
CVE_dict = json.load(CVE_dict)
if CVE_dict == None:
    CVE_dict = {}

j = 0

# start = int(input())
counter = 0
total_length= len(cpe_cves)
cve_record = []
for cpe_name, cve_list in cpe_cves.items():
    # if counter < start:
    #     counter += 1
    #     continue
    counter += 1
    print("progress: " + str(counter)+"/"+str(total_length))
    cve_details = []
    for cve_url in cve_list:
        
        if cve_url in cve_record:
            continue
        if cve_url.split("/")[-1] in CVE_dict:
            continue
        cve_record.append(cve_url)
        #print("before get")

        start_time = time.time()  # Record the start time before making the request

        cve = requests.get(title+cve_url)
        print("request made")

        end_time = time.time()  # Record the end time after receiving the response
        # Update request statistics
        total_requests += 1
        request_time = end_time - start_time
        request_times.append(request_time)

        #print("after get")
        cve.encoding = 'utf-8'
        cve_html = cve.text

        html_1 = etree.HTML(cve_html)
        #f = open("save_cve_page.html", "w")
        #f.write(cve_html)
        #f.close()

        with open("save_cve_page.html", "w", encoding="utf-8") as f:
            f.write(cve_html)
            #f.close()

        html_0 = etree.parse('save_cve_page.html', etree.HTMLParser())
        cve_id = html_0.xpath("//i[@class='fa fa-bug fa-flip-vertical']/following-sibling::span/text()")
        description = html_0.xpath("//p[@data-testid='vuln-description']/text()")
        nvd_published_date = html_0.xpath("//span[@data-testid='vuln-published-on']/text()")
        nvd_last_modified = html_0.xpath("//span[@data-testid='vuln-last-modified-on']/text()")
        #cwe = html_0.xpath("//*[@data-testid='vuln-CWEs-table']/tbody/tr/td/text()")
        cwe_id_find = html_0.xpath("//div/table/tbody/tr/td[@data-testid='vuln-CWEs-link-0']/a/text()")
        cwe_find = html_0.xpath("//div/table/tbody/tr/td[@data-testid='vuln-CWEs-link-0']/text()")
        cwe_link = html_0.xpath("//div/table/tbody/tr/td[@data-testid='vuln-CWEs-link-0']/a/@href")
        #cwe_link = html_0.xpath("//*[@data-testid='vuln-CWEs-table']/@href")
        
        vuln_vector = html_0.xpath("//*/span[@data-testid='vuln-cvss3-nist-vector']/text()")
        #print("vuln_vector", vuln_vector)
        #exclude_version = html_0.xpath("//tr[@class='vulnerable']//td[@data-testid='vuln-software-cpe-1-0-0-0-end-range']/b/text()")

        if vuln_vector != []:
            metrics = vuln_vector[0].split("/")
            if metrics[1] == "AV:N":
                attack_vector = "Network"
            elif metrics[1] == "AV:A":
                attack_vector = "Adjacent Network"
            elif metrics[1] == "AV:L":
                attack_vector = "Local"
            elif metrics[1] == "AV:P":
                attack_vector = "Physical"
            else:
                attack_vector = "Unknown"
            
            if metrics[2] == "AC:L":
                attack_complexity = "Low"
            elif metrics[2] == "AC:H":
                attack_complexity = "High"
            else:
                attack_complexity = "Unknown"
            
            if metrics[3] == "PR:N":
                privilieges_requires = "None"
            elif metrics[3] == "PR:L":
                privilieges_requires = "Low"
            elif metrics[3] == "PR:H":
                privilieges_requires = "High"
            else:
                privilieges_requires = "Unknown"

            if metrics[4] == "UI:N":
                user_interaction = "None"
            elif metrics[4] == "UI:R":
                user_interaction = "Required"
            else:
                user_interaction = "Unknown"
            
            if metrics[5] == "S:U":
                Scope = "Unchanged"
            elif metrics[5] == "S:C":
                Scope = "Changed"
            else:
                Scope = "Unknown"
            
            if metrics[6] == "C:N":
                Confidentiality_impact = "None"
            elif metrics[6] == "C:L":
                Confidentiality_impact = "Low"
            elif metrics[6] == "C:H":
                Confidentiality_impact = "High"
            else:
                Confidentiality_impact = "Unknown"

            if metrics[7] == "I:N":
                Integrity_impact = "None"
            elif metrics[7] == "I:L":
                Integrity_impact = "Low"
            elif metrics[7] == "I:H":
                Integrity_impact = "High"
            else:
                Integrity_impact = "Unknown"

            if metrics[8] == "A:N":
                Availability_impact = "None"
            elif metrics[8] == "A:L":
                Availability_impact = "Low"
            elif metrics[8] == "A:H":
                Availability_impact = "High"
            else:
                Availability_impact = "Unknown"


        if cwe_find:
            cwe_name = cwe_find[-1]
        if cwe_id_find:
            cwe_id = cwe_id_find[0]

        #print("cwe: ", cwe_find)
        #print("cwe link: ", cwe_link)
        
        #hidden_menu_unparsed = html_0.xpath("//input[@id='nistV3MetricHidden']")
        #hidden_menu = html.unescape(hidden_menu_unparsed)

        soup = BeautifulSoup(cve.content, 'html.parser')  #[2]
        input_value = soup.find('input').get('value')

        soup = BeautifulSoup(input_value, 'html.parser')

        impact_score_text = soup.find('span',{'data-testid' : 'vuln-cvssv3-impact-score'})
        impact_score = ""
        if impact_score_text != None:
            impact_score = impact_score_text.text

        exploitability_score_text = soup.find('span',{'data-testid' : 'vuln-cvssv3-exploitability-score'})
        exploitability_score = ""
        if exploitability_score_text != None:
            exploitability_score = exploitability_score_text.text

        
        soup = BeautifulSoup(cve.content, 'html.parser')  #[2]
        input_value = soup.find('input', {'id': "cveTreeJsonDataHidden"}).get('value')
        input_value = json.loads(input_value)

        versions = []
        for dct in input_value:
            for contain in dct["containers"]:
                for cpes in contain["containers"]:
                    for cpe in cpes["cpes"]: 
                        cpe23Uri = {}
                        cpe23Uri["CPE-version"] = "2.3"
                        cpe23Uri["CPE-uri"] = cpe["cpe23Uri"]
                        if cpe["rangeDescription"] == '':
                            cpe23Uri["CPE-range"] = "NA"
                        else:
                            cpe23Uri["CPE-range"] = cpe["rangeDescription"]
                        versions.append(cpe23Uri)
        
        
        #vuln_vector = soup.find('span',{'data-testid' : 'vuln-cvss3-nist-vector'})
        #print("vuln_vector", vuln_vector)
        vuln_dict = {}
        item = {}
        basic_info = {}
        evaluation = {}
        #info

        
        #date format
        date_obj = datetime.strptime(nvd_published_date[0], "%m/%d/%Y")
        nvd_published_date = date_obj.strftime("%d-%b-%Y")
        date_obj = datetime.strptime(nvd_last_modified[0], "%m/%d/%Y")
        nvd_last_modified = date_obj.strftime("%d-%b-%Y")

        #vulnerability-timestamps
        dates = ({"nvd-published": nvd_published_date, "nvd-last-modified": nvd_last_modified})


        #item['cve_id'] = cve_id
        basic_info['description'] = description
        basic_info['vulnerability-timestamps'] = dates
        basic_info['impact-score'] = impact_score
        basic_info['exploitability-score'] = exploitability_score
        basic_info['cwe-id'] = cwe_id
        basic_info['cwe'] = cwe_name
        basic_info['cwe-link'] = cwe_link
        basic_info['cve-url'] = title+cve_url

        # Create a new dictionary for the solutions
        cpe_dict = {}
        for i, cpe_num in enumerate(versions):
            cpe_key = f"CPE-{i+1}"
            cpe_dict[cpe_key] = cpe_num 
        basic_info["affected-product-versions"] = cpe_dict

        if vuln_vector != []:
            evaluation['ves:exploitability-info'] = {
                "attack-vector" : attack_vector,
                "attack-complexity" : attack_complexity,
                "privileges-requires" : privilieges_requires,
                "user-interaction" : user_interaction,
                "scope" : Scope
            }

            evaluation['ves:impact-info'] = {
                "confidentiality" : Confidentiality_impact,
                "integrity" : Integrity_impact,
                "availability" : Availability_impact
            }
        
        item["basic-info"] = basic_info
        item["evaluation"] = evaluation
        
        '''
        #find_patches_info(url)
        soup = BeautifulSoup(cve.content, 'html.parser')  #[2]
        input_value = soup.find('input', {'id': "cveTreeJsonDataHidden"}).get('value')

        soup = BeautifulSoup(input_value, 'html.parser')

        impact_score_text = soup.find('td',{'data-testid' : 'vuln-software-cpe-1-0-0-0'})
        impact_score = ""
        if impact_score_text != None:
            impact_score = impact_score_text.text



        with open("save_cve_page.html", "w", encoding="utf-8") as f:
            json.dump(input_value, f)

        input_value = json.loads(input_value)

        cpe23Uris = []
        rangeDescriptions = []
        versions = []



        for dct in input_value:
            for contain in dct["containers"]:
                for cpes in contain["containers"]:
                    for cpe in cpes["cpes"]:
                        if cpe["rangeDescription"] != "":
                            cpe23Uri = {}
                            cpe23Uri[cpe["cpe23Uri"]] = cpe["rangeDescription"]
                            versions.append(cpe23Uri)

        with open("save_vuln_product_version.html", "w", encoding="utf-8") as f:
            json.dump(versions, f)

        patches_info = []

        product_list = []
        for cpe_dct in versions:
            for key, value in cpe_dct.items():
                head = key.split(":*")[0]
                head_list = head.split(":")
                number = value.split(" ")[-2]
                #print("number: ", number)
                CPE_name = head+":"+ number
                #print("CPE_name: ", CPE_name)
                print("CPE_name: ", CPE_name)

                if head_list[4] in product_list:
                    continue
                else:
                    product_list.append(head_list[4])

                #CPE_name = "cpe:2.3:o:hp:futuresmart_3:2309025_582081"
                search_url = 'https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3' + '&keyword=' + CPE_name

                r_r = requests.get(search_url)

                r_r.encoding = 'utf-8'

                r_html = r_r.text


                f = open("save_cpe_search_page.html", "w")
                f.write(r_html)
                f.close()

                html_cpe_search = etree.parse('save_cpe_search_page.html', etree.HTMLParser())

                #maintable = html_0.xpath("//table[@id='maintable']//table[@class='listtable']//tr/td/a")
                #print("maintable: ", maintable)
                pages_url = html_cpe_search.xpath("//div[@class='searchResults']//div[@class='col-lg-12']/strong/a/@href")
                #print("pages_url: ", pages_url)

                print("pages_url: ", pages_url)

                title = 'https://nvd.nist.gov/'
                if pages_url == []:
                    continue

                CPE_detail_url = title + pages_url[0]

                r_r = requests.get(CPE_detail_url)

                r_r.encoding = 'utf-8'

                r_html = r_r.text

                f = open("save_cpe_page.html", "w")
                f.write(r_html)
                f.close()

                html_cpe = etree.parse('save_cpe_page.html', etree.HTMLParser())

                creation_date = html_cpe.xpath("//dd[@data-testid='cpe-quick-created-on']/text()")

                

                patche_info = {}
                patche_info["part"] = head_list[3]
                patche_info["vendor"] = head_list[4]
                patche_info["product"] = head_list[4]
                patche_info["version number"] = number
                patche_info["creation date"] = creation_date
                patches_info.append(patche_info)
        '''

        # vuln_dict["vuln information"] = item
        # vuln_dict['patches info'] = patches_info
        # cve_details.append(vuln_dict)
        # cve_details.append(item)
        CVE_dict[cve_id[0]] = item
        # CVE_dict[cpe_name] = cve_details

if CVE_dict != {}:
    data = {}
    data["vd"] = {}
    data["vd"]["vd:product"] = {}
    data["vd"]["vd:vulnerability"] = CVE_dict
    data["vd"]["vd:exploit"] = {}
    data["vd"]["vd:solution"] = {}
    with open("./results/"+input_name+"_CVEs.json", 'w') as fp:
        json.dump(data, fp, indent=4)


end_time_total = time.time()  # Record the end time
# Calculate the time taken
execution_time_total = end_time_total - start_time_total
print(f"The file took {execution_time_total:.2f} seconds to run.")

# Calculate the average time per request
average_request_time = sum(request_times) / total_requests

print(f"Total requests made: {total_requests}")
print(f"Average time per request: {average_request_time:.2f} seconds")
