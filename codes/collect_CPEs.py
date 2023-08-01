import scrapy, html
import time

from scrapy.crawler import CrawlerProcess
# from item_cve import CveItem 
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

import sys

#running file individually
input_name = input()

start_time_total = time.time()  # Record the start time
# Variables to keep track of request statistics
total_requests = 0
request_times = []

# taking input from "automated_vesData.py"
#input_name = sys.stdin.read().rstrip('\n')

if input_name == "":
    raise Exception("input is invalid")

name_split = input_name.split(" ")
CPE_name = name_split[0]
for i in range(len(name_split)):
    if i == 0:
        continue
    CPE_name = CPE_name + "+" + name_split[i]

#print(CPE_name)

url = 'https://nvd.nist.gov/products/cpe/search'
title = 'https://nvd.nist.gov/'

start_time = time.time()  # Record the start time before making the request

r = requests.get(url)

end_time = time.time()  # Record the end time after receiving the response
 # Update request statistics
total_requests += 1
request_time = end_time - start_time
request_times.append(request_time)

r.encoding = 'utf-8'

html_text = r.text



soup = BeautifulSoup(html_text, "lxml")

search_box = soup.find(class_='SearchTextBox')

search_url = 'https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3' + '&keyword=' + CPE_name

'''
formdata = {'type': 'text',
            'keywords': "Amazon Echo"}
'''

start_time = time.time()  # Record the start time before making the request

r_r = requests.get(search_url)

end_time = time.time()  # Record the end time after receiving the response
 # Update request statistics
total_requests += 1
request_time = end_time - start_time
request_times.append(request_time)

r_r.encoding = 'utf-8'

r_html = r_r.text


f = open("save_cpe_search_page.html", "w")
f.write(r_html)
f.close()

html_cpe_search = etree.parse('save_cpe_search_page.html', etree.HTMLParser())

#maintable = html_0.xpath("//table[@id='maintable']//table[@class='listtable']//tr/td/a")
#print("maintable: ", maintable)
pages_url = html_cpe_search.xpath("//div[@class='searchResults']//ul[@class='pagination']/li/a")

#if len(pages_url) == 0:
#    pages_url.append == html_cpe_search.xpath('/html/body/main/div/div/div[2]/h2/small/a')
#    print(pages_url)

cpe_link_dict = {}
for page in pages_url:
    href = page.xpath("@href")

    print(href)
    #nt("title", check.xpath("@title"))

    start_time = time.time()  # Record the start time before making the request

    r_m = requests.get(title+href[0])

    end_time = time.time()  # Record the end time after receiving the response
    # Update request statistics
    total_requests += 1
    request_time = end_time - start_time
    request_times.append(request_time)

    r_m.encoding = 'utf-8'

    page_search_html = r_m.text

    r_soup = BeautifulSoup(page_search_html, "lxml")

    device_div_list = r_soup.find_all(class_="searchResults")

    for device_div in device_div_list:
        
        cpe_link_list = device_div.find_all(class_='col-lg-12')
        for text in cpe_link_list:
            cpe_text = text.get_text()   
            
            cpe_text_seperate = cpe_text.split(":")
            
            print("cpe_text: ", cpe_text)
            cve_link_class = text.find_all(class_ ='btn btn-sm')
            cve_url_list = []
            for cve_links in cve_link_class:
                cve_link = cve_links['href']
                cve_url_list.append(cve_link)
            cpe_link_dict[cpe_text_seperate[3] + ":" + cpe_text_seperate[4]+":"+cpe_text_seperate[5]] = cve_url_list
            
print(cpe_link_dict)

cpe_cves = {}

i = 0
for cpe_name, cve_urls in cpe_link_dict.items():
    cpe_cves[cpe_name] = []
    for cve_url in cve_urls:
    
        cve_link = title + cve_url
        
        start_time = time.time()  # Record the start time before making the request

        r_m = requests.get(cve_link)

        end_time = time.time()  # Record the end time after receiving the response
        # Update request statistics
        total_requests += 1
        request_time = end_time - start_time
        request_times.append(request_time)
        
        r_m.encoding = 'utf-8'
        
        cve_html = r_m.text
    
        html_1 = etree.HTML(cve_html)
        f = open("save_cve.html", "w")
        f.write(cve_html)
        f.close()
    
        
    
        html_0 = etree.parse('save_cve.html', etree.HTMLParser())
        
        # Turn the cves search page to next page
        pages = html_0.xpath("//nav[@data-testid='pagination-nav-container']/ul/li/a/@href")
        print("pages: ", pages)
        if pages == []:
            result = html_0.xpath("//*[@data-testid='vuln-results-table']/tbody/tr/th/strong/a/@href")
            if result != None:
                cpe_cves[cpe_name] += result
            continue
        pages_broswer_record = []
        for page_link in pages:
            if page_link not in pages_broswer_record:

                start_time = time.time()  # Record the start time before making the request

                page = requests.get(title+page_link)

                end_time = time.time()  # Record the end time after receiving the response
                # Update request statistics
                total_requests += 1
                request_time = end_time - start_time
                request_times.append(request_time)

                pages_broswer_record.append(page_link)
                
                page.encoding = 'utf-8'
        
                cve_html = page.text
            
                html_1 = etree.HTML(cve_html)
                f = open("save_cve_search_page.html", "w")
                f.write(cve_html)
                f.close()
                
                html_0 = etree.parse('save_cve_search_page.html', etree.HTMLParser())
                # Get the CVE links
                result = html_0.xpath("//*[@data-testid='vuln-results-table']/tbody/tr/th/strong/a/@href")
                
                cpe_cves[cpe_name] += result
        
print("cpe_cves: ", cpe_cves)
if cpe_cves:
    with open("./results/"+input_name+"_CPEs.json", 'w') as fp:
        json.dump(cpe_cves, fp, indent=4)


end_time_total = time.time()  # Record the end time
# Calculate the time taken
execution_time_total = end_time_total - start_time_total
print(f"The file took {execution_time_total:.2f} seconds to run.")

# Calculate the average time per request
average_request_time = sum(request_times) / total_requests

print(f"Total requests made: {total_requests}")
print(f"Average time per request: {average_request_time:.2f} seconds")
