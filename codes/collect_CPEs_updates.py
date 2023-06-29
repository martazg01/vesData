import scrapy, html

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

input_name = input()

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

r = requests.get(url)

r.encoding = 'utf-8'

html_text = r.text



soup = BeautifulSoup(html_text, "lxml")

search_box = soup.find(class_='SearchTextBox')

search_url = 'https://nvd.nist.gov/products/cpe/search/results?namingFormat=2.3' + '&keyword=' + CPE_name

'''
formdata = {'type': 'text',
            'keywords': "Amazon Echo"}
'''

r_r = requests.get(search_url)

r_r.encoding = 'utf-8'

r_html = r_r.text


f = open("save_cpe_search_page.html", "w")
f.write(r_html)
f.close()

html_cpe_search = etree.parse('save_cpe_search_page.html', etree.HTMLParser())

#maintable = html_0.xpath("//table[@id='maintable']//table[@class='listtable']//tr/td/a")
#print("maintable: ", maintable)
pages_url = html_cpe_search.xpath("//div[@class='searchResults']//ul[@class='pagination']/li/a")
cpe_link_dict = {}
for page in pages_url:
    href = page.xpath("@href")

    print(href)
    #nt("title", check.xpath("@title"))

    r_m = requests.get(title+href[0])

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
        
        r_m = requests.get(cve_link)
        
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
                page = requests.get(title+page_link)
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
