import scrapy, html
import sys

from scrapy.crawler import CrawlerProcess
#from item_cve import CveItem 
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

from bs4 import BeautifulSoup
from lxml import html
import requests
import time
import os

cve_map = open('CVE_edb_map.json', encoding='utf-8')
map = json.load(cve_map)

#running file individually
#input_name = input()

# taking input from "automated_vesData.py"
input_name = sys.argv[1]

judge_file_exist = os.path.exists("./results/"+input_name+'_data.json')
if judge_file_exist:
    cve_store = open("./results/"+input_name+'_data.json', encoding='utf-8')
    data = json.load(cve_store)
else:
    print("Not exist such file!")
    exit(1)
new_dct = {"ves":{}}
new_dct["ves"]["ves:product"] = {}
new_dct["ves"]["ves:product"]['product'] = input_name
new_dct["ves"]["ves:product"]['manufacturer'] = input_name.split(" ")[0]
new_dct["ves"]["ves:product"]['models'] = {}
name_record = []
for cve in data["ves"]["ves:vulnerability"]: 
    effected_product_list = data["ves"]["ves:vulnerability"][cve]["basic-info"]["affected-product-versions"]
    for _, p_dct in effected_product_list.items():
        effected_product_name = p_dct["CPE-uri"].split("_")
        if effected_product_name == []:
            continue
        name_lst = effected_product_name[0].split(":")
        # if name_lst[3] != "hp":
        #     continue

        if len(name_lst) == 4:
            name = name_lst[3]
        else:
            name = name_lst[3] + "_" + name_lst[4]
        '''
        if len(effected_product_name) < 2:
            name = effected_product_name[0]
        else:
            name = effected_product_name[0] + effected_product_name[1]
        '''
        if name not in name_record:
            dct = {}
            name_record.append(name)
            '''
            dct["vd:manufacture"] = p_dct["cpe23Uri"].split(":")[3]
            dct["vd:vulnerbility"] = {}
            dct["vd:vulnerbility"][cve] = data["vd"]["vd:vulnerbility"][cve]
            dct["vd:exploit"] = {}
            dct["vd:solution"] = {}
            '''
            #dct["manufacture"] = p_dct["cpe23Uri"].split(":")[3]
            #dct["models"] = {}
            dct["vulnerability"] = [cve]
            if cve in map.keys():
                dct["exploit"] = []
                for i in map[cve]:
                    dct["exploit"].append(i)
            new_dct["ves"]["ves:product"]['models'][name] = dct
        else:
            if cve not in new_dct["ves"]["ves:product"]['models'][name]["vulnerability"]:
                new_dct["ves"]["ves:product"]['models'][name]["vulnerability"].append(cve)
            if cve in map.keys():
                if "exploit" not in new_dct["ves"]["ves:product"]['models'][name]:
                    new_dct["ves"]["ves:product"]['models'][name]["exploit"] = []
                for i in map[cve]:
                    if i not in new_dct["ves"]["ves:product"]['models'][name]["exploit"]:
                        new_dct["ves"]["ves:product"]['models'][name]["exploit"].append(i)
                    #print("exploit: ", data["vd"]["vd:exploit"][map[cve]])


new_dct["ves"]["ves:vulnerability"] = data["ves"]["ves:vulnerability"]
new_dct["ves"]["ves:exploit"] = data["ves"]["ves:exploit"]
new_dct["ves"]["ves:solution"] = data["ves"]["ves:solution"]
with open("./results/"+input_name+'_ves.json', 'w') as fp:
    json.dump(new_dct, fp, indent=4)