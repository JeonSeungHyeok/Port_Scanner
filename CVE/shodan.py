from VERSION.service_version import *
from bs4 import BeautifulSoup
import requests
import json
import re

class shodan_api:
    def __init__(self,ip,port,timeout,maxTries):
        self.ip=ip
        self.port=port
        self.timeout=timeout
        self.maxTries=maxTries
        self.result1=''
        self.result2=''
        self.product=''
        self.banner=''
        self.ver = ''
        self.cpe = None
        self.cve = None

    def shodan_api_cpe(self):
        baseUrl = 'https://cvedb.shodan.io/cpes'
        query = {'product':self.product}
        response = requests.get(baseUrl,params=query)
        return self.parse_cpe(response)

    def parse_cpe(self,response):
        cpes = [v for v in json.loads(response.text).values()][0]
        for cpe in cpes:
            if self.ver in cpe:
                self.cpe=cpe
                break
        if self.cpe==None:
            self.nist_cpe(self.product,self.ver)
        return self.shodan_api_cve()

    def nist_cpe(self, app:str, ver:str, form=2.3) -> None:
        vendor = 'https://nvd.nist.gov/products/cpe/search/results'
        query = {'namingFormat':form,'keyword':f'{app} {ver}'}
        response = requests.get(vendor,params=query)
        soup = BeautifulSoup(response.text, 'html.parser')
        cpeLinks = soup.find_all('a', style='text-decoration:none')
        for link in cpeLinks:
            cpe = link.text.strip()
            if cpe.startswith('cpe:'):
                self.cpe = cpe
        
#    def nist_cve_result(self):
#        baseUrl = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
#        query = {'cpeName':self.cpe}
#        response = requests.get(baseUrl,params=query)
#        pprint.pprint(response.text,indent=4, depth=4)

    def shodan_api_cve(self):
        baseUrl = 'https://cvedb.shodan.io/cves'
        if self.cpe:
            query = {'cpe23':self.cpe}
            response = requests.get(baseUrl,params=query)
            return self.parse_shodan_cve_id(response)
        else:
            return None

    def parse_shodan_cve_id(self, response):
        try:
            data = json.loads(response.text)
            if 'cves' in data:
                cves = data['cves']
            else:
                print("No 'cves' key found")
                return []
            result = []
            for item in cves:
                cve_id = item.get('cve_id')
                if cve_id:
                    result.append(cve_id)
                else:
                    pass
            result.reverse()
            return result
        except Exception as e:
            return []

    def extract_version(self):
        try:
            match = re.search(r'\d+(\.\d+)+', self.banner)
            if match:
                return match.group(0)
        except TypeError as e:
            pass
        return ''

    def process(self):
        self.result1, self.result2, self.product, self.banner = scan_service_version(self.ip,self.port,self.timeout,self.maxTries)
        self.ver = self.extract_version()
        return self.shodan_api_cpe()