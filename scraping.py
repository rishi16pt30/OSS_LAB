import requests
page=requests.get("https://www.cvedetails.com/cve/CVE-2018-13605")
page
page.content
import bs4
from bs4 import BeautifulSoup
soup = BeautifulSoup(page.content, 'html.parser')
soup.find_all('meta')
k=soup.find_all('meta')
for i in k:
    content=i['content']
    if('CVSS' in content):
        index=content.find("CVSS")
        print(content[index:index+8])