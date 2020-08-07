from bs4 import BeautifulSoup
import requests,csv
url="https://www.cvedetails.com/vulnerability-list.php?vendor_id=26&product_id=17153&version_id=&page=17&hasexp=0&opdos=0&opec=0&opov=0&opcsrf=0&opgpriv=0&opsqli=0&opxss=0&opdirt=0&opmemc=0&ophttprs=0&opbyp=0&opfileinc=0&opginf=0&cvssscoremin=0&cvssscoremax=0&year=0&month=0&cweid=0&order=3&trc=1283&sha=47d29bad4e41fa72927e93dbd6b6e2cbeefa4e07"
page=requests.get(url)
soup = BeautifulSoup(page.content, 'html.parser')
soup=soup.find(id="searchresults")
soup=soup.find_all(class_="srrowns")
cve_list=[]
for i in soup:
    i=i.find_all('a')
    i=i[1]
    cve_list.append(i.text)
