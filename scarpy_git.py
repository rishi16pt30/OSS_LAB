from bs4 import BeautifulSoup
import requests,csv
count=0
cve_write_data=[]
count=0
with open('2016-2020.csv','rt')as f:
    data = csv.reader(f)
    for row in data:
        try:
            count+=1
            cve_id=row[0]
            cve_id_url="https://www.cvedetails.com/cve/"+cve_id
            page=requests.get(cve_id_url)
            soup = BeautifulSoup(page.content, 'html.parser')
            soup.find_all('meta')
            soup=soup.find_all('meta')
            cvss_score='NA'
            for i in soup:
                content=i['content']
                if('CVSS' in content):
                    index=content.find("CVSS")
                    cvss_score=content[index+5:index+8]
                    if(cvss_score[len(cvss_score)-1]=='.'):
                        cvss_score+='0'
                    break
            row[2]=str(cvss_score)
            cve_write_data.append(row)
        except:
            print("Err Occured")
        print(count)  
with open('2010-2015_CVE_DETAILS.csv',"a",newline="")as f:
    data = csv.writer(f)
    data.writerows(cve_write_data)
################################################################
with open('2016-2020.csv','rt')as f:
    data = csv.reader(f)
    for row in data:
        try:
            count+=1
            cve_id=row[0]
            cve_id_url="https://www.cvedetails.com/cve/"+cve_id
            page=requests.get(cve_id_url)
            soup = BeautifulSoup(page.content, 'html.parser')
            soup.find_all('meta')
            soup=soup.find_all('meta')
            cvss_score='NA'
            for i in soup:
                content=i['content']
                if('CVSS' in content):
                    index=content.find("CVSS")
                    cvss_score=content[index+5:index+8]
                    if(cvss_score[len(cvss_score)-1]=='.'):
                        cvss_score+='0'
                    break
            row[2]=str(cvss_score)
            cve_write_data.append(row)
        except:
            print("Err Occured")
        print(count)  
with open('2010-2015_CVE_DETAILS.csv',"a",newline="")as f:
    data = csv.writer(f)
    data.writerows(cve_write_data)