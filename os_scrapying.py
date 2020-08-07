from bs4 import BeautifulSoup
import requests,csv
f=open("os_list.txt","r")
cve_list=f.readlines()
cve_data=[]
for i in range(len(cve_list)):
    cve_list[i]=cve_list[i].rstrip()
count=1
for cve_id in cve_list:
    temp_cve_data=[]
    escape_sequence=['\n','\t']
    url="https://www.cvedetails.com/cve/"+cve_id
    page=requests.get(url)
    soup = BeautifulSoup(page.content, 'html.parser')
    try:
        cvss_soup=soup
        cvss_soup.find_all('meta')
        cvss_soup=cvss_soup.find_all('meta')
        cvss_score='NA'
        for i in cvss_soup:
            content=i['content']
            if('CVSS' in content):
                index=content.find("CVSS")
                cvss_score=content[index+5:index+8]
                if(cvss_score[len(cvss_score)-1]=='.'):
                    cvss_score+='0'
                break
    except:
        cvss_score="NA"
    try:
        soup_cve_description=soup.find_all(class_="cvedetailssummary")
        cve_description=soup_cve_description[0].text
        cve_des_list=cve_description.split('.')
        cve_des_list.pop()
        cve_description=""
        for i in cve_des_list:
            cve_description+=i
    except:
        cve_description="NA"
    temp_cve_data.append(cve_id)
    temp_cve_data.append(cvss_score)
    for esc_seq in escape_sequence:
        cve_description=cve_description.replace(esc_seq,"")
    temp_cve_data.append(cve_description)
    try:
        table=soup.find(class_="listtable")
        table_list=table.find_all('tr')
        product_version_details=""
        for i in table_list:
            try:
                j=i.find_all('td')
                product="Product :"+ j[3].text.rstrip()+" "
                version="Version :"+ j[4].text.rstrip()+" "
                product_version_details+=product+version
                for esc_seq in escape_sequence:
                    product_version_details=product_version_details.replace(esc_seq,"")
            except:
                pass
    except:
        product_version_details="NA"
    temp_cve_data.append(product_version_details)
    cve_data.append(temp_cve_data)
    print(count)
    count+=1
with open('Operating_System_CVE_Details.csv',"a",newline="")as f:
    data = csv.writer(f)
    data.writerows(cve_data)
