f=open("vendorlist.txt","r")
vendor_list=f.readlines()

for i in range(len(vendor_list)):
    if(i!=len(vendor_list)-1):
        vendor_list[i]=vendor_list[i][:-1]
vendor_list.append("internet explorer")
vendor_list.append("chrome")
vendor_list.append("firefox")
vendor_list.append("edge")
for i in range(len(vendor_list)):
    vendor_list[i]=vendor_list[i].lower()
count=0
tot_count=0
total_data=[]
data=[]
import pandas as pd
import csv
with open ("cvedata_cvss//CVE_DETAILS.csv","r") as csvfile:
    csvreader = csv.reader(csvfile)
    for row in csvreader:
        total_data.append(row)
total_data.pop(0)
total_data.pop(0)
vendor=[]
for i in total_data:
    try:
        description=i[1].lower()
        for j in vendor_list:
            if j in description:
                temp=i
                data.append(i)
                vendor.append(j)
    except:
        pass
df = pd.DataFrame(data, columns = ['CVE-ID', 'Description','CVSS'])
df['Vendors']=vendor

count=0
df.to_csv('vendor_cve.csv',index=False)

