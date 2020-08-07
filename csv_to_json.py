import pandas as pd
import json
df=pd.read_csv("vendor_cve.csv")
#print(list(df.columns.values))
df_vendors=df['Vendors'].drop_duplicates()
vendors=df_vendors.values.tolist()
json_dict={}
count=0
for i in vendors:
    json_dict[i]=[]
count=0
for index,row in df.iterrows():
    descrip=row['Description']
    descrip=descrip.replace('"',"")
    string='ss\\n\\t'+'{"CVE":'+'"'+row['CVE-ID']+'"'+","
    string+='\\n\\t'+'"Description":'+'"'+descrip+'"'+","
    string+='\\n\\t'+'"CVSS":'+'"'+str(row['CVSS'])+'"'+"}"+"qwe"
    json_dict[row['Vendors']].append(string)
    count+=1;

json = json.dumps(json_dict)
f = open("dict.json","w")
f.write(json)
f.close()