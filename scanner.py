import vt
import os
import openai
import requests
import json
from api_key import virus_total_key
from api_key import openai_key


# Activating API 
client = vt.Client(virus_total_key)

# Get a Report by Hash
url = "https://www.virustotal.com/api/v3/files/db3f663417baec4d8da89267a4a27df5"


headers = {
    "accept": "application/json",
    "x-apikey": virus_total_key
}

response = requests.get(url, headers=headers)

# Extracting only the Data I need
data = response.text

parsed_data = json.loads(data)

#Subheaders in JSON File
type_description = parsed_data['data']['attributes']['type_description']
classification = parsed_data['data']['attributes']['popular_threat_classification']['suggested_threat_label']
times_submitted = parsed_data['data']['attributes']['times_submitted']
file_size = parsed_data['data']['attributes']["size"]
last_analysis_results = parsed_data['data']['attributes']['last_analysis_results']
aliases = parsed_data['data']['attributes']['names']

categories = []
engine_names = []
result = []
for engine in last_analysis_results.values():
    categories.append(engine['category'])
    engine_names.append(engine['engine_name'])
    result.append(engine['result'])



#print(response.text)
print(f"Type: {type_description}")
print(f"classification: {classification}")
print(f"File Size: {file_size}mb")
print(f"Submissions: {times_submitted}")
print(f"Aliases: {aliases}")


# Enumerate Total Analysis
#print(f"AV-Analysis: {categories, engine_names, result}")







