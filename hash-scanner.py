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

hash = input("Enter File Hash:")
url = f"https://www.virustotal.com/api/v3/files/{hash}"


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



# # Enumerate Total Analysis
# print(f"AV-Analysis: {categories, engine_names, result}")



# OpenAI Integration
openai.api_key = openai_key

completion = openai.ChatCompletion.create(
  model="gpt-3.5-turbo",
  messages=[
    {"role": "system", "content": "Your name is HashHoundAI you are a helpful cybersecurity assistant that knows everthing related to files and hashes"},
    {"role": "user", "content": f"Go in depth about this hash and what an attacker cna achieve wiht this, can you also organize last_analysis_results such as egnine:status:name{hash,type_description,aliases,last_analysis_results}"},
    {"role": "user", "content": "if the file is malicioustell me how to remediate it if its already in my system"}
  ]
)



def hash_scan ():
  print(f"Type: {type_description}")
  print(f"classification: {classification}")
  print(f"File Size: {file_size}mb")
  print(f"Submissions: {times_submitted}")
  print(f"Aliases: {aliases}")
  print("HashHound-AI:"),'\n', print(completion.choices[0].message.content)


hash_scan()





