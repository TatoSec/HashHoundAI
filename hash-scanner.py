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
if 'error' in parsed_data:
   print("HashHound-AI:"),'\n', print("As a Cyber Security Assistant I am constantly leanrning, but I couldn't find anything matching this across the world wide web..")
   exit()
else:

  type_description = parsed_data
  if 'type_description' in parsed_data['data']['attributes']:
    type_description = parsed_data['data']['attributes']['type_description']
    
  elif 'type_description' not in parsed_data['data']['attributes']:
    type_description = 'No Description'

  classification = parsed_data
  if 'popular_threat_classification' in parsed_data['data']['attributes']:
      classification = parsed_data['data']['attributes']['popular_threat_classification']['suggested_threat_label']

  elif 'popular_threat_classification' not in parsed_data['data']['attributes']:
    classification = "no file classification"

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


# # Enumerate Total Analysis
# print(f"AV-Analysis: {categories, engine_names, result}")



# OpenAI Integration
openai.api_key = openai_key

if classification == "No Description":
  completion = openai.ChatCompletion.create(
    model="gpt-3.5-turbo",
    messages=[
      {"role": "system", "content": "Your name is HashHoundAI you are a helpful cybersecurity assistant that knows everthing related to files and hashes"},
      {"role": "user", "content": f"determine weather the hash is malicious or not and Give an in depth explanation about the hash provided and what it does given this data:{categories,engine_names,result}"}
    ]
  )

else:
   
  completion = openai.ChatCompletion.create(
    model="gpt-3.5-turbo",
    messages=[
      {"role": "system", "content": "Your name is HashHoundAI you are a helpful cybersecurity assistant that knows everthing related to files and hashes"},
      {"role": "user", "content": f"Go inn depth about what this does, Determine wether this is malicious or not based on the following data:{classification,type_description,aliases,categories,engine_names,result}. give steps for remediation if this file is within the environment"},
    ]
  )



def hash_scan ():
  print(f"Type: {type_description}")
  print(f"classification: {classification}")
  print(f"File Size: {file_size} mb")
  print(f"Submissions: {times_submitted}")
  print(f"Aliases: {aliases}")
  print("HashHound-AI:"),'\n', print(completion.choices[0].message.content)


hash_scan()