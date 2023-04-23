import vt
import os
import openai
import requests
from api_key import virus_total_key
from api_key import openai_key


# Activating API 
client = vt.Client(virus_total_key)

# Hash Analysis
url = "https://www.virustotal.com/api/v3/files/db3f663417baec4d8da89267a4a27df5"


headers = {
    "accept": "application/json",
    "x-apikey": virus_total_key
}

response = requests.get(url, headers=headers)

#print(response.text)
