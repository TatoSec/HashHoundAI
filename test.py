import vt
import os
import openai
import requests
import json
from api_key import virus_total_key
from api_key import openai_key

def test ():
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
    print(response.text)


test()