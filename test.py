import requests
import json
import openai
import os
import vt
from api_key import openai_key, virus_total_key

# Set up the VirusTotal API endpoint and API key
VT_API_ENDPOINT = 'https://www.virustotal.com/vtapi/v2/file/report'
VT_API_KEY = virus_total_key

# Set up the ChatGPT 3.5 Turbo API endpoint and API key
CGPT_API_ENDPOINT = 'https://api.openai.com/v1/engine/turbo-davinci-002'
CGPT_API_KEY = openai_key

# Set up the file to be scanned
file_path = '/Users/Ivan Test/Desktop/Trigger Testing/AmsiTrigger_x64.exe'

# Submit the file for scanning to VirusTotal API
with open(file_path, 'rb') as file:
    response = requests.post(VT_API_ENDPOINT, params={'apikey': VT_API_KEY}, files={'file': file})

# Parse the VirusTotal API response
if response.status_code == 200:
    report = json.loads(response.text)
    # Extract relevant information from the report
    file_name = report['resource']
    file_type = report['type_description']
    file_size = report['size']
    file_sha256 = report['sha256']
else:
    print(f"Error: {response.status_code} - {response.reason}")
    file_name = ''
    file_type = ''
    file_size = ''
    file_sha256 = ''

# Use ChatGPT 3.5 Turbo API to generate summaries and recommendations
prompt = f"Please summarize and provide recommendations for file {file_name}."
model_input = {
    "prompt": prompt,
    "temperature": 0.5,
    "max_tokens": 100,
    "stop": "\n"
}
headers = {"Authorization": f"Bearer {CGPT_API_KEY}"}
response = requests.post(CGPT_API_ENDPOINT + "/completions", json=model_input, headers=headers)

# Parse the ChatGPT 3.5 Turbo API response
if response.status_code == 200:
    chatgpt_summary = response.json()['choices'][0]['text']
else:
    print(f"Error: {response.status_code} - {response.reason}")
    chatgpt_summary = ''

# Output the results
print(f"File Name: {file_name}")
print(f"File Type: {file_type}")
print(f"File Size: {file_size}")
print(f"File SHA256: {file_sha256}")
print(f"Summary: {chatgpt_summary}")