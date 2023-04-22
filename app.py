import vt 
from api_key import virus_total_key

client = vt.Client(virus_total_key)



# URL SCANNER
url_id = vt.url_id("http://google.com")
url = client.get_object("/urls/{}", url_id)

url = client.get_object("/urls/{}".format(url_id))

#print(url.last_analysis_stats)  #print function allows us to enumerate results


