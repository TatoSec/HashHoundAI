import vt
from api_key import vt_key

client = vt.client(vt_key)

file = client.get_object(r'C:\Users\Ivan Test\Downloads\Audit Log Baseline Data [ThreatLocker Staff].xlsx')

file.size

file.sha256