import json
import re
from os import path
def get_contents(filename):
    with open(filename) as f:
        return f.read()
def put_contents(filename, data, base_dir = None):
    if base_dir != None:
        filename = path.join(base_dir, filename)
    with open(filename, 'w') as f:
        f.write(data)
def json_decode(data):
    data = re.sub("#(/\*([^*]|[\r\n]|(\*+([^*/]|[\r\n])))*\*+/)|([\s\t]//.*)|(^//.*)#","",data)
    return json.loads(data)