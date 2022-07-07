import sys
from dotenv import load_dotenv
import hashlib
import os
import requests

# Class MD_Requestor( auth_key: string, filename: string )
class MD_Requester:
    def __init__(self, apikey, filename):
        self.apikey = apikey
        self.filename = filename
        self.URL = 'https://api.metadefender.com/v4'
        
        try:
            headers = { 'apikey': self.apikey }
            r = requests.get(f'{self.URL}/apikey/', headers=headers)
            r.raise_for_status()
        except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
            print("Error: Bad API key")
            exit(e)

    # hash_lookup() -> bool
    def hash_lookup(self):
        sha2hash = hashlib.sha256()

        # Calculate hash of the given file
        with open(self.filename, 'rb') as f: 
            for block in iter(lambda: f.read(1024), b''):
                sha2hash.update(block)

        headers = { 'apikey': self.apikey }
        try:
            r = requests.get(f'{self.URL}/hash/{sha2hash.hexdigest()}', headers=headers)
            r.raise_for_status()
        except requests.exceptions.HTTPError as e:
            print("Hash cannot be found")
            print(e)
            return False
        except requests.exceptions.RequestException as e:
            print(e)
            return False
        
        # Format and parse the response
        self._format(r.json())

        return True

    #scan() -> None
    def scan(self):
        # Post file to endpoint
        headers = {
            'apikey': self.apikey,
            'Content-Type': 'application/octet-stream',
            'filename': self.filename
        }

        try:
            r = requests.post(f'{self.URL}/file', headers=headers, data=open(self.filename, 'rb'))
            r.raise_for_status()
        except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
            print(e)
            exit(e)

        # Grab id from response
        data_id = r.json()['data_id']
        
        headers.clear()
        headers = {
            'apikey': self.apikey
        }

        progress_percentage = 0
        try:
            # Keep hitting endpoint until server sends back progress 100
            while(progress_percentage != 100):
                r = requests.get(f'{self.URL}/file/{data_id}', headers=headers)
                r.raise_for_status()
                progress_percentage = r.json()['scan_results']['progress_percentage']
        except (requests.exceptions.RequestException, requests.exceptions.HTTPError) as e:
            print(e)
            exit(e)

        # Format and parse the response
        self._format(r.json())
        

    def _format(self, r):
        overall_status = 'Clean' if r["scan_results"]["scan_all_result_a"] == 'No threat detected' else 'Threat detected'

        print(f'filename: {r["file_info"]["display_name"]}')
        print(f'overall_status: {overall_status}')
        for engine_name, res in r['scan_results']['scan_details'].items():
            threat_found = 'Clean' if res["threat_found"] == '' else res["threat_found"]
            scan_result = res["scan_result_i"]
            def_time = res["def_time"]

            print(f'engine: {engine_name}')
            print(f'threat_found: {threat_found}')
            print(f'scan_result: {scan_result}')
            print(f'def_time: {def_time}')


if __name__ == '__main__':
    if len(sys.argv) != 2: 
        print('COMMAND USAGE: python3 scan.py [FILENAME]')
        exit()

    # Get the API key from environment variables
    load_dotenv()
    API_AUTH = os.environ.get("DT_API_KEY")
    
    # Instantiate an MD_Requester object
    requester = MD_Requester(API_AUTH, sys.argv[1])

    # If SHA256 file hash is not found, then post and scan the file
    if(not requester.hash_lookup()):
        requester.scan()
        

    

