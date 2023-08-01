# import re
# import requests

# def compareVersions(ver1, ver2):
#     ver1Segmente = ver1.split('.')
#     ver2Segmente = ver2.split('.')
    
#     whosBigger = max(len(ver1Segmente), len(ver2Segmente))
    
#     for i in range(whosBigger):
#         ver1Segment = int(ver1Segmente[i]) if i < len(ver1Segmente) else 0
#         ver2Segment = int(ver2Segmente[i]) if i < len(ver2Segmente) else 0
        
#         if ver1Segment < ver2Segment:
#             return -1
#         elif ver1Segment > ver2Segment:
#             return 1
        
#     return 0

# wpAPIResponse = requests.get(f'https://www.wpvulnerability.net/plugin/revslider/')
            
# wpAPIResponse = wpAPIResponse.json()
# wpAPIResponse = wpAPIResponse['data']

# if wpAPIResponse['vulnerability'] != None:
#     print("[*] Finding vulnerabilities for your version..")
    
#     vulnsFound = 0
#     for vuln in range(0, len(wpAPIResponse['vulnerability'])):
        
#         cevaString = wpAPIResponse['vulnerability'][vuln]['source'][0]['id'] + ": " + wpAPIResponse['vulnerability'][vuln]['source'][0]['description']
#         print(cevaString)


# content = requests.get('https://ecomedbt.ro/feed')

# for line in content.text.splitlines():
#     if line.find('<generator>') != -1:
#         pass
        
        

# with open('filename.txt') as f:
#     # Read all the lines into a list
#     lines = f.readlines()

# # Choose a random line from the list
# random_line = random.choice(lines)
    
    
# print(compareVersions('1.3.2', '1.2.3.4'))

from markdownmaker.document import Document
from markdownmaker.markdownmaker import *

doc = Document() 
doc.add(Paragraph("test"))
print(doc.write())