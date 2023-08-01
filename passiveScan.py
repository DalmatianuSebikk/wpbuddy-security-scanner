from markdownmaker.document import Document
from markdownmaker.markdownmaker import *

import requests
from bs4 import BeautifulSoup # for analyzing html 
import re
import time


retries = 3 # in cazul in care e posibil sa dea un error 500 website ul
delayRetry = 3 # stam un numar de secunde secunde

# PENTRU CREAREA FISIERULUI MARKDOWN
# doc = Document() 
# ---------------------------- passiveCoreVersionDiscovery ----------------------------

# 1. analizezi meta tag-ul si scoti de acolo versiunea de wordpress
# 2. daca nu exista meta tagul te uiti in pagina html a site-ului, atunci citesti pagina de readme.html / pagina de RSS
# 3. te mai poti uita si in style.css cum se termina
# alte modalitati sunt putin mai complicate fiindca necesita acces (we don t want that 4 now)

def passiveCoreVersionDiscovery(doc, websiteName):
    extractVersionPattern = re.compile(r'(\d+\.\d+\.\d+)|(\d+\.\d+)')
    
    for retry in range(retries):

        try:
            websiteRequest = requests.get(websiteName)

            if(websiteRequest.status_code >= 400):
                raise Exception(f'Error at requests.get({websiteName}); \n Status code: {websiteRequest.status_code}.\n')

            break
        except Exception as e:
            print(f'Connection failure. Error: {e}')
            # if(websiteRequest.status_code >= 400):
            #     print(f'Error at requests.get({websiteName}); \n Status code: {websiteRequest.status_code}.\n')
                
    with HeaderSubLevel(doc):
        doc.add(Header("WordPress Core Version discovery and vulnerabilities"))

    # intai verificam in pagina daca avem respectivul tag
    wordpressVersion = ''
    # punem pe soup
    soup = BeautifulSoup(websiteRequest.text, features="html.parser")
    metaGeneratorTag = soup.find("meta", attrs={'name': 'generator'}) # metaGeneratorTag['content']
    
    if 'WordPress' in metaGeneratorTag['content']:

        # found it
        wordpressVersion = metaGeneratorTag['content'].replace('WordPress ', '')

        doc.add(Paragraph(f"WordPress version was found in a {Bold('Meta tag')} in the homepage: {websiteName}"))
        # print(f'[*] Version of Wordpress: {wordpressVersion} ') # de aici dam call la API si vedem mai departe ce se intampla
        
    else:
        # ne uitam dupa linkurile de stylesheet
        
        for htmlLine in soup.find_all('link', href=True, id=True):
            # librarii comune de css care dau versiunea wordpressului, mai ramane de vazut oricum
            if htmlLine['id'] in ['cookie-notice-front-css', 'fancybox-css', 'wp-block-library-css', 'anythingSlider-css']:
                linkImport = htmlLine['href']
                print(f'[*] Wordpress version found in a css import: {linkImport}')
                # extragere pattern
                
                found = re.search(extractVersionPattern, htmlLine['href'])
                if found:
                    
                    wordpressVersion = found.group()
                    doc.add(Paragraph(f"WordPress version was found in a {Bold('css stylesheet link')} in the homepage: {websiteName}"))

                    
                break
            
        if wordpressVersion == '':
            # daca inca nu am gasit versiunea, atunci putem sa mai cautam si in rss, ultima metoda
            rssContent = requests.get(f'{websiteName}/feed')
            for line in rssContent.text.splitlines():
                if line.find('<generator>') != -1:
                    
                    found = re.search(extractVersionPattern, line)
                    if found:
                        wordpressVersion = found.group()
                        doc.add(Paragraph(f"WordPress version was found in the {Bold('RSS feed')} in the {Bold('meta <generator>')} tag: {websiteName}/feed."))
                    
                    if wordpressVersion != '':
                        break
                    
    if wordpressVersion == '':
        print('[!] Wordpress version could not be found.')
        doc.add(Paragraph("WordPress version could not be found using the given methods."))
    else:
        print(f'[*] Wordpress version found: {wordpressVersion}')
        doc.add(Paragraph(f"WordPress has the version {Bold(wordpressVersion)}"))
        findCVEForCore(doc, wordpressVersion)
        # upgrade pe mai tz sa analizezi si scripturile de js de unde sunt source-uite
        
# ---------------------------- passiveCoreVersionDiscovery ----------------------------
# functie ajutatoare pentru passiveCoreVersionDiscovery

def findCVEForCore(doc, wordpressVersion):
    extractVersionPattern = re.compile(r'(\d+\.\d+\.\d+)|(\d+\.\d+)')
    wordpressOriginalVersion = wordpressVersion
    if wordpressVersion != '':
        wordpressVersionTest = wordpressVersion.split('.')
        if len(wordpressVersionTest) >= 3:
            # imi e mai usor sa iau direct numar1.numar2, fiindca al 3lea numar reprezinta de fapt un hotfix si nu o vulnerabilitate anume. 
            # de aceea e posibil sa nu dea nimic API ul atunci cand fac request cu numar1.numar2.numar3
            wordpressVersion = wordpressVersionTest[0] + '.' + wordpressVersionTest[1]
        
        coreExploitResponse = requests.get(f'https://www.wpvulnerability.net/core/{wordpressVersion}/')
        
        coreExploitResponse = coreExploitResponse.json()['data']
        
        if coreExploitResponse['vulnerability'] != None:

            doc.add(Paragraph(f"Vulnerabilities were found for the current version of WordPress used on the website ({Bold(wordpressOriginalVersion)}):"))

            for vuln in range(0, len(coreExploitResponse['vulnerability'])):
                # trebuie sa masor frecventa descrierilor fiindca unele vulnerabilitati duc catre aceeasi chestie
                descriptionDictionaries = {}
                # trebuie sa mai verific si daca versiunea mea este mai mare, ca daca e mai mare atunci e patchuit


                dictionaryDesc = coreExploitResponse['vulnerability'][vuln]['source'][0]['description']
                vulnName = coreExploitResponse['vulnerability'][vuln]['source'][0]['name']

                found = re.search(extractVersionPattern, vulnName)
                if found:
                    versionFound = found.group()

                    if compareVersions(versionFound, wordpressOriginalVersion) < 0:
                        continue # pentru ca avem un wordpress cu versiune mai mare si e patchuit

                if dictionaryDesc in descriptionDictionaries:
                    continue
                
                if  dictionaryDesc not in descriptionDictionaries:
                    descriptionDictionaries[dictionaryDesc] = 1

                    doc.add(UnorderedList((
                            f"{Bold(vulnName)}: {dictionaryDesc}",))
                    )
                    # print(f''' 
                    #       [!] Vulnerability found: 
                    #         -   {vulnName}
                    #       ''')
                    
                    
            
            doc.add(Paragraph(Bold("It is recommended to update to the latest version of WordPress to fix these possible exploits.")))
            # print(f'---------------- It is recommended to update to the latest version of WordPress to fix these exploits. ----------------')
        
        else:
            doc.add(Paragraph("There are no WordPress vulnerabilities found for the current version used on the website."))
            print(f'[✓] No vulnerabilities found for your version of Wordpress. Hooray!')
            
# ---------------------------- passivePluginDiscovery (more features coming soon) ----------------------------

# 1. deschizi o pagina de wordpress pe respectivul website cu numele websiteName
# 2. preiei toate tagurile de link ce contin "wp-content/plugins"
#       - numele pluginului se va afla aici: "wp-content/plugins/[NUME PLUGIN AICI]/[child directory]"
#       - preiei numele pluginului si accesezi readme.txt de unde incerci sa iei versiunea pluginului
#       - mai departe folosesti un CVE API si incerci sa cauti o vulnerabilitate pentru pluginul respectiv

def passivePluginDiscovery(doc, websiteName, customPluginsPath):

    for retry in range(retries):

        try:
            websiteRequest = requests.get(websiteName)

            if(websiteRequest.status_code >= 400):
                raise Exception(f'Error at requests.get({websiteName}); \n Status code: {websiteRequest.status_code}.\n')

            break
        except Exception as e:
            print(f'Connection failure. Error: {e}')
            # if(websiteRequest.status_code >= 400):
            #     print(f'Error at requests.get({websiteName}); \n Status code: {websiteRequest.status_code}.\n')

        print(f'Retrying connection to {websiteName} in {delayRetry} seconds..')
        time.sleep(delayRetry)

    # websiteRequest = requests.get(websiteName)
    
    # if(websiteRequest.status_code >= 400):
    #     print(f'Error at requests.get({websiteName}); \n Status code: {websiteRequest.status_code}.\n')
        
    # else:
    with HeaderSubLevel(doc):
        doc.add(Header("WordPress Plugin discovery and vulnerabilities"))   

    pluginsList = []
    # iteram prin fiecare linie din html ul primit inapoi si pentru link si script 
    # scoatem tot ce contine wp-content/plugins:
    soup = BeautifulSoup(websiteRequest.text, features="html.parser")
    
    for htmlLine in soup.find_all('link', href=True):
        if 'wp-content/plugins' in htmlLine['href'] and 'wp-content/plugins/public/' not in htmlLine['href']:
            
            # stergem numele websiteului si ce urmeaza dupa numele pluginului
            htmlLine['href'] = htmlLine['href'].replace(websiteName + 'wp-content/plugins/', "")
            htmlLine['href'] = htmlLine['href'][0:htmlLine['href'].find('/')] 
            
            # adaugam intr-o lista pluginurile care nu exista deja
            if htmlLine['href']:

                # print(f'Am gasit pluginul ' + htmlLine['href'] + ' prin metoda cu link si wp-content/plugins')
                pluginsList.append(htmlLine['href'])
        
    # scoatem duplicatele 
    pluginsList = list(set(pluginsList))
    print("Plugins found:")
    print(pluginsList)

    doc.add(Paragraph(f"Here is the list with all of the plugins found by scanning (passive scan, watching for css links and watching for {Italic('wp-content/plugins')}):"))
    for plugin in pluginsList:
        doc.add(UnorderedList((
            f"{Bold(plugin)}",))
        )

    # adaugam lista custom de pluginuri
    manualScanPluginsList = []
    with open(customPluginsPath, 'r') as readCustomPlugins:
        manualScanPluginsList = [line.strip() for line in readCustomPlugins]

    doc.add(Paragraph(f'There were plugins added manually by the user of the scanner to be found and tested for vulnerabilities:'))

    for plugin in manualScanPluginsList:
        doc.add(UnorderedList((
            f"{Bold(plugin)}",))
        )

    pluginsList += manualScanPluginsList
    
    # facem din nou requests pentru fiecare plugin si incercam sa accesam readme.txt ul fiecaruia, astfel incat sa putem prelua versiunea pluginului:
    dictionaryOfPlugins = findReadme(doc, websiteName, pluginsList)
    
    # for key in dictionaryOfPlugins:
    #     print(f'{key} : {dictionaryOfPlugins[key]}')
        
    # cautam pe CVE si afisam ce gasim
    findCVEForPlugins(doc, dictionaryOfPlugins)
        
# ---------------------------- findReadMe ----------------------------
# Functie ajutatoare pentru passive scan.
# Folosesc regex si slicing pentru a cauta mai eficient in fisier. 

def findReadme(doc, websiteName, pluginsList):
    dictionaryOfPlugins = {}

    with HeaderSubLevel(doc):
        doc.add(Header(f"WordPress Plugins used on {websiteName}"))   
    
    for pluginName in pluginsList:
            # facem requestul:
            filesToSearch = ['readme.md', 'README.md', 'readme.txt', 'README.txt', 'release_log.html', 'changes.txt', 'index.php'] 
            # se mai poate modifica ulterior in functie de alte plugins
            
            gasit = 0
            for file in filesToSearch:
                
                requestPath = websiteName + f'/wp-content/plugins/{pluginName}/{file}' 
                # print(requestPath)
                # print(f'* Trying to find the readme file of the plugin: {requestPath}')
                
                websiteRequestPlugin = requests.get(requestPath)
                
                if(websiteRequestPlugin.status_code == 200):
                    gasit = 1
                    
                    if file not in ['release_log.html', 'changes.txt', 'index.php']:
                        
                        # folosesc un regex pentru a gasi patternul
                        # regexul urmator face un or intre patternurile "numar.numar.numar.numar", "numar.numar.numar", "numar.numar"
                        patternForVersion = re.compile(r'(\d+\.\d+\.\d+\.\d+)|(\d+\.\d+\.\d+)|(\d+\.\d+)')
                        
                        #extragem readme-ul
                        readmeContent = websiteRequestPlugin.text
                        readmeContent = readmeContent.lower()
                        
                        if 'changelog' in readmeContent:
                            
                            # patternForVersion =  re.compile(r'(\d+\.\d+)(\.\d+)?') prima incercare de regex
                            
                            
                            readmeContent = readmeContent[readmeContent.find('changelog'):]

                            found = re.search(patternForVersion, readmeContent)
                            if found:
                                pluginVersion = found.group()
                                # if found.group(2):
                                #     pluginVersion += found.group(2)
                                dictionaryOfPlugins[pluginName] = pluginVersion
                                doc.add(OrderedList((
                                    f"{Bold(pluginName)} has the version {Bold(pluginVersion)}",))
                                )
                                print(f'[OK] Plugin {pluginName} has the version {pluginVersion}')
                            else:
                                # mai putem incerca altfel de pattern
                                doc.add(OrderedList(
                                    (f"⚠️ {Bold(pluginName)}'s version cannot be found in /wp-content/plugins/{pluginName}/{Italic(file)}",)
                                    )
                                )
                                print(f'[!] Could not find {pluginName} version')
                                
                                
                        else: 
                            # atunci nu avem changelogs, deci sunt mai multe posibilitati aici:
                            # putem sa cautam de la jumatatea fisierului in jos in cazul in care avem features:
                            
                            if 'installation' in readmeContent:
                                readmeContent = readmeContent[readmeContent.find('installation'):]
                            
                            elif 'features' in readmeContent:
                                readmeContent = readmeContent[readmeContent.find('features'):]
                                
                            found = re.search(patternForVersion, readmeContent)
                            if found:
                                # l-am gasit si ii putem da output
                                pluginVersion = found.group()
                                # if found.group(2):
                                #     pluginVersion += found.group(2)
                                dictionaryOfPlugins[pluginName] = pluginVersion

                                doc.add(OrderedList((
                                    f"{Bold(pluginName)} has the version {Bold(pluginVersion)}",))
                                )
                                print(f'[✓] Plugin {pluginName} has the version {pluginVersion}')
                                
                            else:
                                # ?
                                doc.add(OrderedList((
                                    f"{Bold(pluginName)}'s README file version could not be found.",))
                                )
                                print(f'[!] Could not find {pluginName} version in the /wp-content/plugins/{pluginName}/{Italic(file)} file.')
                    
                    else:
                        
                        patternForVersion = re.compile(r'(\d+\.\d+\.\d+\.\d+)|(\d+\.\d+\.\d+)|(\d+\.\d+)')
                        
                        if file == 'changes.txt' or file == 'release_log.html':
                            # cautam ver sau version
                            readmeContent = websiteRequestPlugin.text
                            readmeContent = readmeContent.lower()
                            
                            if 'ver' in readmeContent:
                                readmeContent = readmeContent[readmeContent.find('ver'):]
                            
                            elif 'version' in readmeContent:
                                readmeContent = readmeContent[readmeContent.find('version'):]
                                
                            found = re.search(patternForVersion, readmeContent)
                            if found:
                                # l-am gasit si ii putem da output
                                pluginVersion = found.group()
                                # if found.group(2):
                                #     pluginVersion += found.group(2)
                                dictionaryOfPlugins[pluginName] = pluginVersion

                                doc.add(OrderedList((
                                    f"{Bold(pluginName)} has the version {Bold(pluginVersion)}",))
                                )
                                print(f'[OK] Plugin {pluginName} has the version {pluginVersion}')
                                
                            else:
                                # ? in development
                                doc.add(OrderedList((
                                    f"{Bold(pluginName)}'s version could not be found in the {Italic('changes.txt')} file.",))
                                )
                                print(f'[!] Could not find {pluginName} version in the changes.txt file.')
                        
                        else:
                            dictionaryOfPlugins[pluginName] = None
                            doc.add(OrderedList((
                                    f"{Bold(pluginName)}'s version could not be found because the version crawling for {Italic(file)} is not implemented yet. You can research on your own if you can access the file {Link(label='by going to this path', url=requestPath)}.",))
                                )
                            print(f'[!] Plugin version crawling for {file} is not implemented yet, but the file may be accesible by going to this path: {requestPath}')
                        
                    break
                
            
            if gasit == 0:
                doc.add(OrderedList((
                    f"❌ {Bold(pluginName)}'s version could not be found with the given methods.",))
                 )
                print(f'- For {pluginName} we could not find any versions.')
                dictionaryOfPlugins[pluginName] = None
                
    return dictionaryOfPlugins
        
# ---------------------------- findCVEForPlugins ----------------------------
# Functie ajutatoare pentru passive scan.
# Apeleaza API ul de la wpsysadmin si gaseste vulnerabilitatea pentru fiecare plugin din dictionaryOfPlugins
            
def findCVEForPlugins(doc, dictionaryOfPlugins):
    
    # o sa folosesc API-ul pus de vulnerability.wpsysadmin.com, este o posibilitate ca acesta sa nu gaseasca toate pluginurile 
    with HeaderSubLevel(doc):
        doc.add(Header("Plugin vulnerability analysis:"))

    for key in dictionaryOfPlugins:
        
        if dictionaryOfPlugins[key] != None:
            # facem request catre API si dupa modificam json-ul.
            wpAPIResponse = requests.get(f'https://www.wpvulnerability.net/plugin/{key}/')
            
            wpAPIResponse = wpAPIResponse.json()['data']
            
            if wpAPIResponse['vulnerability'] != None:
                print(f'[*] Finding vulnerabilities for your version of {key}')
                
                vulnsFound = 0
                try:
                    for vuln in range(0, len(wpAPIResponse['vulnerability'])):

                        # comparam operatorul:
                        if(wpAPIResponse['vulnerability'][vuln]['operator']['max_operator'] == 'lt'):

                            # comparam pentru a vedea daca e vulnerabil sau nu 
                            if(compareVersions(dictionaryOfPlugins[key], wpAPIResponse['vulnerability'][vuln]['operator']['max_version']) < 0):
                                # atunci versiunea este vulnerabila la [insert CVE Here]
                                # aici am modificat cu name in loc de id .
                                cveName = wpAPIResponse['vulnerability'][vuln]['source'][0]['name']
                                cveDescription = wpAPIResponse['vulnerability'][vuln]['source'][0]['description']
                                vulnsFound += 1

                                doc.add(UnorderedList((
                                    f"{Bold(key)} version {Bold(dictionaryOfPlugins[key])} -> {Bold(cveName)} : {Italic(cveDescription)}",))
                                )
                                print(f'''
                                      [!] Vulnerability found in plugin {key}:
                                        -   {cveName}
                                        -   {cveDescription}
                                        -   Your version of the plugin is: {dictionaryOfPlugins[key]}
                                      ''')   

                        elif(wpAPIResponse['vulnerability'][vuln]['operator']['max_operator'] == 'le'):

                            if(compareVersions(dictionaryOfPlugins[key], wpAPIResponse['vulnerability'][vuln]['operator']['max_version']) <= 0):
                                # atunci versiunea este vulnerabila la [insert CVE Here]
                                cveName = wpAPIResponse['vulnerability'][vuln]['source'][0]['name']
                                cveDescription = wpAPIResponse['vulnerability'][vuln]['source'][0]['description']
                                vulnsFound += 1

                                doc.add(UnorderedList((
                                    f"{Bold(key)} version {Bold(dictionaryOfPlugins[key])} -> {Bold(cveName)} : {Italic(cveDescription)}",))
                                )

                                print(f'''
                                      [!] Vulnerability found in plugin {key}:
                                        -   {cveName}
                                        -   {cveDescription}
                                        -   Your version of the plugin is: {dictionaryOfPlugins[key]}
                                      ''') 
                except IndexError as e:
                    leng = len(wpAPIResponse['vulnerability'])
                    print(f'{e.args} : vuln is {vuln} and length is {leng}')
                

                if not vulnsFound:
                    doc.add(UnorderedList((
                        f"{Bold(key)} version {Bold(dictionaryOfPlugins[key])}-> No vulnerabilities found for this version of the plugin ",))
                    )
                    print(f'[✓] No vulnerabilities found for this version of the plugin: {key}')
                            
            
            else:
                doc.add(UnorderedList((
                    f"{Bold(key)} -> No vulnerability found for this plugin on the base API ({Italic('vulnerability field is null')})",))
                )
                print(f'[✓] No vulnerability found for this plugin on the base API (vulnerability field is null): {key}')
                                          
# ---------------------------- compareVersions ----------------------------
# Functie ajutatoare pentru comparat diverse versiuni pentru pluginuri in cazul in care sunt diferite.

def compareVersions(ver1, ver2):
    ver1Segmente = ver1.split('.')
    ver2Segmente = ver2.split('.')
    
    whosBigger = max(len(ver1Segmente), len(ver2Segmente))
    
    for i in range(whosBigger):
        # de scris altfel aici
        ver1Segment = int(ver1Segmente[i]) if i < len(ver1Segmente) else 0
        ver2Segment = int(ver2Segmente[i]) if i < len(ver2Segmente) else 0
        
        if ver1Segment < ver2Segment:
            return -1
        elif ver1Segment > ver2Segment:
            return 1
        
    return 0                   

# ---------------------------- some other useful small functions for scanning ----------------------------
# 1. findReadmeHtml -> readme.html contine informatii despre software ul de wordpress si poate fi folosit pentru a cauta vulnerabilitati despre software.
def findReadmeHtml(doc, websiteName):
    readmeResponse = requests.get(f'{websiteName}readme.html')
    
    if readmeResponse.status_code >= 400:
        print('[!] Could not get the readme.html for this website.')
    else:
        print(f'[✓] readme.html file found: {websiteName}readme.html')

# 2. findRobots.txt -> de folos in cazul in care cineva nu indexeaza niste pagini in google.
def findRobotsTxt(doc, websiteName):

    with HeaderSubLevel(doc):
        doc.add(Header("Robots.txt content"))

    for retry in range(retries):

        try:
            readmeResponse = requests.get(f'{websiteName}robots.txt')
            if(readmeResponse.status_code >= 400):
                raise Exception(f'Error at requests.get({websiteName}); \n Status code: {readmeResponse.status_code}.\n')

            break
        except Exception as e:
            print(f'Connection failure. Error: {e}')

        print(f'Retrying connection to {websiteName} in {delayRetry} seconds..')
        time.sleep(delayRetry)
    
    if readmeResponse.status_code >= 400:
        doc.add(Paragraph("robots.txt file not found for this website."))
        print('[!] Could not get the robots.txt for this website.')
    else:
        doc.add(Paragraph(f"robots.txt file was found: {websiteName}robots.txt"))
        doc.add(CodeBlock(readmeResponse.text.strip()))
        print(f'[✓] robots.txt file found: {websiteName}robots.txt \nContent: {readmeResponse.text}')
       
# ---------------------------- checkForInterestingHeaders ----------------------------
# de obicei ignorat, fiindca nu s asa de useful.
# headerele pe care le caut pot fac site ul mai putin secure, fiindca pot permite anumite atacuri

def checkForInterestingHeaders(doc, websiteName):

    with HeaderSubLevel(doc):
        doc.add(Header("Headers that may be useful"))

    for retry in range(retries):

        try:
            websiteRequest = requests.get(websiteName)
            if(websiteRequest.status_code >= 400):
                raise Exception(f'Error at requests.get({websiteName}); \n Status code: {websiteRequest.status_code}.\n')

            break
        except Exception as e:
            print(f'Connection failure. Error: {e}')

        print(f'Retrying connection to {websiteName} in {delayRetry} seconds..')
        time.sleep(delayRetry)

    interestingHeaders = ['Server', 'X-Frame-Options', 'X-XSS-Protection', 'Strict-Transport-Security', 'Content-Security-Policy']
    
    # analizam headerele din response
    # print(websiteResponse.headers)
    
    for header in interestingHeaders:
        try:
            if websiteRequest.headers[header]:
                doc.add(Paragraph(f"{Bold(header)} : {Italic(websiteRequest.headers[header])}"))
                print(f'[✓] Interesting header found:\n {header} : {websiteRequest.headers[header]}')
        except:
            continue
    
def passiveThemeDiscovery(doc, websiteName):

    for retry in range(retries):

        try:
            websiteResponse = requests.get(websiteName)

            if(websiteResponse.status_code >= 400):
                raise Exception(f'Error at requests.get({websiteName}); \n Status code: {websiteResponse.status_code}.\n')

            break
        except Exception as e:
            print(f'Connection failure. Error: {e}')
            # if(websiteRequest.status_code >= 400):
            #     print(f'Error at requests.get({websiteName}); \n Status code: {websiteRequest.status_code}.\n')

        print(f'Retrying connection to {websiteName} in {delayRetry} seconds..')
        time.sleep(delayRetry)

    with HeaderSubLevel(doc):
        doc.add(Header("WordPress Theme discovery and vulnerabilities"))   

    extractVersionPattern = re.compile(r'(\d+\.\d+\.\d+)|(\d+\.\d+)')
    
    
    soup = BeautifulSoup(websiteResponse.text, features="html.parser")
    themeName = ''
    print('Starting looking for the theme')
    for htmlLine in soup.find_all('link', href=True):
        if 'wp-content/themes' in htmlLine['href']:
            
            htmlLine['href'] = htmlLine['href'].replace(websiteName + 'wp-content/themes/', "")
            htmlLine['href'] = htmlLine['href'][0:htmlLine['href'].find('/')] 
            
            themeName = htmlLine['href']
            doc.add(Paragraph(f'WordPress theme was found in a {Bold("link")} tag. The path to the theme is: wp-content/themes/{themeName}'))
            break
    
    if themeName == '':
        for scriptLine in soup.find_all('script', src=True):
            if 'wp-content/themes' in scriptLine['src']:
                scriptLine['src'] = scriptLine['src'].replace(websiteName + 'wp-content/themes/', "")
                scriptLine['src'] = scriptLine['src'][0:scriptLine['src'].find('/')] 
                
                themeName = scriptLine['src']
                doc.add(Paragraph(f'WordPress theme was found in a {Bold("script")} tag. The path to the theme is: wp-content/themes/{themeName}'))
                break
                
    if themeName != '':
        print(f'[✓] Wordpress theme found: {themeName}')
        
        filesToSearch = ['readme.md', 'README.md', 'readme.txt', 'README.txt', 'release_log.html', 'changes.txt', 'index.php'] 

        themeVersion = ''
        # verificam acum versiunea in readme
        for file in filesToSearch:
            requestPath = websiteName + f'/wp-content/themes/{themeName}/{file}' 
            websiteThemeResponse = requests.get(requestPath)
            
            if(websiteThemeResponse.status_code == 200):
                readmeContent = websiteThemeResponse.text
                readmeContent = readmeContent.lower()

                if 'changelog' in readmeContent:

                    # patternForVersion =  re.compile(r'(\d+\.\d+)(\.\d+)?') prima incercare de regex

                    readmeContent = readmeContent[readmeContent.find('changelog'):]
                    found = re.search(extractVersionPattern, readmeContent)
                    if found:
                        themeVersion = found.group()
                        # if found.group(2):
                        #     pluginVersion += found.group(2)
                        doc.add(Paragraph(f'Version of the theme {Bold(themeName)} was found: {Bold(themeVersion)}'))
                        print(f'[OK] Theme {themeName} has the version {themeVersion}')
                        findCVEForTheme(doc, themeName, themeVersion)
                        break
                    else:
                        # mai putem incerca altfel de pattern
                        doc.add(Paragraph(f'Version of the theme was not found.'))
                        print(f'[!] Could not find {themeName} version')


                else: 
                    # atunci nu avem changelogs, deci sunt mai multe posibilitati aici:
                    # putem sa cautam de la jumatatea fisierului in jos in cazul in care avem features:
                    if 'version' in readmeContent.lower():
                        readmeContent = readmeContent.lower()
                        readmeContent = readmeContent[readmeContent.find('version'):]
                        
                    elif 'installation' in readmeContent:
                        readmeContent = readmeContent[readmeContent.find('installation'):]

                    elif 'features' in readmeContent:
                        readmeContent = readmeContent[readmeContent.find('features'):]

                    found = re.search(extractVersionPattern, readmeContent)
                    if found:
                        # l-am gasit si ii putem da output
                        themeVersion = found.group()
                        # if found.group(2):
                        #     pluginVersion += found.group(2)
                        print(f'[✓] Theme {themeName} has the version {themeVersion}')
                        doc.add(f'Version of the theme {Bold(themeName)} was found: {Bold(themeVersion)}')
                        findCVEForTheme(doc, themeName, themeVersion)
                        break

                    else:
                        # ?
                        print(f'[!] Could not find {themeName} version in the README file.')


def findCVEForTheme(doc, themeName, themeVersion):
    themeResponse = requests.get(f'https://www.wpvulnerability.net/theme/{themeName}').json()

    themeResponse = themeResponse['data']

    with HeaderSubLevel(doc):
        doc.add(Header("Theme vulnerability analysis:"))

    if not themeResponse['vulnerability']:
        # nu am gasit nimic pentru tema asta
        doc.add(Paragraph("No vulnerabilities found for this theme"))
        print('[!] No vulnerabilities found for this theme.')


    else:
        vulnsFound = 0

        for vuln in range(0, len(themeResponse['vulnerability'])):

            if(themeResponse['vulnerability'][vuln]['operator']['max_operator'] == 'lt'):
                if(compareVersions(themeVersion, themeResponse['vulnerability'][vuln]['operator']['max_version']) < 0):

                    cveName = themeResponse['vulnerability'][vuln]['source'][0]['name']
                    cveDescription = themeResponse['vulnerability'][vuln]['source'][0]['description']
                    vulnsFound += 1
                    doc.add(UnorderedList((
                            f"{Bold(cveName)}: {cveDescription}",))
                    )
                    # print(f'''
                    #       [!] Vulnerability found in theme {themeName}:
                    #         -   {cveName}
                    #         -   {cveDescription}
                    #         -   Your version of the plugin is: {themeVersion}
                    #       ''') 

            elif(themeResponse['vulnerability'][vuln]['operator']['max_operator'] == 'le'):
                if(compareVersions(themeVersion, themeResponse['vulnerability'][vuln]['operator']['max_version']) <= 0):

                    cveName = themeResponse['vulnerability'][vuln]['source'][0]['name']
                    cveDescription = themeResponse['vulnerability'][vuln]['source'][0]['description']
                    vulnsFound += 1
                    doc.add(UnorderedList((
                            f"{Bold(cveName)}: {cveDescription}",))
                    )
                    # print(f'''
                    #       [!] Vulnerability found in theme {themeName}:
                    #         -   {cveName}
                    #         -   {cveDescription}
                    #         -   Your version of the plugin is: {themeVersion}
                    #       ''') 

        if vulnsFound == 0:
            doc.add(Paragraph(f'No vulnerabilities were found for this theme: {themeName}'))
            print(f'[✓] No vulnerabilities found for this theme: {themeName}')


# passiveCoreVersionDiscovery('https://fmi.unibuc.ro/')
# passivePluginDiscovery('https://ecomedbt.ro/')
# passiveThemeDiscovery('https://ecomedbt.ro/')

def passiveScanAll(doc, websiteName, manualPluginPath):
    passiveCoreVersionDiscovery(doc, websiteName)
    passivePluginDiscovery(doc, websiteName, manualPluginPath)
    passiveThemeDiscovery(doc, websiteName)
    findRobotsTxt(doc, websiteName)
    checkForInterestingHeaders(doc, websiteName)
    

# testAll('http://192.168.10.105:8000/')
# passivePluginDiscovery('http://192.168.10.105:8000/')
# passivePluginDiscovery('https://ecomedbt.ro/')

        
