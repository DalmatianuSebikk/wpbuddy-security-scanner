import argparse
import textwrap
import passiveScan
import activeScan

from markdownmaker.document import Document
from markdownmaker.markdownmaker import *

# in main parsezi argumentele si trimiti mai departe.

parser = argparse.ArgumentParser(
    prog='WsBuddy, WordPress vulnerability scanner',
    description='''
        
    ░██╗░░░░░░░██╗
    ░██║░░██╗░░██║
    ░╚██╗████╗██╔╝
    ░░████╔═████║░
    ░░╚██╔╝░╚██╔╝░
    ░░░╚═╝░░░╚═╝░░
    WsBuddy, WordPress vulnerability scanner.
    ------------------------------------------------------------------
    An open-source vulnerability scanner for websites that use WordPress CMS.
    This scanner is useful at identifying and scanning vulnerabilities for the core version and plugins/themes in WordPress and also for testing weak credentials
    in the /wp-login page.
    You can use http://plugins.svn.wordpress.org for searching the slug of a plugin you want to maunally check on your website.

    Disclaimer:
    - this project is related to Website Security and not a tool that should be used in malicious activities. 
    - you shall not misuse this tool to gain unauthorized access. 
    ''',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=textwrap.dedent(
    '''
    ------------------------------------------------------------------
    Example: 
    python main.py --target https://example.com/ --pluginList pluginList.txt --user admin --passwordList pwd.txt --output out
    ------------------------------------------------------------------
    Project made by Sebastian Ionel @github.com/DalmatianuSebikk.
    '''
    )
)

parser.add_argument('--target', required=True, help='Name of the website that you want to scan. It can be an IP address or a domain name.')
parser.add_argument('--pluginList', help='Path to a custom pluginList.txt file for WsBuddy to check manually in the website (in case WsBuddy cannot detect them).')
parser.add_argument('--user', help='The user you want WsBuddy to check if has weak credentials.')
parser.add_argument('--passwordList', help='Path to the list of passwords that WpBuddy will use to check for weak credentials.')
parser.add_argument('--output', help ='output of the results of the scanner at the given path. (The file is saved as a markdown file, insert path only, without .md)')
args = vars(parser.parse_args())


pluginList = 'pluginList.txt'
user = 'admin'
passwordList = 'passwordList.txt'
output = 'outputScan'

target = args['target']



if __name__ == '__main__':

    print(target)
    if target.startswith('http://') == False and target.startswith('https://') == False:
        print(target.startswith('https://'))
        print("Insert the target again and be sure to include http:// or https://.\n")
        exit(0)
    else:
        if not target.endswith("/"):
            target += '/' #avoid errors

    if args['pluginList']:
        pluginList = args['pluginList']
    
    if args['user']:
        user = args['user']

    if args['passwordList']:
        passwordList = args['passwordList']

    if args['output'] and '.' not in args['output']:
        output = args['output']


    print("Starting the scanner..")

    doc = Document()
    doc.add(Header(f"WsBuddy output scan for {target}")) 
    
    passiveScan.passiveScanAll(doc, target, pluginList)
    activeScan.activeScanAll(doc, target, user, passwordList)
    with open(f'{output}.md', 'w') as f:
        f.write(doc.write())
        f.close()
    




