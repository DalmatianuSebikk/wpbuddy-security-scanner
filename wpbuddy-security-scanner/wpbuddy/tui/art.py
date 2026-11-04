"""Shared artwork for WpBuddy's terminal surfaces.

`LOGO` is the wordmark (pure ASCII, every line <= 78 columns) and
`LOGO_COMPACT` is its one-line stand-in for height-starved surfaces (the
observatory top bar). `CLI_BANNER` pairs the wordmark with the scanner intro
and the authorization disclaimer. The CLI's argparse description and the TUI
splash both render from here so the surfaces never drift apart.

Logo provenance: generated with pyfiglet (figlet) in the `doom` font -
regenerate with:
    python -c "import pyfiglet; print(pyfiglet.figlet_format('WpBuddy', font='doom'))"
"""

LOGO = r""" _    _      ______           _     _
| |  | |     | ___ \         | |   | |
| |  | |_ __ | |_/ /_   _  __| | __| |_   _
| |/\| | '_ \| ___ \ | | |/ _` |/ _` | | | |
\  /\  / |_) | |_/ / |_| | (_| | (_| | |_| |
 \/  \/| .__/\____/ \__,_|\__,_|\__,_|\__, |
       | |                             __/ |
       |_|                            |___/
"""

# One-line brand for rows too short to spare the 8-line wordmark.
LOGO_COMPACT = "WpBuddy"

CLI_BANNER = LOGO + """

WpBuddy - WordPress vulnerability scanner
------------------------------------------------------------------
An open-source vulnerability scanner for websites using WordPress.
Identifies and matches vulnerabilities for the core version and for
plugins/themes, tests weak credentials, and audits component source
code locally. Passive, active (stealthy/invasive) and code-audit
phases can be tuned from the CLI.

Disclaimer:
- this project is related to Website Security and must not be used
  for malicious activities.
- never scan a website you do not own or are not authorized to test.
------------------------------------------------------------------
"""
