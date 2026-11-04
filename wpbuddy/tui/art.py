"""Shared artwork for WpBuddy's terminal surfaces.

`LOGO` is the hand-drawn figlet-style wordmark (pure ASCII, every line
<= 78 columns) and `CLI_BANNER` pairs it with the scanner intro and the
authorization disclaimer. The CLI's argparse description and the TUI
splash both render from here so the surfaces never drift apart.
"""

LOGO = r"""__        __               ____                _       _
\ \      / /       _ __   | __ )   _   _      | |     | |
 \ \ /\ / /       | '_ \  |  _ \  | | | | | | | | | | | | \   | |
  \ V  V /        | |_) | | |_) | | |_| | | |_| | | |_| |  \  | |
   \_/\_/         | .__/  |____/   \___/  \__,|_| \__,|_|   \ | |
                  |_|                                        \|_|"""

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
