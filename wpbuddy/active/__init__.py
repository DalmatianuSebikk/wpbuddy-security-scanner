"""Active phase: requests that interact with the target's functionality
(user enumeration fallbacks, XML-RPC probing, access assessment).

Everything invasive is opt-in: user enumeration and the XML-RPC probe run by
default (single, quiet requests); the access assessment (registration check,
login-error user validation, password spray) needs --access or --user.
"""

from . import access, users, xmlrpc  # credentials: imported directly where used
from . import extrachecks as extra_active


def run(report, target, args, dict_list=None, model=None):
    """Run the active phase.

    dict_list is the loaded full dictionary (--dict), used only when the
    operator explicitly opts into the loud path. model receives discovered
    credentials (P2-7) when provided.
    """
    found_users = users.enumerate_users(report, target, args.max_users)
    xmlrpc_alive = xmlrpc.probe(report, target)

    if getattr(args, "access", False) or args.user:
        access.run_access(report, target, args, found_users, xmlrpc_alive,
                          dict_list=dict_list, model=model)
    extra_active.run(report, target)
    report.rule()
