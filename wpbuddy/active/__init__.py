"""Active phase: requests that interact with the target's functionality
(user enumeration fallbacks, XML-RPC probing, access assessment).

Everything invasive is opt-in: user enumeration and the XML-RPC probe run by
default (single, quiet requests); the access assessment (registration check,
login-error user validation, password spray) needs --access or --user.
"""

from . import access, users, xmlrpc  # credentials: imported directly where used
from . import extrachecks as extra_active


def run(report, target, args, dict_list=None, model=None, include_access=True, emit=None):
    """Run the active phase.

    dict_list is the loaded full dictionary (--dict), used only when the
    operator explicitly opts into the loud path. model receives discovered
    credentials (P2-7) when provided.

    include_access=False runs only enumeration/XML-RPC and returns their
    results, so the engine can expose the access assessment as its own phase
    (`access`). The return value is always {'users': [...], 'xmlrpc_alive': bool}.
    """
    def check(step):
        if emit:
            emit("check-started", subphase=step)

    def done(step, **data):
        if emit:
            emit("check-finished", subphase=step, **data)

    check("users")
    found_users = users.enumerate_users(report, target, args.max_users)
    done("users", count=len(found_users))

    check("xmlrpc")
    xmlrpc_alive = xmlrpc.probe(report, target)
    done("xmlrpc", alive=xmlrpc_alive)

    if include_access and (getattr(args, "access", False) or args.user):
        access.run_access(report, target, args, found_users, xmlrpc_alive,
                          dict_list=dict_list, model=model)
    check("extra-checks")
    extra_active.run(report, target)
    done("extra-checks")
    report.rule()
    return {"users": found_users, "xmlrpc_alive": xmlrpc_alive}
