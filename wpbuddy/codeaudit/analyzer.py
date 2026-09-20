"""Pattern-based static analysis of gathered PHP source code.

This is intentionally a pragmatic grep-with-context analyzer (the same class
of engine early WPScan/Nessus plugin checks used), not a full taint solver:
every finding is a lead that must be reviewed, with file:line evidence
attached so a pentester can jump straight to the code.

False-positive control (learned the hard way against real plugins):
- rules run against a code-only view of each line: single-quoted string
  CONTENTS are blanked (a minifier's 'exec(' token list is not a call) and
  comments are stripped. Double-quoted strings are kept because PHP
  interpolation inside them is exactly what the SQL rules must see.
- the csrf-no-nonce heuristic skips class/trait/interface definition files:
  they are included by WordPress, never routed directly, and their nonce
  checks live in the dispatcher (admin-ajax/REST), not the file.
- include $var without request input on the line is demoted to a LOW
  'review' finding: that is the standard autoloader/template pattern.
"""

import re
from pathlib import Path

from .. import config

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
MAX_FINDINGS_PER_RULE_PER_FILE = 5
CONTEXT_LINES = 3

REQUEST_VAR = r"\$_(GET|POST|REQUEST|COOKIE|SERVER)\s*\["

# Parameter names inside $_GET['x'] / $_POST["y"] etc. - used by the PoC builder
PARAM_RE = re.compile(r"\$_(?:GET|POST|REQUEST|COOKIE)\s*\[\s*['\"]([\w\-]+)['\"]\s*\]")

# Files that define classes WordPress *includes* but never routes to directly
NOT_ENDPOINT_BASENAME = re.compile(r"(?:^class-|\.cls\.php$|\.trait\.php$|^abstract-|^interface-)", re.I)

# Content-based endpoint detection (naming conventions miss PSR-4 layouts):
# a file IS routable when it registers hooks/menus/routes itself; a file that
# only declares a class/trait/interface/namespace and hooks nothing is
# autoloaded definition code - its nonce checks live in the dispatcher.
_HOOK_RE = re.compile(r"\b(?:add_action|add_filter|add_shortcode|add_menu_page|"
                      r"add_submenu_page|register_rest_route|register_activation_hook)\s*\(")
_TYPE_DECL_RE = re.compile(r"(?m)^\s*(?:abstract\s+|final\s+)?(?:class|trait|interface)\s+\w")
_NAMESPACE_RE = re.compile(r"(?m)^\s*namespace\s+\w")

# Bundled third-party / test code: real matches, but not plugin-author code -
# demoted one severity level and labelled so it can't outrank the author's own.
_VENDOR_PATH_RE = re.compile(r"(?:^|/)(?:vendor|vendor_prefixed|node_modules|bower_components)(?:/|$)", re.I)
_TEST_PATH_RE = re.compile(r"(?:^|/)(?:tests?|spec)(?:/|$)|(?:-test|Test)\.php$", re.I)


def _is_endpoint_file(lines):
    """True when the file looks directly routable by WordPress."""
    code = "\n".join(code_view(line) for line in lines)
    if _HOOK_RE.search(code):
        return True
    if _TYPE_DECL_RE.search(code) or _NAMESPACE_RE.search(code):
        return False
    return True  # plain procedural file: give it the heuristic look

_SINGLE_QUOTED = re.compile(r"'(?:\\.|[^'\\])*'")
_LINE_COMMENT = re.compile(r"(//|#).*$")
_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)


def code_view(line):
    """A line with string-literal contents and comments blanked, for matching.

    $_GET['msg'] keeps its brackets (contents blanked), so REQUEST_VAR-style
    patterns still match; 'exec(' as a quoted token disappears.
    """
    line = _SINGLE_QUOTED.sub("''", line)
    line = _BLOCK_COMMENT.sub("", line)
    line = _LINE_COMMENT.sub("", line)
    return line


def _rules():
    """(severity, id, description, compiled_regex, exclusion_regex_or_None) per line.

    The exclusion regex suppresses the rule when it also matches the line -
    e.g. $wpdb->query($wpdb->prepare(...)) is the SAFE WordPress idiom and
    must not trigger the SQL rule.
    """
    return [
        ("CRITICAL", "backdoor-obfuscation",
         "eval() of obfuscated payload (base64/gzip/rot13) - classic webshell pattern",
         re.compile(r"eval\s*\(\s*(@?\w+\()? *(base64_decode|gzinflate|gzuncompress|str_rot13|urldecode)\s*\("),
         None),
        ("CRITICAL", "request-unserialize",
         "unserialize() directly on request input - PHP object injection / RCE",
         re.compile(r"unserialize\s*\([^)]*" + REQUEST_VAR),
         re.compile(r"sanitize|esc_|wp_unslash|absint")),
        ("HIGH", "command-exec",
         "OS command execution function",
         re.compile(r"\b(system|exec|shell_exec|passthru|popen|proc_open)\s*\("),
         re.compile(r"escapeshellarg|escapeshellcmd|WP_CLI|wp_shell")),
        ("HIGH", "eval-usage", "eval() usage",
         re.compile(r"\beval\s*\("),
         re.compile(r"base64_decode|gzinflate|gzuncompress|str_rot13")),
        ("HIGH", "create-function",
         "create_function() - equivalent to eval(), removed in PHP 8",
         re.compile(r"\bcreate_function\s*\("),
         None),
        ("HIGH", "preg-e-modifier",
         "preg_replace() with /e modifier executes the replacement as PHP code",
         re.compile(r"preg_replace\s*\(\s*['\"][^'\"]*e[a-z]*['\"]\s*,"),
         None),
        ("HIGH", "sqli-request",
         "SQL built with request variables ($_GET/$_POST/$_REQUEST) - SQL injection",
         re.compile(r"\$wpdb->\w+\s*\([^;)]*" + REQUEST_VAR),
         re.compile(r"->prepare\s*\(")),
        ("HIGH", "file-inclusion",
         "include/require of a path taken from request input - LFI/RFI",
         re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*[^;]*" + REQUEST_VAR),
         re.compile(r"plugin_dir_path|ABSPATH|locate_template|get_template_part|load_template")),
        ("MEDIUM", "ssrf-request",
         "remote fetch driven by request input - SSRF",
         re.compile(r"(?:wp_remote_(?:get|post|head|request)|file_get_contents|curl_setopt|curl_exec)\s*\([^;)]*" + REQUEST_VAR),
         re.compile(r"esc_url_raw|wp_http_validate_url|wp_safe_remote")),
        ("MEDIUM", "xss-echo",
         "echo/print of request input without escaping - reflected XSS",
         re.compile(r"\b(?:echo|print)\b[^;]*" + REQUEST_VAR),
         re.compile(r"esc_html|esc_attr|esc_url|wp_kses|sanitize|\b(?:int|integer|float|bool)\s*\(|absint")),
        ("LOW", "sqli-no-prepare",
         "SQL with string interpolation and no ->prepare() on the line - review whether "
         "the interpolated values can be attacker-controlled (internal constants are fine)",
         re.compile(r"\$wpdb->(?:query|get_var|get_row|get_results)\s*\([^;]*(?:\.\s*\$|\{\$|\$[A-Za-z_])"),
         re.compile(r"->prepare\s*\(|" + REQUEST_VAR)),
        ("LOW", "include-variable",
         "include/require with a variable path - usually an autoloader or template "
         "loader; review only if the path can be influenced from input",
         re.compile(r"\b(?:include|include_once|require|require_once)\s*\(?\s*\$"),
         re.compile(r"plugin_dir_path|ABSPATH|locate_template|get_template_part|load_template")),
        ("LOW", "extract-usage",
         "extract() overwrites local variables (historically $_REQUEST extracts)",
         re.compile(r"\bextract\s*\("),
         re.compile(r"EXTR_SKIP|EXTR_PREFIX")),
        ("INFO", "suppress-errors", "error suppression operator @ (hides failures)",
         re.compile(r"@\s*\$\w+->"),
         None),
    ]


# File-level heuristic rules (reported once per file)
FILE_RULES = [
    ("MEDIUM", "csrf-no-nonce",
     "directly-routed file handles $_POST with no nonce verification in the file "
     "(check_admin_referer / wp_verify_nonce)",
     re.compile(r"\$_(POST|REQUEST)\s*\["), re.compile(r"check_admin_referer|wp_verify_nonce|wp_nonce_field|check_ajax_referer")),
]

# AJAX/admin handlers registered without authorization in the callback - the
# vulnerability class behind a large share of recent plugin CVEs (the
# Claude+Semgrep CVE-hunting workflow popularized the join: registration on
# one line, missing check in the callback's BODY).
AJAX_ACTION_RE = re.compile(
    r"add_action\s*\(\s*['\"]((?:wp_ajax(?:_nopriv)?|admin_post|admin_action)_[\w-]+)['\"]"
    r"\s*,\s*['\"](\w+)['\"]")
AUTH_CHECK_RE = re.compile(
    r"current_user_can|wp_verify_nonce|check_ajax_referer|check_admin_referer|verify_nonce")
# 'verify_nonce' (bare) accepts framework wrappers like WPSEO_Utils::verify_nonce().
# NB: is_admin() is deliberately NOT in that list - it checks whether the
# request is in /wp-admin context, NOT the user's capabilities, and is a
# classic non-authorization check to hide behind.
_FUNC_DEF_RE = re.compile(r"function\s+(\w+)\s*\(")
_CALL_RE = re.compile(r"\b([a-zA-Z_]\w*)\s*\(")


def analyze(root):
    """Walk a directory of source and return findings sorted by severity.

    Finding shape: {severity, rule, description, file, line, snippet, params}
    """
    rules = _rules()
    findings = []
    root = Path(root)

    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix.lower() not in (".php", ".inc"):
            continue
        if path.stat().st_size > config.MAX_AUDIT_FILE_SIZE:
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        rel = str(path.relative_to(root))
        findings.extend(_scan_file(rel, lines, rules))

    findings.sort(key=lambda f: (SEVERITY_ORDER[f["severity"]], f["file"], f["line"]))
    return findings


def _scan_file(rel, lines, rules):
    findings = []
    per_rule_counts = {}
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith(("*", "//", "#")):
            continue
        code = code_view(stripped)
        for severity, rule_id, description, rx, exclude in rules:
            if per_rule_counts.get(rule_id, 0) >= MAX_FINDINGS_PER_RULE_PER_FILE:
                continue
            if exclude and exclude.search(code):
                continue
            if rx.search(code):
                findings.append(_finding(severity, rule_id, description, rel, lineno, stripped))
                per_rule_counts[rule_id] = per_rule_counts.get(rule_id, 0) + 1

    if not NOT_ENDPOINT_BASENAME.search(Path(rel).name) and _is_endpoint_file(lines):
        findings.extend(_scan_file_heuristics(rel, lines))
    findings.extend(_scan_ajax_auth(rel, lines))

    for finding in findings:
        _demote_bundled_code(finding)
    return findings


def _demote_bundled_code(finding):
    """Vendor/test-path matches are one step less severe - bundled framework
    code (Twig's eval, PHPUnit helpers) is worth knowing, not worth billing
    as the plugin's own HIGH."""
    if not (_VENDOR_PATH_RE.search(finding["file"]) or _TEST_PATH_RE.search(finding["file"])):
        return
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    if finding["severity"] in order:
        finding["severity"] = order[min(order.index(finding["severity"]) + 1, len(order) - 1)]
    finding["description"] += " [in bundled vendor/test code - not plugin-author code]"


def _scan_ajax_auth(rel, lines):
    """wp_ajax_* / admin_post_* callbacks whose bodies contain no capability
    or nonce check. Two passes over the file (the 'join'): collect the
    add_action() registrations, then locate each named callback's body.

    One hop of same-file delegation is followed: a thin wrapper that calls
    save_what(), where save_what() does check_ajax_referer(), is NOT a
    finding (real Yoast pattern that once tripped this rule).

    Severity: wp_ajax_nopriv_* handlers are callable UNAUTHENTICATED (HIGH);
    plain wp_ajax_*/admin_post_* need only a logged-in Subscriber (MEDIUM).
    """
    code_lines = [code_view(line) for line in lines]
    defined = set(_FUNC_DEF_RE.findall("\n".join(code_lines)))
    findings = []
    # registrations are matched on the RAW line: the action/callback names
    # live inside single-quoted strings, which code_view blanks
    for lineno, line in enumerate(lines, 1):
        for match in AJAX_ACTION_RE.finditer(line):
            action, callback = match.group(1), match.group(2)
            body = _function_body(code_lines, callback)
            if body is None or AUTH_CHECK_RE.search(body):
                continue
            callees = {c for c in _CALL_RE.findall(body)
                       if c in defined and c != callback}
            if any(AUTH_CHECK_RE.search(_function_body(code_lines, c) or "")
                   for c in callees):
                continue  # the check lives one hop away
            unauthenticated = "nopriv" in action
            findings.append(_finding(
                "HIGH" if unauthenticated else "MEDIUM",
                "ajax-handler-no-auth",
                f"`{action}` callback `{callback}()` has no capability/nonce check - "
                + ("callable by UNAUTHENTICATED visitors"
                   if unauthenticated else
                   "callable by any logged-in user (a Subscriber account is enough)"),
                rel, lineno, lines[lineno - 1].strip()))
    return findings


def _function_body(code_lines, name):
    """The brace-delimited body of function `name`, or None if not found.

    Works on the code_view'd lines (string contents blanked) so braces inside
    string literals don't break the depth count.
    """
    func_re = re.compile(rf"function\s+{re.escape(name)}\s*\(")
    start = next((i for i, line in enumerate(code_lines) if func_re.search(line)), None)
    if start is None:
        return None
    depth, opened, body = 0, False, []
    for line in code_lines[start:start + 400]:
        body.append(line)
        depth += line.count("{") - line.count("}")
        if "{" in line:
            opened = True
        if opened and depth <= 0:
            break
    return "\n".join(body) if opened else None


def _scan_file_heuristics(rel, lines):
    """Whole-file heuristics: patterns whose absence is the finding."""
    text = "\n".join(lines)
    out = []
    for severity, rule_id, description, must, absent in FILE_RULES:
        if must.search(text) and not absent.search(text):
            # point at the first line using a request variable
            for lineno, line in enumerate(lines, 1):
                if must.search(line):
                    out.append(_finding(severity, rule_id, description, rel, lineno, line.strip()))
                    break
    return out


def _finding(severity, rule_id, description, file, line, snippet):
    snippet = snippet[:160]
    return {"severity": severity, "rule": rule_id, "description": description,
            "file": file, "line": line, "snippet": snippet,
            "params": PARAM_RE.findall(snippet)}


def summarize(findings):
    counts = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts
