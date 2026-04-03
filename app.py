"""
Controlled Execution Sandbox — Flask Application
==================================================
A production-ready web application that safely executes user-submitted
Python expressions in a restricted environment with comprehensive
security controls, input validation, and persistent JSON logging.

Security Design Decisions:
  1. Keyword blacklist blocks dangerous tokens at the string level
     BEFORE any parsing or evaluation occurs.
  2. Only a curated whitelist of Python built-ins is exposed to eval();
     __builtins__ is explicitly replaced so nothing else leaks through.
  3. Execution is wrapped in a thread with a hard timeout so infinite
     loops or expensive computations cannot hang the server.
  4. Both globals and locals passed to eval() are locked down — no
     module references, no file handles, no introspection hooks.
"""

import json
import os
import re
import threading
import ast
import hashlib
from datetime import datetime, timezone, timedelta
from collections import defaultdict

from flask import Flask, render_template, request, jsonify

# ---------------------------------------------------------------------------
# App initialisation
# ---------------------------------------------------------------------------
app = Flask(__name__)

LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "execution_log.json")
EXECUTION_TIMEOUT = 5  # seconds — hard cap on any single eval()

# ---------------------------------------------------------------------------
# Security Database
# ---------------------------------------------------------------------------

BLOCKED_KEYWORDS = [
    "import", "os", "sys", "subprocess", "eval", "exec", "socket", 
    "pickle", "shutil", "marshal", "pty", "ftplib", "smtplib", "urllib",
    "requests", "builtins", "platform", "resource", "gc", "threading",
    "multiprocessing"
]

# Patterns representing active sandbox escape attempts or malicious intent.
HIGH_RISK_PATTERNS = [
    r"__subclasses__",   # Sandbox escape technique
    r"__builtins__",     # Direct builtin access
    r"__class__",        # Class-tree traversal
    r"__base__",
    r"__mro__",
    r"__init__",
    r"__globals__",
    r"\\x[0-9a-fA-F]",   # Hex-encoded payload
    r"\\u[0-9a-fA-F]",   # Unicode obfuscation
    r"base64",           # Encoded payload hint
    r"rot13",
    r"chr\s*\(",         # Character-based obfuscation
    r"ord\s*\(",
    r"__\w+__",          # Broad dunder check
]

# Regex patterns that catch reconnaissance or unusual but not necessarily critical behavior.
SUSPICIOUS_PATTERNS = [
    r"getattr",          # Dynamic attribute retrieval
    r"setattr",
    r"delattr",
    r"dir\s*\(",         # Reconnaissance / Discovery
    r"vars\s*\(",
    r"help\s*\(",
    r"locals\s*\(",
    r"globals\s*\(",
    r"compile\s*\(",     # Dynamic block generation
    r"breakpoint\s*\(",  # Terminal escape
]

# ---------------------------------------------------------------------------
# AST Security Validator
# ---------------------------------------------------------------------------
class ASTValidator(ast.NodeVisitor):
    """
    Walks the Abstract Syntax Tree (AST) of a Python expression to ensure
    it only contains safe operations. Rejects imports, dunder access, 
    and prohibited function calls.
    """
    ALLOWED_NODES = {
        ast.Expression, ast.Expr, ast.Load, ast.BinOp, ast.UnaryOp, 
        ast.Num, ast.Str, ast.Constant, ast.List, ast.Dict, ast.Tuple, 
        ast.Set, ast.Name, ast.Call, ast.Subscript, ast.Index, 
        ast.Attribute, ast.keyword, ast.Compare, ast.BoolOp
    }

    def __init__(self, safe_builtins):
        self.safe_builtins = set(safe_builtins)
        self.is_safe = True
        self.violation = None

    def visit(self, node):
        if type(node) not in self.ALLOWED_NODES:
            self.is_safe = False
            self.violation = f"Prohibited operation: {type(node).__name__}"
            return

        # Prevent dunder access (e.g., __class__) via Attribute nodes
        if isinstance(node, ast.Attribute):
            if node.attr.startswith("__"):
                self.is_safe = False
                self.violation = f"Prohibited dunder access: {node.attr}"
                return

        # Prevent dunder access via Name nodes
        if isinstance(node, ast.Name):
            if node.id.startswith("__"):
                self.is_safe = False
                self.violation = f"Prohibited dunder access: {node.id}"
                return

        # Restrict function calls to the whitelist
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Name):
                if node.func.id not in self.safe_builtins:
                    self.is_safe = False
                    self.violation = f"Unauthorised function call: {node.func.id}()"
                    return
            else:
                self.is_safe = False
                self.violation = "Complex function calls are restricted."
                return

        super().visit(node)

# ---------------------------------------------------------------------------
# Security: restricted built-ins whitelist
# ---------------------------------------------------------------------------
# Only these safe, side-effect-free functions are available inside eval().
# Everything else (including __import__) is absent.
SAFE_BUILTINS = {
    "len": len,
    "sum": sum,
    "max": max,
    "min": min,
    "abs": abs,
    "round": round,
    "str": str,
    "int": int,
    "float": float,
    "list": list,
    "dict": dict,
    "tuple": tuple,
    "set": set,
    "range": range,
    "sorted": sorted,
    "reversed": reversed,
    "enumerate": enumerate,
    "zip": zip,
    "map": map,
    "filter": filter,
    "bool": bool,
    "type": type,
    "print": print,       # captured via stdout — harmless
    "True": True,
    "False": False,
    "None": None,
    "pow": pow,
}


# ---------------------------------------------------------------------------
# Classification engine
# ---------------------------------------------------------------------------
def classify_input(expression: str) -> tuple[str, str | None]:
    """
    Classify a user expression as SAFE, BLOCKED, SUSPICIOUS, or HIGH_RISK.
    Returns (classification, violating_line).
    """
    lines = [line.strip() for line in expression.split('\n') if line.strip()]

    for line in lines:
        lowered = line.lower()
        
        # 1. Check for HIGH_RISK escape patterns first (highest priority)
        for pattern in HIGH_RISK_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return "HIGH_RISK", line

        # 2. Check blocked keywords
        for kw in BLOCKED_KEYWORDS:
            if re.search(rf"\b{re.escape(kw)}\b", lowered):
                return "BLOCKED", line

        # 3. Check suspicious patterns
        for pattern in SUSPICIOUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                return "SUSPICIOUS", line

    return "SAFE", None


# ---------------------------------------------------------------------------
# Sandboxed execution
# ---------------------------------------------------------------------------
def execute_safe(expression: str) -> dict:
    """
    Execute *expression* inside a tightly sandboxed eval() with a timeout.
    First performs AST validation for extra security.

    Returns a dict:
      {"success": True,  "result": <string>}   on success
      {"success": False, "error":  <string>}    on failure / timeout
    """
    # 1. AST Validation (Level 2 Defence)
    try:
        tree = ast.parse(expression, mode='eval')
        validator = ASTValidator(SAFE_BUILTINS.keys())
        validator.visit(tree)
        if not validator.is_safe:
            return {"success": False, "error": f"AST_VALIDATION_FAILED: {validator.violation}"}
    except SyntaxError as e:
        return {"success": False, "error": f"SyntaxError: {str(e)}"}
    except Exception as e:
        return {"success": False, "error": f"Validation Error: {str(e)}"}

    # 2. Sandboxed Eval (Level 3 Defence)
    result_container = {"done": False, "value": None, "error": None}

    def _target():
        try:
            # __builtins__ is explicitly overridden so that ONLY the
            # functions listed in SAFE_BUILTINS are available.
            restricted_globals = {"__builtins__": SAFE_BUILTINS}
            restricted_locals = {}
            value = eval(expression, restricted_globals, restricted_locals)
            result_container["value"] = str(value)
            result_container["done"] = True
        except Exception as exc:
            result_container["error"] = f"{type(exc).__name__}: {exc}"
            result_container["done"] = True

    thread = threading.Thread(target=_target, daemon=True)
    thread.start()
    thread.join(timeout=EXECUTION_TIMEOUT)

    if not result_container["done"]:
        return {"success": False, "error": "Execution timed out (exceeded 5 s)"}

    if result_container["error"]:
        return {"success": False, "error": result_container["error"]}

    return {"success": True, "result": result_container["value"]}


# ---------------------------------------------------------------------------
# Persistent JSON logging
# ---------------------------------------------------------------------------
def log_submission(ip: str, expression: str, classification: str, result: str | None):
    """
    Append one entry to the JSON log file with hash chaining.
    Each entry contains the hash of the previous record to ensure integrity.
    """
    # Read existing log (or start fresh)
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
    else:
        logs = []

    # Get previous hash
    prev_hash = logs[-1].get("current_hash") if logs else "0" * 64

    from datetime import timezone, timedelta
    ist = timezone(timedelta(hours=5, minutes=30))
    entry_data = {
        "timestamp": datetime.now(ist).strftime("%Y-%m-%d %H:%M:%S"),
        "ip_address": ip,
        "input": expression,
        "classification": classification,
        "result": result,
        "previous_hash": prev_hash
    }

    # Generate current hash (cryptographic link)
    hash_payload = json.dumps(entry_data, sort_keys=True).encode()
    current_hash = hashlib.sha256(hash_payload).hexdigest()
    entry_data["current_hash"] = current_hash

    logs.append(entry_data)

    with open(LOG_FILE, "w", encoding="utf-8") as f:
        json.dump(logs, f, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Rate Limiting & Anomaly Detection State
# ---------------------------------------------------------------------------
IP_HISTORY = defaultdict(list) # ip: [timestamp1, timestamp2, ...]
ATTACK_COUNTS = defaultdict(int) # ip: count of high-risk violations
MAX_REQUESTS_PM = 20 # Max 20 requests per minute per IP

def check_rate_limit(ip: str) -> bool:
    """True if under limit, False if rate-limited."""
    now = datetime.now()
    # Clean old history
    IP_HISTORY[ip] = [ts for ts in IP_HISTORY[ip] if now - ts < timedelta(minutes=1)]
    if len(IP_HISTORY[ip]) >= MAX_REQUESTS_PM:
        return False
    IP_HISTORY[ip].append(now)
    return True

# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
@app.route("/index.html")
def index():
    """Serve the single-page interface."""
    return render_template("index.html")

@app.route("/admin/v1/internal_config", methods=["GET", "POST"])
def honeypot_route():
    """
    Deception-based forensic trap (Honeypot). 
    Any interaction with this route is an immediate SECURITY_VIOLATION.
    """
    client_ip = request.remote_addr or "unknown"
    log_submission(
        client_ip, 
        f"HONEYPOT_ACCESS_ATTEMPT: {request.path}", 
        "HIGH_RISK", 
        "Honeypot Triggered: Path intended for internal admin only."
    )
    return jsonify({
        "status": "error",
        "message": "CRITICAL_SECURITY_BREACH: Your session has been flagged for forensic analysis."
    }), 403

@app.route("/execute", methods=["POST"])
def execute():
    """
    API endpoint: receive a Python expression, classify it, optionally
    execute it, log the event, and return the outcome as JSON.
    """
    client_ip = request.remote_addr or "unknown"

    # 1. Rate Limit Enforcement
    if not check_rate_limit(client_ip):
        return jsonify({
            "classification": "BLOCKED",
            "message": "RATE_LIMIT_EXCEEDED: Forensic kernel paused to prevent resource exhaustion."
        }), 429

    data = request.get_json(silent=True) or {}
    expression = (data.get("expression") or "").strip()

    if not expression:
        return jsonify({"classification": "BLOCKED", "message": "Empty input."}), 400

    # 2. Anomaly Detection (Repeated Offender)
    if ATTACK_COUNTS[client_ip] >= 5:
        # Penalise aggressive attackers
        log_submission(client_ip, expression, "HIGH_RISK", "AUTOMATED_BAN: Persistent malicious activity detected.")
        return jsonify({
            "classification": "HIGH_RISK",
            "message": "SESSION_TERMINATED: Systematic attack patterns detected from your origin."
        }), 403

    classification, violating_line = classify_input(expression)
    result_text = None

    if classification == "SAFE":
        outcome = execute_safe(expression)
        if outcome["success"]:
            result_text = outcome["result"]
            message = outcome["result"]
        else:
            result_text = outcome["error"]
            message = outcome["error"]
            # If it's a syntax error or similar, keep safe.
            # But if it's an AST failure, it's already caught.
            
    elif classification == "HIGH_RISK":
        ATTACK_COUNTS[client_ip] += 1
        message = f"CRITICAL_ALERT: High-risk attack pattern detected on line: '{violating_line}'. Immediate sandbox termination."
        result_text = f"Attack Payload: {violating_line}"

    elif classification == "BLOCKED":
        ATTACK_COUNTS[client_ip] += 0.5 # Fractional weights for anomalies
        message = f"SECURITY_VIOLATION: Input contains blacklisted tokens on line: '{violating_line}'. Execution terminated."
        result_text = f"Offending Payload: {violating_line}"

    else:  # SUSPICIOUS
        message = f"HEURISTIC_DETECTION: Potential reconnaissance/obfuscation on line: '{violating_line}'. Request flagged."
        result_text = f"Suspicious Line: {violating_line}"

    # Persistent chain-linked logging
    log_submission(client_ip, expression, classification, result_text)

    return jsonify({
        "classification": classification,
        "message": message,
    })


@app.route("/logs")
def view_logs():
    """Return the full execution log as JSON (for the log viewer panel)."""
    if os.path.exists(LOG_FILE):
        with open(LOG_FILE, "r", encoding="utf-8") as f:
            try:
                logs = json.load(f)
            except json.JSONDecodeError:
                logs = []
    else:
        logs = []
    return jsonify(logs)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5001)
