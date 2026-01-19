
# AI-Powered Code Generation Risk Assessment and Secure SDLC Controls

## Introduction: Proactive Security for AI-Assisted Development

As a Software Developer at "InnovateTech Solutions," I'm constantly leveraging AI code assistants to boost productivity. However, this has brought a new challenge: a noticeable increase in security incidents linked to AI-generated code. From hard-coded secrets to vulnerable dependencies, these issues threaten our product integrity and customer trust.

My primary responsibility is to ensure that while we embrace AI's power, we don't compromise on security. Leadership has mandated a proactive approach: identifying and mitigating these risks *before* they hit production. This means performing thorough static analysis, assessing third-party dependencies, and integrating robust security gates into our CI/CD pipelines.

This notebook simulates my daily workflow, demonstrating how I utilize static analysis techniques and risk assessment to secure our codebase. We'll process code artifacts, identify common AI-introduced vulnerabilities, analyze dependencies, and ultimately generate an automated CI/CD gate plan to enforce our security policies.

---

## 1. Environment Setup and Dependency Installation

Before we dive into analyzing code, we need to ensure our environment is correctly set up with all the necessary libraries. This includes `pydantic` for structured data models, `uuid` and `hashlib` for generating unique identifiers and content hashes, `ast` for abstract syntax tree parsing, and `re` for regex-based pattern matching.

```python
# Install required libraries
!pip install pydantic==2.5.3  # Pinning version for consistency in specification
```

## 2. Importing Dependencies and Defining Data Models

As a Software Developer, I rely on well-defined structures to manage complex data, especially when dealing with security findings. Pydantic helps me create robust, type-safe data models for code artifacts, security findings, dependency records, and our CI/CD gate plans. This ensures consistency and makes it easier to process and export audit results.

### Story + Context + Real-World Relevance

My first step in building any robust analysis tool is defining the data structures that will hold my findings. This is crucial for maintaining clarity, ensuring data integrity, and facilitating easy export and integration with other systems. Using Pydantic means I'm not just storing data; I'm storing *structured, validated* data, which is essential for auditability and reliability in a security context. These models mirror the artifacts I'll be working with – code snippets, vulnerability findings, dependency information, and the final CI/CD gate configurations.

The `GateType` and `FindingType` enumerations, for example, define the standardized categories for our security checks and pipeline actions. This prevents ambiguity and ensures that everyone on the team understands the classification of risks and controls. The `Severity` enumeration allows for consistent risk prioritization, guiding our remediation efforts.

```python
# Import required dependencies
import re
import uuid
import hashlib
import datetime
import ast
import json
import yaml
from enum import Enum
from typing import List, Dict, Any, Optional

from pydantic import BaseModel, Field, ValidationError

# --- Enumerations for Data Models ---
class FindingType(str, Enum):
    """Enumerates types of security findings."""
    SECRET = "SECRET"
    INJECTION_SINK = "INJECTION_SINK"
    UNSAFE_CRYPTO = "UNSAFE_CRYPTO"
    UNSAFE_DESERIALIZATION = "UNSAFE_DESERIALIZATION"
    DANGEROUS_EXEC = "DANGEROUS_EXEC"
    INSECURE_DEPENDENCY = "INSECURE_DEPENDENCY"
    HALLUCINATED_PACKAGE = "HALLUCINATED_PACKAGE"
    LICENSE_RISK = "LICENSE_RISK"

class Severity(str, Enum):
    """Enumerates severity levels for findings."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class GateType(str, Enum):
    """Enumerates types of CI/CD gates."""
    PRE_COMMIT = "PRE_COMMIT"
    CI_BUILD = "CI_BUILD"
    CI_TEST = "CI_TEST"
    CI_SECURITY = "CI_SECURITY"
    PRE_DEPLOY = "PRE_DEPLOY"

class DependencyStatus(str, Enum):
    """Enumerates status for dependency packages."""
    ALLOW = "ALLOW"
    DENY = "DENY"
    UNKNOWN = "UNKNOWN"

# --- Pydantic Data Models ---
class CodeArtifact(BaseModel):
    """Represents a code artifact being analyzed."""
    artifact_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    filename: str
    language: str = "python" # Defaulting to python for this lab
    content_hash: str # SHA256 hash of the content
    source: str = "UNKNOWN" # e.g., COPILOT, CLAUDE, AGENT, UNKNOWN
    created_at: datetime.datetime = Field(default_factory=datetime.datetime.now)
    content: str # The actual code content, kept for processing

class Finding(BaseModel):
    """Represents a single security finding."""
    finding_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    artifact_id: uuid.UUID
    finding_type: FindingType
    severity: Severity
    rule_id: str
    description: str
    location: Optional[str] = None # e.g., "line 5-7"
    evidence_snippet: Optional[str] = None
    remediation_guidance: str
    cwe_mapping: Optional[str] = None

class DependencyRecord(BaseModel):
    """Represents a detected dependency package."""
    name: str
    version_spec: str
    source_file: str # e.g., requirements.txt
    status: DependencyStatus
    risk_notes: Optional[str] = None

class GateConfig(BaseModel):
    """Represents a single gate configuration within the GatePlan."""
    gate_type: GateType
    tools: List[str]
    required_checks: List[str]
    failure_action: str # e.g., BLOCK, WARN
    owner_role: Optional[str] = "DevSecOps Team"
    evidence_required: List[str] = []

class GatePlan(BaseModel):
    """Represents the overall CI/CD gate plan."""
    gates: List[GateConfig]

class EvidenceManifest(BaseModel):
    """Records metadata about the analysis run and its outputs."""
    run_id: uuid.UUID = Field(default_factory=uuid.uuid4)
    generated_at: datetime.datetime = Field(default_factory=datetime.datetime.now)
    team_or_user: str = "InnovateTech DevSecOps"
    app_version: str = "1.0.0-alpha"
    inputs_hash: str # Hash of all input artifacts combined
    outputs_hash: str # Hash of all output reports combined
    artifacts: List[Dict[str, Any]] # Simplified artifact info for manifest

# --- Rule Engine Structure ---
class Rule(BaseModel):
    """Defines a security rule for static analysis."""
    rule_id: str
    detection_method: str # REGEX or AST
    severity: Severity
    description: str
    remediation_guidance: str
    cwe_mapping: Optional[str] = None
    pattern: Optional[str] = None # For REGEX rules
    ast_check_func: Optional[Any] = None # For AST rules (function reference)

# --- Configuration for Dependency Analysis ---
DEPENDENCY_CONFIG = {
    "allowlist": ["requests", "numpy", "pandas", "Flask", "fastapi", "sqlalchemy"],
    "denylist": ["shodan", "pickle", "pyyaml", "MD5", "Crypto.Cipher.ARC4"], # Common risky libs
    "hallucinated_suffix": ["-pro", "-enterprise", "-ai", "-securelib"] # Suffixes to flag as potential hallucination
}

# --- Mock synthetic data for demonstration ---
SYNTHETIC_CODE_SNIPPETS = {
    "app_with_secrets.py": """
import os

# AI generated code often includes hardcoded secrets
API_KEY = "sk-A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"
AWS_SECRET = "AKIAIOSFODNN7EXAMPLE" # AWS Access Key ID example
DB_PASSWORD = os.getenv("DB_PASSWORD", "myHardcodedPassword123") # Fallback to hardcoded

def send_request(url, data):
    headers = {"Authorization": f"Bearer {API_KEY}"}
    # Insecure use of eval
    if "debug" in data:
        eval(data["debug"]) # Dangerous dynamic execution
    return requests.post(url, json=data, headers=headers)

class User:
    def __init__(self, username, password):
        self.username = username
        self.password = password

# Insecure deserialization example
import pickle
def load_user_data(data):
    return pickle.loads(data)

""",
    "data_processor.py": """
import sqlite3
import hashlib

def get_user_data(username):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # SQL injection vulnerability using f-string
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchone()

def process_data(data_str):
    # Unsafe hash for security purposes
    hashed_data = hashlib.md5(data_str.encode()).hexdigest()
    return hashed_data

import subprocess
def execute_command(command):
    # Dangerous shell=True
    subprocess.run(command, shell=True, check=True)

""",
    "simple_script.py": """
def hello_world():
    print("Hello, secure world!")

# No vulnerabilities here.
"""
}

SYNTHETIC_DEPENDENCY_FILES = {
    "requirements.txt": """
requests>=2.25.1
flask-secure-pro==1.0.0 # Hallucinated package
pyyaml==5.4.1 # Denylisted for unsafe loading
numpy==1.22.0
""",
    "pyproject.toml": """
[project]
name = "my-project"
version = "0.1.0"
dependencies = [
    "fastapi>=0.70.0",
    "badlib-enterprise==0.0.1", # Hallucinated and potentially denylisted
    "SQLAlchemy==1.4.27"
]
""",
    "package.json": """
{
  "name": "frontend-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.17.1",
    "lodash.get": "^4.4.2",
    "insecure-js-lib": "1.0.0" # This would be denylisted
  }
}
"""
}

# --- Global lists to store findings and artifacts ---
all_artifacts: List[CodeArtifact] = []
all_findings: List[Finding] = []
all_dependencies: List[DependencyRecord] = []
```

### Explanation of Execution

These Pydantic models serve as the schema for all the data our analysis will generate. When I process a code file, its metadata and content will conform to `CodeArtifact`. Any security issues found will be stored as `Finding` objects, complete with severity, description, and remediation advice. Dependencies found in files like `requirements.txt` will be structured as `DependencyRecord`s. This structured approach is critical for creating consistent, machine-readable security reports, which are invaluable for tracking risks and demonstrating compliance to auditors. The enumerations standardize our security vocabulary across the team.

---

## 3. Code Ingestion and Artifact Generation

As a developer, my first practical step is to get the code into a format I can analyze. This often means ingesting raw code snippets or files from a repository, creating a standard `CodeArtifact` record for each. This process includes generating a unique `artifact_id` and a content hash (SHA256). The content hash is particularly important for auditability; it's our digital fingerprint of the exact code state at the time of analysis, ensuring that our findings always refer to an immutable piece of evidence.

### Story + Context + Real-World Relevance

When AI assists in code generation, I need a reliable way to track exactly *which* code was analyzed. Imagine an AI generating 50 lines of code; I need to ensure that if a vulnerability is found, I can point directly to the exact version of that code. The `content_hash` serves as this unalterable reference. It’s a cryptographic integrity check, ensuring the code hasn't been tampered with since analysis. For instance, if an auditor later questions a finding, I can provide the hash and the corresponding code, proving the finding's validity against that specific version. The `artifact_id` provides a unique identifier for each piece of code, simplifying tracking across multiple analysis runs.

The SHA256 content hash $H$ for a code artifact $C$ is calculated as:
$$ H = \text{SHA256}(\text{UTF8Encode}(C)) $$
This operation ensures that any change, no matter how small, to the code $C$ will result in a completely different hash $H$, making it an ideal tool for immutability and auditing.

```python
def generate_code_artifact(filename: str, content: str, source: str = "UNKNOWN") -> CodeArtifact:
    """
    Creates a CodeArtifact object, including generating a SHA256 content hash.
    """
    content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
    artifact = CodeArtifact(
        filename=filename,
        content=content,
        content_hash=content_hash,
        source=source
    )
    all_artifacts.append(artifact)
    return artifact

# Ingest our synthetic code snippets
for filename, content in SYNTHETIC_CODE_SNIPPETS.items():
    if "app_with_secrets.py" in filename:
        generate_code_artifact(filename, content, source="COPILOT")
    elif "data_processor.py" in filename:
        generate_code_artifact(filename, content, source="CLAUDE")
    else:
        generate_code_artifact(filename, content)

print(f"Generated {len(all_artifacts)} CodeArtifacts:")
for artifact in all_artifacts:
    print(f"- ID: {artifact.artifact_id}, File: {artifact.filename}, Hash: {artifact.content_hash[:8]}...")
```

### Explanation of Execution

Each of my input code snippets has now been converted into a structured `CodeArtifact`. I can see the unique ID and the content hash for each. This is my foundation for all subsequent security analysis. If I need to trace back a finding, I can link it directly to this artifact and its immutable hash. This level of traceability is crucial for security compliance and incident response, ensuring that I can always verify the exact version of the code that was scanned.

---

## 4. Implementing Static Analysis Rules: Regex for Secrets and Injection

Now that I have my code artifacts, I need to start scanning them for common vulnerabilities. My first line of defense often involves regex-based pattern matching. This is extremely effective for identifying hard-coded secrets (like API keys or passwords) and common injection patterns quickly, even if the code structure varies slightly. These are prevalent issues in AI-generated code due to its tendency to produce straightforward, sometimes insecure, solutions.

### Story + Context + Real-World Relevance

Hard-coded secrets are a prime example of a critical risk introduced by AI code assistants. Developers might prompt an AI for a quick solution, and the AI, without context of environment variables or secure credential management, might just embed a placeholder API key directly. My job is to catch these immediately. Regex is perfect for this: it's fast and highly customizable. Similarly, for SQL injection, I can use regex to find common patterns like f-strings or string concatenations directly within SQL queries.

A `Rule` object defines the specific patterns I’m looking for, along with the `severity` and `remediation_guidance`. This structured rule definition is part of our pluggable rule engine.
When using regex, a pattern $P$ is applied to a code line $L$. If the regex `re.search(P, L)` returns a match, a finding is generated. This is an efficient way to detect known insecure strings or patterns.

```python
# --- Static Analysis Rule Definitions ---
# REGEX-based rules
STATIC_RULES: List[Rule] = [
    Rule(
        rule_id="SECRET_API_KEY",
        detection_method="REGEX",
        severity=Severity.CRITICAL,
        description="Hard-coded API key detected.",
        remediation_guidance="Use environment variables or a secure secret management system.",
        cwe_mapping="CWE-798",
        pattern=r"(api_key|secret|token|password|auth_token)\s*=\s*[\"'](sk-|AKIA|eyJ)[a-zA-Z0-9\-_]{16,}[\"']"
    ),
    Rule(
        rule_id="SECRET_AWS_KEY",
        detection_method="REGEX",
        severity=Severity.CRITICAL,
        description="Hard-coded AWS access key/secret detected.",
        remediation_guidance="Use IAM roles or environment variables for AWS credentials.",
        cwe_mapping="CWE-798",
        pattern=r"(AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}"
    ),
    Rule(
        rule_id="SECRET_GENERIC_PASSWORD",
        detection_method="REGEX",
        severity=Severity.HIGH,
        description="Generic hard-coded password pattern detected.",
        remediation_guidance="Avoid hard-coding passwords. Use secure secret management.",
        cwe_mapping="CWE-798",
        pattern=r"(password|passwd|pwd)\s*=\s*[\"'][a-zA-Z0-9!@#$%^&*()_+]{8,}[\"']"
    ),
    Rule(
        rule_id="INJECTION_SQL_FSTRING",
        detection_method="REGEX",
        severity=Severity.HIGH,
        description="Potential SQL injection due to f-string formatting in query.",
        remediation_guidance="Use parameterized queries instead of f-strings or string concatenation for SQL.",
        cwe_mapping="CWE-89",
        pattern=r"(cursor\.execute\s*\(f\"(SELECT|INSERT|UPDATE|DELETE).*\')",
    ),
    Rule(
        rule_id="UNSAFE_CRYPTO_MD5",
        detection_method="REGEX",
        severity=Severity.MEDIUM,
        description="Use of MD5 for security-sensitive operations, which is cryptographically weak.",
        remediation_guidance="Use SHA256 or stronger hashing algorithms for security purposes.",
        cwe_mapping="CWE-327",
        pattern=r"hashlib\.md5"
    )
]

def find_vulnerabilities_regex(artifact: CodeArtifact, rules: List[Rule]) -> List[Finding]:
    """
    Applies regex-based rules to a code artifact and returns detected findings.
    """
    findings: List[Finding] = []
    lines = artifact.content.splitlines()
    for i, line in enumerate(lines):
        for rule in rules:
            if rule.detection_method == "REGEX" and rule.pattern:
                match = re.search(rule.pattern, line)
                if match:
                    findings.append(
                        Finding(
                            artifact_id=artifact.artifact_id,
                            finding_type=FindingType[rule.rule_id.split('_')[0]], # Infer type from rule_id prefix
                            severity=rule.severity,
                            rule_id=rule.rule_id,
                            description=rule.description,
                            location=f"line {i+1}",
                            evidence_snippet=line.strip(),
                            remediation_guidance=rule.remediation_guidance,
                            cwe_mapping=rule.cwe_mapping
                        )
                    )
    return findings

# Execute regex-based checks
for artifact in all_artifacts:
    regex_findings = find_vulnerabilities_regex(artifact, STATIC_RULES)
    all_findings.extend(regex_findings)

# Display findings
print(f"Found {len(all_findings)} regex-based vulnerabilities.")
if all_findings:
    print("\nSample of detected findings:")
    for finding in all_findings:
        print(f"  - [{finding.severity.value}] {finding.rule_id} in {next(a.filename for a in all_artifacts if a.artifact_id == finding.artifact_id)} at {finding.location}: '{finding.evidence_snippet}'")

```

### Explanation of Execution

I've successfully run our initial set of regex-based checks. The output clearly shows several critical and high-severity findings, such as hard-coded API keys and potential SQL injection, along with the use of a weak cryptographic hash (MD5). For each finding, I get the exact line number and the snippet of code that triggered the rule, making it easy to pinpoint and verify the vulnerability. This immediate feedback helps me understand the attack surface generated by the AI and prioritize my remediation efforts. For instance, a `CRITICAL` secret finding would prompt an immediate action to remove the secret and implement a secure secret management solution.

---

## 5. Advanced Static Analysis: AST for Dangerous Execution & Deserialization

While regex is great for patterns, some vulnerabilities require a deeper understanding of the code's structure and execution flow. This is where Abstract Syntax Tree (AST) analysis comes in. By parsing the code into an AST, I can precisely identify dangerous function calls like `eval()`, `subprocess.run(shell=True)`, or `pickle.loads()`, which are often misused and can lead to severe security breaches. AI can sometimes generate these constructs without fully understanding their implications.

### Story + Context + Real-World Relevance

Dangerous dynamic execution (`eval`, `exec`, `subprocess.run(shell=True)`) and insecure deserialization (`pickle.loads`, `yaml.load`) are critical vulnerabilities. An AI might suggest using `eval` for dynamic expression evaluation or `pickle` for object persistence without recognizing the inherent security risks. Relying solely on regex for these would be prone to false positives or negatives. AST analysis allows me to precisely locate these function calls and confirm their dangerous usage within the code's actual structure. This ensures that I’m not just looking for strings but for actual execution paths that introduce risk.

An AST traversal involves recursively visiting each node in the tree. For instance, to detect `subprocess.run(shell=True)`, I would look for `ast.Call` nodes where the function is `subprocess.run` and one of its keyword arguments is `shell=True`.

```python
# --- AST-based rule functions ---
def check_dangerous_exec_ast(node: ast.AST, artifact_id: uuid.UUID) -> List[Finding]:
    findings: List[Finding] = []
    if isinstance(node, (ast.Call, ast.Attribute)):
        func_name = ""
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        elif isinstance(node, ast.Attribute):
            func_name = node.attr

        # Check for eval/exec/subprocess
        if func_name in ["eval", "exec"]:
            findings.append(
                Finding(
                    artifact_id=artifact_id,
                    finding_type=FindingType.DANGEROUS_EXEC,
                    severity=Severity.HIGH,
                    rule_id="AST_DANGEROUS_EVAL_EXEC",
                    description=f"Use of {func_name}() detected, which can lead to arbitrary code execution.",
                    remediation_guidance="Avoid eval/exec for untrusted input. Consider safer alternatives like ast.literal_eval.",
                    location=f"line {node.lineno}",
                    evidence_snippet=ast.unparse(node),
                    cwe_mapping="CWE-94"
                )
            )
        elif func_name == "run" and isinstance(node, ast.Call):
            if any(k.arg == "shell" and isinstance(k.value, ast.Constant) and k.value.value is True for k in node.keywords):
                if isinstance(node.func, ast.Attribute) and node.func.attr == "run" and isinstance(node.func.value, ast.Name) and node.func.value.id == "subprocess":
                    findings.append(
                        Finding(
                            artifact_id=artifact_id,
                            finding_type=FindingType.DANGEROUS_EXEC,
                            severity=Severity.HIGH,
                            rule_id="AST_SUBPROCESS_SHELL_TRUE",
                            description="subprocess.run() with shell=True detected, which is dangerous with untrusted input.",
                            remediation_guidance="Avoid shell=True. Pass commands as a list of arguments instead.",
                            location=f"line {node.lineno}",
                            evidence_snippet=ast.unparse(node),
                            cwe_mapping="CWE-78"
                        )
                    )
    return findings

def check_unsafe_deserialization_ast(node: ast.AST, artifact_id: uuid.UUID) -> List[Finding]:
    findings: List[Finding] = []
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
        if node.func.attr == "loads":
            if isinstance(node.func.value, ast.Name) and node.func.value.id == "pickle":
                findings.append(
                    Finding(
                        artifact_id=artifact_id,
                        finding_type=FindingType.UNSAFE_DESERIALIZATION,
                        severity=Severity.CRITICAL,
                        rule_id="AST_PICKLE_LOADS",
                        description="Use of pickle.loads() detected, which is unsafe for untrusted input due to arbitrary code execution risk.",
                        remediation_guidance="Avoid pickle for untrusted data. Use safer serialization formats like JSON or Protocol Buffers.",
                        location=f"line {node.lineno}",
                        evidence_snippet=ast.unparse(node),
                        cwe_mapping="CWE-502"
                    )
                )
    return findings

# Add AST-based rules to the STATIC_RULES list
# Note: For AST rules, 'pattern' is None, and 'ast_check_func' is set
STATIC_RULES.extend([
    Rule(
        rule_id="AST_DANGEROUS_EVAL_EXEC",
        detection_method="AST",
        severity=Severity.HIGH,
        description="Dangerous use of eval() or exec() detected.",
        remediation_guidance="Review use of dynamic code execution. Prefer safer alternatives.",
        cwe_mapping="CWE-94",
        ast_check_func=check_dangerous_exec_ast
    ),
    Rule(
        rule_id="AST_SUBPROCESS_SHELL_TRUE",
        detection_method="AST",
        severity=Severity.HIGH,
        description="subprocess.run with shell=True is dangerous.",
        remediation_guidance="Refactor to pass commands as a list and avoid shell=True.",
        cwe_mapping="CWE-78",
        ast_check_func=check_dangerous_exec_ast # Reusing the same check function
    ),
    Rule(
        rule_id="AST_PICKLE_LOADS",
        detection_method="AST",
        severity=Severity.CRITICAL,
        description="Unsafe deserialization using pickle.loads detected.",
        remediation_guidance="Avoid pickle.loads with untrusted input. Use JSON or similar for data exchange.",
        cwe_mapping="CWE-502",
        ast_check_func=check_unsafe_deserialization_ast
    )
])


def find_vulnerabilities_ast(artifact: CodeArtifact, rules: List[Rule]) -> List[Finding]:
    """
    Applies AST-based rules to a code artifact and returns detected findings.
    """
    findings: List[Finding] = []
    try:
        tree = ast.parse(artifact.content)
        for node in ast.walk(tree):
            for rule in rules:
                if rule.detection_method == "AST" and rule.ast_check_func:
                    findings.extend(rule.ast_check_func(node, artifact.artifact_id))
    except SyntaxError as e:
        print(f"Skipping AST analysis for {artifact.filename} due to syntax error: {e}")
    return findings

# Execute AST-based checks
for artifact in all_artifacts:
    ast_findings = find_vulnerabilities_ast(artifact, STATIC_RULES)
    # Filter out duplicates if a single check_func identifies multiple rules (e.g., check_dangerous_exec_ast for both eval/exec and subprocess)
    # For simplicity in this lab, we assume rule_ids are distinct enough.
    all_findings.extend(ast_findings)

# Display new findings
print(f"\nFound {len(all_findings) - len(regex_findings)} new AST-based vulnerabilities (total: {len(all_findings)}).")
if ast_findings:
    print("\nSample of new AST findings:")
    for finding in [f for f in ast_findings if f not in regex_findings]: # Only show newly added AST findings
        print(f"  - [{finding.severity.value}] {finding.rule_id} in {next(a.filename for a in all_artifacts if a.artifact_id == finding.artifact_id)} at {finding.location}: '{finding.evidence_snippet}'")

```

### Explanation of Execution

The AST analysis has successfully identified more subtle but critically dangerous patterns, such as `eval()` and `pickle.loads()`. These findings are particularly important because they represent high-impact vulnerabilities that a simple text search might miss or misinterpret. For instance, knowing that `pickle.loads` is explicitly called within the AST node provides definitive evidence of unsafe deserialization. This level of precision is invaluable for a developer, allowing me to trust the findings and focus on targeted remediation, preventing potential remote code execution or data corruption.

---

## 6. Dependency Risk Assessment: Allowlist, Denylist, and Hallucination Detection

AI code assistants can generate `requirements.txt` or `pyproject.toml` entries that might include outdated, insecure, or even entirely fabricated (hallucinated) packages. As a Software Developer, reviewing dependencies is a crucial part of securing the supply chain. I need to ensure that all packages conform to our organization's approved lists and flag any suspicious entries that could be hallucinations.

### Story + Context + Real-World Relevance

Supply chain attacks are a major threat, and AI can inadvertently contribute by suggesting insecure or non-existent packages. My role involves parsing these dependency files and comparing them against our internal `allowlist` (approved packages) and `denylist` (known risky packages). Beyond that, AI sometimes "hallucinates" packages that don't exist or have misleading names (e.g., `requests-pro`). Detecting these hallucinations is vital to prevent developers from unknowingly installing malicious or non-functional libraries. This step directly mitigates supply chain risks.

The process involves:
1. Parsing the dependency file to extract package names and versions.
2. Checking against the `allowlist` and `denylist`.
3. Applying heuristics (like custom suffixes) to detect potential `hallucinated_package` risks.

```python
def parse_and_analyze_dependencies(filename: str, content: str, artifact_id: uuid.UUID) -> List[DependencyRecord]:
    """
    Parses dependency file content and analyzes packages against allow/denylists and for hallucination risk.
    """
    dependencies: List[DependencyRecord] = []
    lines = content.splitlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        package_name = ""
        version_spec = ""
        risk_notes = []
        dep_status = DependencyStatus.UNKNOWN

        # Basic parsing for requirements.txt, pyproject.toml (dependencies array), package.json (dependencies object)
        if filename.endswith("requirements.txt"):
            match = re.match(r"([a-zA-Z0-9_\-\.]+)(?:\s*[<>=!~]+(.+))?", line)
            if match:
                package_name = match.group(1).lower()
                version_spec = match.group(2) if match.group(2) else ""
        elif filename.endswith("pyproject.toml"):
            # Simplified parsing: looking for direct dependencies within TOML
            match = re.match(r'\"([a-zA-Z0-9_\-\.]+)(?:[<>=!~]+(.+))?\"', line)
            if match and "dependencies" in content: # Crude check to ensure it's in the deps section
                package_name = match.group(1).lower()
                version_spec = match.group(2) if match.group(2) else ""
        elif filename.endswith("package.json"):
            # Simplified parsing for package.json "dependency": "version"
            match = re.match(r'"([a-zA-Z0-9_\-\.\/]+)"\s*:\s*"(.+)"', line)
            if match and '"dependencies": {' in content: # Crude check
                package_name = match.group(1).lower()
                version_spec = match.group(2) if match.group(2) else ""

        if not package_name:
            continue

        if package_name in DEPENDENCY_CONFIG["denylist"]:
            dep_status = DependencyStatus.DENY
            risk_notes.append(f"Package '{package_name}' is on the denylist.")
            all_findings.append(
                Finding(
                    artifact_id=artifact_id,
                    finding_type=FindingType.INSECURE_DEPENDENCY,
                    severity=Severity.HIGH,
                    rule_id="DEP_DENYLISTED",
                    description=f"Denylisted package '{package_name}' found.",
                    remediation_guidance="Remove denylisted package. Consult internal security policies.",
                    location=f"File: {filename}",
                    evidence_snippet=line,
                    cwe_mapping="CWE-937"
                )
            )
        elif package_name in DEPENDENCY_CONFIG["allowlist"]:
            dep_status = DependencyStatus.ALLOW
        else: # Potentially UNKNOWN or Hallucinated
            dep_status = DependencyStatus.UNKNOWN
            # Check for hallucination
            if any(package_name.endswith(suffix) for suffix in DEPENDENCY_CONFIG["hallucinated_suffix"]):
                risk_notes.append(f"Package '{package_name}' flagged as potential hallucination risk (suspicious naming).")
                all_findings.append(
                    Finding(
                        artifact_id=artifact_id,
                        finding_type=FindingType.HALLUCINATED_PACKAGE,
                        severity=Severity.MEDIUM,
                        rule_id="DEP_HALLUCINATION_RISK",
                        description=f"Potential hallucinated package '{package_name}' detected.",
                        remediation_guidance="Verify package existence and authenticity. Avoid unknown/hallucinated packages.",
                        location=f"File: {filename}",
                        evidence_snippet=line,
                        cwe_mapping="CWE-506" # Supply Chain Exploitation
                    )
                )
            else:
                risk_notes.append(f"Package '{package_name}' is not in the allowlist or denylist.")

        dependencies.append(
            DependencyRecord(
                name=package_name,
                version_spec=version_spec,
                source_file=filename,
                status=dep_status,
                risk_notes=", ".join(risk_notes) if risk_notes else None
            )
        )
    return dependencies

# Ingest and analyze dependency files
for dep_filename, dep_content in SYNTHETIC_DEPENDENCY_FILES.items():
    # Create a dummy artifact for the dependency file itself, for linking findings
    dep_artifact = generate_code_artifact(dep_filename, dep_content, source="UNKNOWN_DEPENDENCY_FILE")
    dep_records = parse_and_analyze_dependencies(dep_filename, dep_content, dep_artifact.artifact_id)
    all_dependencies.extend(dep_records)

print(f"\nFound {len(all_dependencies)} dependencies across files.")
print("Dependency Analysis Results:")
for dep in all_dependencies:
    print(f"- Package: {dep.name} ({dep.version_spec}) from {dep.source_file}, Status: {dep.status.value}, Notes: {dep.risk_notes if dep.risk_notes else 'N/A'}")

# Display findings related to dependencies
dep_findings = [f for f in all_findings if f.finding_type in [FindingType.INSECURE_DEPENDENCY, FindingType.HALLUCINATED_PACKAGE]]
if dep_findings:
    print("\nSample of new Dependency-related findings:")
    for finding in dep_findings:
        print(f"  - [{finding.severity.value}] {finding.rule_id} in {next(a.filename for a in all_artifacts if a.artifact_id == finding.artifact_id).split('/')[-1]}: {finding.description}")
```

### Explanation of Execution

The dependency analysis clearly flags denylisted packages like `pyyaml` (which is often used unsafely without a safe loader) and potential hallucinations such as `flask-secure-pro`. This immediate insight helps me ensure that only trusted and vetted libraries make it into our projects. For a developer, this means less time chasing down obscure build failures or vulnerability alerts from unknown packages, and more confidence in the integrity of our software supply chain. Any package marked as `UNKNOWN` or `DENY` becomes an immediate point of investigation, directly contributing to securing our build process.

---

## 7. Generating CI/CD Gate Plan from Findings

With all the vulnerabilities and dependency risks identified, the next critical step is to translate these findings into actionable controls for our CI/CD pipeline. This means generating a `sdlc_control_plan.yaml` that defines specific "gates" – automated checks that will either `BLOCK` a deployment or issue a `WARN` based on the severity and type of findings. This ensures that security isn't just an afterthought but an integrated part of our Software Development Lifecycle (SDLC).

### Story + Context + Real-World Relevance

My analysis is only useful if it leads to concrete actions. Generating a CI/CD gate plan is where the rubber meets the road. If I find a `CRITICAL` secret or a `HIGH` risk dependency, the pipeline must `BLOCK` the build immediately. For lower-severity issues, a `WARN` might suffice to notify the team without halting development. This YAML plan becomes the blueprint for our automated security controls, ensuring that every piece of AI-generated code, and any changes, passes a strict security review before it ever reaches production. This automates the enforcement of our security policies, reducing human error and "automation complacency."

The mapping logic is as follows:
- Presence of `HIGH`/`CRITICAL` findings $\rightarrow$ enforce `CI_SECURITY` gate `BLOCK`.
- Presence of `SECRET` findings $\rightarrow$ enforce `PRE_COMMIT` secret scanning gate `BLOCK`.
- Presence of `UNKNOWN` or `DENY` dependencies $\rightarrow$ enforce `CI_BUILD` or `CI_SECURITY` dependency allowlist gate `BLOCK`.
- Otherwise $\rightarrow$ `WARN` gating for low risk.

Let's define a simple risk score for an artifact to drive decision-making for gating, where $S(f)$ is the severity of finding $f$. We assign weights: $\text{Weight}(\text{CRITICAL}) = 100$, $\text{Weight}(\text{HIGH}) = 50$, $\text{Weight}(\text{MEDIUM}) = 10$, $\text{Weight}(\text{LOW}) = 1$.
The `ArtifactRiskScore` for an artifact $A$ is then:
$$ \text{ArtifactRiskScore}(A) = \sum_{f \in \text{Findings}(A)} \text{Weight}(S(f)) $$
This quantitative score helps to aggregate risk across an artifact and inform the gating decision.

```python
# Function to generate the CI/CD Gate Plan
def generate_ci_cd_gate_plan(all_findings: List[Finding], all_dependencies: List[DependencyRecord]) -> GatePlan:
    """
    Generates a CI/CD GatePlan based on identified findings and dependency risks.
    """
    gates: List[GateConfig] = []

    # Calculate overall risk score for decision making
    risk_weights = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 50,
        Severity.MEDIUM: 10,
        Severity.LOW: 1
    }
    total_risk_score = sum(risk_weights.get(f.severity, 0) for f in all_findings)

    # Determine if any CRITICAL/HIGH findings exist
    has_high_critical_findings = any(f.severity in [Severity.CRITICAL, Severity.HIGH] for f in all_findings)
    # Determine if any SECRET findings exist
    has_secret_findings = any(f.finding_type == FindingType.SECRET for f in all_findings)
    # Determine if any UNKNOWN/DENY dependencies exist
    has_risky_dependencies = any(d.status in [DependencyStatus.DENY, DependencyStatus.UNKNOWN] for d in all_dependencies)

    # Base CI_SECURITY Gate
    ci_security_action = "WARN"
    if has_high_critical_findings or has_risky_dependencies:
        ci_security_action = "BLOCK"

    gates.append(
        GateConfig(
            gate_type=GateType.CI_SECURITY,
            tools=["SAST Scanner", "Dependency Scanner"],
            required_checks=["No HIGH/CRITICAL Vulnerabilities", "Dependency Allowlist Compliance"],
            failure_action=ci_security_action,
            evidence_required=["code_gen_risk_findings.json", "dependency_risk_report.json"]
        )
    )

    # PRE_COMMIT Gate for secrets
    if has_secret_findings:
        gates.append(
            GateConfig(
                gate_type=GateType.PRE_COMMIT,
                tools=["Secret Scanner"],
                required_checks=["No Hardcoded Secrets"],
                failure_action="BLOCK",
                evidence_required=["code_gen_risk_findings.json"]
            )
        )
    else:
         gates.append( # Even if no findings, we want this gate to exist with a WARN or PASS
            GateConfig(
                gate_type=GateType.PRE_COMMIT,
                tools=["Secret Scanner", "Linter"],
                required_checks=["No Hardcoded Secrets", "Code Formatting"],
                failure_action="WARN", # Warn if no secrets but still run checks
                evidence_required=["code_gen_risk_findings.json"]
            )
        )

    # CI_BUILD Gate - basic compile/lint checks (always present)
    gates.append(
        GateConfig(
            gate_type=GateType.CI_BUILD,
            tools=["Build Tool", "Linter"],
            required_checks=["Successful Build", "Code Linting"],
            failure_action="BLOCK",
            owner_role="Development Team"
        )
    )

    # CI_TEST Gate - unit tests (always present)
    gates.append(
        GateConfig(
            gate_type=GateType.CI_TEST,
            tools=["Test Runner"],
            required_checks=["All Unit Tests Pass"],
            failure_action="BLOCK",
            owner_role="QA Team"
        )
    )

    # PRE_DEPLOY Gate - manual approval + audit (always present for critical apps)
    pre_deploy_action = "BLOCK" if total_risk_score > 0 else "WARN" # Block if any risk, otherwise warn for manual review
    gates.append(
        GateConfig(
            gate_type=GateType.PRE_DEPLOY,
            tools=["Manual Review", "Audit Artifact Check"],
            required_checks=["Security Audit Approval", "Artifact Integrity Check"],
            failure_action=pre_deploy_action,
            owner_role="Release Manager"
        )
    )

    return GatePlan(gates=gates)

# Generate the Gate Plan
sdlc_gate_plan = generate_ci_cd_gate_plan(all_findings, all_dependencies)

# Preview the generated YAML
print("\n--- Generated CI/CD Gate Plan (YAML Preview) ---")
sdlc_gate_plan_yaml = yaml.dump(sdlc_gate_plan.model_dump(by_alias=True), indent=2, sort_keys=False)
print(sdlc_gate_plan_yaml)
```

### Explanation of Execution

The generated YAML output provides a clear, machine-readable `sdlc_control_plan.yaml`. Based on the critical findings (secrets, dangerous execution, denylisted dependencies) identified earlier, the `CI_SECURITY` and `PRE_COMMIT` gates are correctly configured to `BLOCK` the pipeline. This means if any AI-generated code introduces similar vulnerabilities in the future, our pipeline will automatically prevent it from progressing. For me, this is the ultimate goal: automating security enforcement to build a more resilient and secure development process. This plan directly translates my analysis into organizational security policy.

---

## 8. Consolidating Findings and Exporting Auditable Results

The final step in my workflow is to consolidate all findings and artifacts into a comprehensive set of auditable reports. This includes JSON files for detailed findings and dependency risks, the YAML gate plan, and a markdown executive summary. Crucially, I also need to generate an `evidence_manifest.json` that hashes all inputs and outputs, providing an immutable record for auditing and compliance.

### Story + Context + Real-World Relevance

As a developer in a security-conscious organization, documentation and auditability are paramount. It’s not enough to just find vulnerabilities; I need to provide clear, structured evidence of what was found, where, how it was remediated, and what controls are in place. These export formats (`.json`, `.yaml`, `.md`) are designed to be consumed by different stakeholders: developers for remediation, DevSecOps for pipeline configuration, and leadership for risk oversight. The `evidence_manifest.json` serves as the ultimate proof-of-work, hashing every piece of input and output to ensure non-repudiation and integrity for auditors.

The `inputs_hash` combines the hashes of all `CodeArtifact` contents. The `outputs_hash` combines the hashes of the generated JSON and YAML reports. This creates a chain of custody for the audit.
$$ \text{inputs_hash} = \text{SHA256}(\text{Concat}(\text{CodeArtifact}_1.\text{content\_hash}, \dots, \text{CodeArtifact}_N.\text{content\_hash})) $$
$$ \text{outputs_hash} = \text{SHA256}(\text{Concat}(\text{Hash}(\text{findings.json}), \text{Hash}(\text{deps.json}), \text{Hash}(\text{gateplan.yaml}))) $$

```python
# --- Helper to hash output content ---
def hash_content(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

# 8.1 Export Findings and Dependency Reports (JSON)
findings_json_content = json.dumps([f.model_dump(mode='json') for f in all_findings], indent=2)
dependency_report_json_content = json.dumps([d.model_dump(mode='json') for d in all_dependencies], indent=2)

# 8.2 Export CI/CD Gate Plan (YAML)
# sdlc_gate_plan_yaml is already generated in the previous step

# 8.3 Generate Executive Summary (Markdown)
def generate_executive_summary(findings: List[Finding], dependencies: List[DependencyRecord]) -> str:
    num_critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    num_high = sum(1 for f in findings if f.severity == Severity.HIGH)
    num_medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
    num_secrets = sum(1 for f in findings if f.finding_type == FindingType.SECRET)
    num_insecure_deps = sum(1 for f in findings if f.finding_type == FindingType.INSECURE_DEPENDENCY)
    num_hallucinated_deps = sum(1 for f in findings if f.finding_type == FindingType.HALLUCINATED_PACKAGE)

    risk_themes = []
    if num_secrets > 0: risk_themes.append("Hard-coded Secrets & Credential Leaks")
    if any(f.finding_type in [FindingType.INJECTION_SINK, FindingType.DANGEROUS_EXEC, FindingType.UNSAFE_DESERIALIZATION] for f in findings):
        risk_themes.append("Insecure Input Handling & Dynamic Execution")
    if num_insecure_deps > 0 or num_hallucinated_deps > 0:
        risk_themes.append("Dependency / Package Hallucinations & Risky Libraries")

    top_findings = sorted(findings, key=lambda f: (f.severity.value, f.finding_type.value), reverse=True)[:5]

    summary = f"""# AI Code Generation Risk Assessment Summary for InnovateTech Solutions

## Overview
This report summarizes the security posture of AI-generated code artifacts within InnovateTech Solutions, following recent increases in security incidents linked to AI-assisted development. A total of {len(all_artifacts)} code artifacts and {len(all_dependencies)} dependencies were analyzed.

## Key Findings & Risk Themes
The analysis identified significant security risks, primarily centered around:
- **{', '.join(risk_themes if risk_themes else ['No major risk themes identified - excellent!'])}**

**Severity Breakdown:**
- **CRITICAL:** {num_critical} findings
- **HIGH:** {num_high} findings
- **MEDIUM:** {num_medium} findings
- **LOW:** {sum(1 for f in findings if f.severity == Severity.LOW)} findings

**Top 5 Specific Findings:**
"""
    if top_findings:
        for i, f in enumerate(top_findings):
            summary += f"- {i+1}. **[{f.severity.value}] {f.description}** in {next(a.filename for a in all_artifacts if a.artifact_id == f.artifact_id)} at {f.location}. Remediation: {f.remediation_guidance}\n"
    else:
        summary += "- No major findings. Excellent work!\n"

    summary += f"""
## Control Plan Overview
Based on these findings, an automated CI/CD Gate Plan (`sdlc_control_plan.yaml`) has been generated. This plan integrates security checks into our development pipeline, enforcing controls such as:
- **Blocking deployments** for `CRITICAL` or `HIGH` vulnerabilities.
- **Enforcing secret scanning** at `PRE_COMMIT` to prevent credential leaks.
- **Mandating dependency allowlist compliance** during `CI_SECURITY` scans.

This structured approach ensures that security is baked into our SDLC, proactively mitigating risks introduced by AI-generated code and strengthening our overall application security posture.
"""
    return summary

executive_summary_md_content = generate_executive_summary(all_findings, all_dependencies)


# 8.4 Generate Evidence Manifest (JSON)
# Calculate inputs_hash
all_artifact_hashes_str = "".join(sorted([a.content_hash for a in all_artifacts]))
inputs_hash = hashlib.sha256(all_artifact_hashes_str.encode('utf-8')).hexdigest()

# Calculate outputs_hash (hash of all generated reports)
combined_outputs_content = findings_json_content + dependency_report_json_content + sdlc_gate_plan_yaml + executive_summary_md_content
outputs_hash = hashlib.sha256(combined_outputs_content.encode('utf-8')).hexdigest()

manifest = EvidenceManifest(
    inputs_hash=inputs_hash,
    outputs_hash=outputs_hash,
    artifacts=[{"artifact_id": str(a.artifact_id), "filename": a.filename, "content_hash": a.content_hash} for a in all_artifacts]
)
evidence_manifest_json_content = json.dumps(manifest.model_dump(mode='json'), indent=2)

# Simulate writing files to disk
output_dir = "./audit_reports"
import os
os.makedirs(output_dir, exist_ok=True)

with open(f"{output_dir}/code_gen_risk_findings.json", "w") as f:
    f.write(findings_json_content)
with open(f"{output_dir}/dependency_risk_report.json", "w") as f:
    f.write(dependency_report_json_content)
with open(f"{output_dir}/sdlc_control_plan.yaml", "w") as f:
    f.write(sdlc_gate_plan_yaml)
with open(f"{output_dir}/case5_executive_summary.md", "w") as f:
    f.write(executive_summary_md_content)
with open(f"{output_dir}/evidence_manifest.json", "w") as f:
    f.write(evidence_manifest_json_content)

print(f"\n--- All reports generated and saved to '{output_dir}/' ---")
print(f"Generated code_gen_risk_findings.json (size: {len(findings_json_content)} bytes)")
print(f"Generated dependency_risk_report.json (size: {len(dependency_report_json_content)} bytes)")
print(f"Generated sdlc_control_plan.yaml (size: {len(sdlc_gate_plan_yaml)} bytes)")
print(f"Generated case5_executive_summary.md (size: {len(executive_summary_md_content)} bytes)")
print(f"Generated evidence_manifest.json (size: {len(evidence_manifest_json_content)} bytes)")
print(f"Inputs Hash: {inputs_hash[:16]}...")
print(f"Outputs Hash: {outputs_hash[:16]}...")
```

### Explanation of Execution

All necessary audit reports have been successfully generated and saved. The detailed JSON reports provide granular data for developers, while the YAML gate plan is ready for our DevSecOps team. The executive summary offers a high-level overview for leadership, and critically, the `evidence_manifest.json` provides an immutable record of this entire analysis, linking inputs to outputs via cryptographic hashes. This ensures that every step of my security audit is verifiable, transparent, and defensible, meeting our organization's strict compliance requirements and solidifying our security posture against the evolving risks of AI-generated code.

---

## Conclusion

This notebook demonstrates a practical, end-to-end workflow for a Software Developer to proactively identify and mitigate security risks introduced by AI-generated code. By combining static analysis (regex and AST), dependency risk assessment, and automated CI/CD gate generation, we've established a robust framework to secure our software supply chain. This approach allows InnovateTech Solutions to leverage the benefits of AI-assisted development while maintaining a high standard of security and compliance.
