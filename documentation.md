id: 696e4092f1dd2fc1624a167e_documentation
summary: Case Study 5: AI-Powered Code Generation Risk Assessment + Secure SDLC Controls Documentation
feedback link: https://docs.google.com/forms/d/e/1FAIpQLSfWkOK-in_bMMoHSZfcIvAeO58PAH9wrDqcxnJABHaxiDqhSA/viewform?usp=sf_link
environments: Web
status: Published
# QuLab: AI-Powered Code Generation Risk Assessment + Secure SDLC Controls

## 1. Introduction and Application Overview
Duration: 0:10:00

<aside class="positive">
Welcome to this codelab! This initial step is crucial for understanding the **"why"** behind the application. We'll set the context for the problem we're solving and highlight the key security concepts involved.
</aside>

As a developer at "InnovateTech Solutions" using AI code assistants, I've observed a significant uptick in security incidents stemming from AI-generated code. Issues range from hard-coded secrets to vulnerable dependencies, threatening our product integrity and customer trust. My core mission is to integrate robust security practices into our AI-accelerated development workflow.

This application, **QuLab: Case Study 5: AI-Powered Code Generation Risk Assessment + Secure SDLC Controls**, simulates a proactive approach to identifying and mitigating these risks *before* they reach production. It demonstrates how to perform thorough static analysis, assess third-party dependencies, and integrate strong security gates into CI/CD pipelines.

The codelab will guide you through the functionalities of this Streamlit application, focusing on:
*   **Structured Data Models:** Using Pydantic for robust, type-safe representation of code artifacts, findings, and controls.
*   **Code Ingestion:** Handling various code inputs (snippets, files, zip archives) and generating auditable `CodeArtifact`s with content hashes.
*   **Static Analysis:** Identifying vulnerabilities using both regex-based and Abstract Syntax Tree (AST)-based scanning.
*   **Dependency Analysis:** Assessing third-party packages for known risks, denylisted entries, and AI hallucinations.
*   **CI/CD Gate Plan Generation:** Automatically creating a `sdlc_control_plan.yaml` to enforce security policies based on analysis findings.
*   **Auditable Exports:** Generating comprehensive reports and an `evidence_manifest.json` for compliance and non-repudiation.

This application is important because it addresses the growing challenge of securing software development in an era of ubiquitous AI code generation. It empowers developers to build secure applications by integrating security early and continuously within the SDLC.

### Application Architecture and Flow

The application follows a sequential flow, broken down into distinct stages accessible via the sidebar navigation. Each stage contributes to a comprehensive security assessment and control generation.

1.  **Code Ingestion**: Users provide code via text input or file uploads (Python, `requirements.txt`, `.toml`, `.zip`). Each piece of code is transformed into an immutable `CodeArtifact` with a unique ID and SHA256 content hash.
2.  **Static Analysis**: The ingested Python code artifacts are scanned using predefined regex patterns and AST rules to detect vulnerabilities like hardcoded secrets, dangerous execution, and insecure deserialization. Findings are recorded as `Finding` objects.
3.  **Dependency Analysis**: Dependency files (e.g., `requirements.txt`) are parsed. Packages are checked against internal allowlists/denylists, and heuristics are applied to detect potential AI "hallucinations." Records are stored as `DependencyRecord` objects, and specific risks are also recorded as `Finding` objects.
4.  **CI/CD Gate Plan Generation**: Based on the aggregated `Finding` and `DependencyRecord` data, an automated `SDLCGatePlan` is generated. This plan, represented as YAML, defines `BLOCK` or `WARN` actions for different CI/CD gates (e.g., `PRE_COMMIT`, `CI_SECURITY`, `CI_BUILD`).
5.  **Auditable Exports**: All generated reports (Findings JSON, Dependencies JSON, Gate Plan YAML, Executive Summary Markdown) are made available for download. A crucial `EvidenceManifest` JSON is also generated, containing cryptographic hashes of all inputs and outputs for auditing and compliance.

The application leverages `st.session_state` to maintain the analysis results across page navigations, providing a persistent and interactive experience for the user.

<aside class="positive">
Before diving into the details, you can run a demo analysis using synthetic data to get a feel for the application's output.
</aside>

If you haven't run an analysis yet, click the button below to generate a sample report:

```python
if not st.session_state.analysis_performed:
    st.info("No analysis has been performed yet. You can proceed to 'Code Input' to start, or click the button below to run an analysis on synthetic data for demonstration.")
    if st.button("Run Analysis with Synthetic Data (Demo)"):
        run_full_analysis()
        st.session_state.current_page = "Findings Dashboard"
        st.rerun()
```

## 2. Understanding Data Models
Duration: 0:08:00

<aside class="positive">
Well-defined data models are the backbone of any robust security analysis tool. They ensure consistency, type safety, and ease of integration. This step will introduce the core Pydantic models used throughout the application.
</aside>

As a Software Developer, I rely on well-defined structures to manage complex data, especially when dealing with security findings. Pydantic helps me create robust, type-safe data models for code artifacts, security findings, dependency records, and our CI/CD gate plans. This ensures consistency and makes it easier to process and export audit results.

My first step in building any robust analysis tool is defining the data structures that will hold my findings. This is crucial for maintaining clarity, ensuring data integrity, and facilitating easy export and integration with other systems. Using Pydantic means I'm not just storing data; I'm storing **structured, validated** data, which is essential for auditability and reliability in a security context. These models mirror the artifacts I'll be working with – code snippets, vulnerability findings, dependency information, and the final CI/CD gate configurations.

The `GateType` and `FindingType` enumerations, for example, define the standardized categories for our security checks and pipeline actions. This prevents ambiguity and ensures that everyone on the team understands the classification of risks and controls. The `Severity` enumeration allows for consistent risk prioritization, guiding our remediation efforts.

Here are the key Pydantic data models and enumerations defined in the `source.py` module, which are critical for the application's functionality:

```python
# From source.py
import hashlib
import uuid
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

# Enumerations for standardized values
class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class FindingType(str, Enum):
    HARDCODED_SECRET = "HARDCODED_SECRET"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    SQL_INJECTION = "SQL_INJECTION"
    DANGEROUS_EXECUTION = "DANGEROUS_EXECUTION"
    WEAK_CRYPTO = "WEAK_CRYPTO"
    OUTDATED_DEPENDENCY = "OUTDATED_DEPENDENCY"
    DENYLISTED_DEPENDENCY = "DENYLISTED_DEPENDENCY"
    HALLUCINATED_PACKAGE = "HALLUCINATED_PACKAGE"
    OTHER_VULNERABILITY = "OTHER_VULNERABILITY"

class GateType(str, Enum):
    PRE_COMMIT = "PRE_COMMIT"
    CI_BUILD = "CI_BUILD"
    CI_TEST = "CI_TEST"
    CI_SECURITY = "CI_SECURITY"
    CD_DEPLOY = "CD_DEPLOY"

class GateAction(str, Enum):
    BLOCK = "BLOCK"
    WARN = "WARN"
    PASS = "PASS"

# Pydantic Models for structured data
class CodeArtifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    content: str
    content_hash: str # SHA256 hash of content
    language: str # e.g., "python", "text", "toml"
    source: str # e.g., "COPILOT", "CLAUDE", "AGENT", "UNKNOWN"
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Finding(BaseModel):
    finding_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    artifact_id: str # Link to the CodeArtifact
    rule_id: str # e.g., "S101", "A201"
    finding_type: FindingType
    severity: Severity
    description: str
    location: str # e.g., "Line 4", "function process_data"
    evidence_snippet: str # The piece of code that triggered the finding
    remediation_guidance: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class DependencyRecord(BaseModel):
    dependency_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    artifact_id: str # Link to the CodeArtifact (e.g., requirements.txt)
    name: str
    version: Optional[str] = None
    status: str # e.g., "ALLOW", "DENY", "UNKNOWN", "HALLUCINATED"
    source_file: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

class SDLCGate(BaseModel):
    gate_type: GateType
    action: GateAction # BLOCK, WARN, PASS
    reason: str
    details: Optional[Dict[str, Any]] = None

class SDLCGatePlan(BaseModel):
    plan_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    gates: List[SDLCGate]
    summary: str
    overall_status: GateAction
    created_at: datetime = Field(default_factory=datetime.utcnow)

class EvidenceManifest(BaseModel):
    manifest_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    inputs_hash: str # Hash of all input artifacts
    outputs_hash: str # Hash of all generated reports
    artifacts: List[Dict[str, str]] # List of artifact_id, filename, content_hash
```

These Pydantic models serve as the schema for all the data our analysis will generate. When I process a code file, its metadata and content will conform to `CodeArtifact`. Any security issues found will be stored as `Finding` objects, complete with severity, description, and remediation advice. Dependencies found in files like `requirements.txt` will be structured as `DependencyRecord`s. This structured approach is critical for creating consistent, machine-readable security reports, which are invaluable for tracking risks and demonstrating compliance to auditors. The enumerations standardize our security vocabulary across the team.

The application also heavily utilizes `st.session_state` to preserve data across reruns and page changes in Streamlit:

```python
#  st.session_state Design (from main.py) 
if "current_page" not in st.session_state:
    st.session_state.current_page = "Application Overview"
if "code_input_text" not in st.session_state:
    st.session_state.code_input_text = ""
if "uploaded_files_data" not in st.session_state:
    st.session_state.uploaded_files_data = []
if "code_source_tag" not in st.session_state:
    st.session_state.code_source_tag = "UNKNOWN"
if "analysis_performed" not in st.session_state:
    st.session_state.analysis_performed = False

# States for storing analysis results
if "all_artifacts_state" not in st.session_state:
    st.session_state.all_artifacts_state = []
if "all_findings_state" not in st.session_state:
    st.session_state.all_findings_state = []
if "all_dependencies_state" not in st.session_state:
    st.session_state.all_dependencies_state = []
if "sdlc_gate_plan_state" not in st.session_state:
    st.session_state.sdlc_gate_plan_state = None
if "sdlc_gate_plan_yaml_state" not in st.session_state:
    st.session_state.sdlc_gate_plan_yaml_state = ""
if "findings_json_content_state" not in st.session_state:
    st.session_state.findings_json_content_state = ""
if "dependency_report_json_content_state" not in st.session_state:
    st.session_state.dependency_report_json_content_state = ""
if "executive_summary_md_content_state" not in st.session_state:
    st.session_state.executive_summary_md_content_state = ""
if "evidence_manifest_json_content_state" not in st.session_state:
    st.session_state.evidence_manifest_json_content_state = ""
if "inputs_hash_state" not in st.session_state:
    st.session_state.inputs_hash_state = ""
if "outputs_hash_state" not in st.session_state:
    st.session_state.outputs_hash_state = ""
```

These `st.session_state` variables hold the application's current state and all generated analysis results, ensuring that information is persisted even as the user navigates between different sections of the Streamlit application.

## 3. Code Ingestion and Artifact Generation
Duration: 0:15:00

<aside class="positive">
This is where we start interacting with the application. We'll learn how to feed code into the system and understand how it's transformed into auditable artifacts.
</aside>

As a developer, my first practical step is to get the code into a format I can analyze. This often means ingesting raw code snippets or files from a repository, creating a standard `CodeArtifact` record for each. This process includes generating a unique `artifact_id` and a content hash (SHA256). The content hash is particularly important for auditability; it's our digital fingerprint of the exact code state at the time of analysis, ensuring that our findings always refer to an immutable piece of evidence.

When AI assists in code generation, I need a reliable way to track exactly *which* code was analyzed. Imagine an AI generating 50 lines of code; I need to ensure that if a vulnerability is found, I can point directly to the exact version of that code. The `content_hash` serves as this unalterable reference. It’s a cryptographic integrity check, ensuring the code hasn't been tampered with since analysis. For instance, if an auditor later questions a finding, I can provide the hash and the corresponding code, proving the finding's validity against that specific version. The `artifact_id` provides a unique identifier for each piece of code, simplifying tracking across multiple analysis runs.

The SHA256 content hash $H$ for a code artifact $C$ is calculated as:
$$ H = \text{SHA256}(\text{UTF8Encode}(C)) $$
where $H$ is the SHA256 hash and $C$ is the code artifact content. This operation ensures that any change, no matter how small, to the code $C$ will result in a completely different hash $H$, making it an ideal tool for immutability and auditing.

### Navigating to "Code Input"

1.  In the sidebar, select **"Code Input"** from the "Go to" dropdown.

You'll see options to:
*   Tag the source of the code (e.g., `COPILOT`, `CLAUDE`).
*   Paste a code snippet directly.
*   Upload individual code files or a `.zip` archive containing multiple files.

The application automatically processes uploaded `.zip` files, extracting all contents and treating each file as a separate artifact.

### How `CodeArtifact`s are Generated

The core logic for artifact generation resides in the `source.generate_code_artifact` function:

```python
# From source.py (simplified)
import hashlib
import uuid
from datetime import datetime
from pydantic import BaseModel, Field # Assuming these are defined as above

class CodeArtifact(BaseModel):
    artifact_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    filename: str
    content: str
    content_hash: str
    language: str
    source: str
    created_at: datetime = Field(default_factory=datetime.utcnow)

# Global list (simulating source.all_artifacts in main.py)
all_artifacts_global: List[CodeArtifact] = []

def generate_code_artifact(filename: str, content: str, source_tag: str) -> CodeArtifact:
    """Generates a CodeArtifact from raw code content."""
    content_hash = hashlib.sha256(content.encode('utf-8')).hexdigest()
    # Simplified language detection
    if filename.endswith(".py"):
        language = "python"
    elif filename.endswith(".txt") or filename.endswith("requirements.txt"):
        language = "text"
    elif filename.endswith(".toml"):
        language = "toml"
    else:
        language = "unknown"

    artifact = CodeArtifact(
        filename=filename,
        content=content,
        content_hash=content_hash,
        language=language,
        source=source_tag
    )
    all_artifacts_global.append(artifact) # Add to a global list (or session state)
    return artifact
```

Each time you provide new code or files and click "Analyze Code", this function is called for every piece of code, converting it into a structured `CodeArtifact` and storing it in `st.session_state.all_artifacts_state`.

### Try It Out!

1.  **Tag the Source:** Select `COPILOT` for demonstration.
2.  **Paste Code Snippet:** Paste the following Python code into the text area:

    ```python
    import os
    API_KEY = "sk-example-super-secret-key-12345" # This is a hardcoded secret
    PASSWORD = "my_weak_password"

    def execute_command(user_input):
        eval(user_input) # Dangerous use of eval

    def generate_id(data):
        import hashlib
        return hashlib.md5(data.encode()).hexdigest() # Weak crypto
    ```
3.  **Upload Files (Optional):** You can also try uploading a `requirements.txt` file like this:
    ```
    requests==2.28.1
    flask-secure-pro==1.0.0 # This might be a hallucinated package
    pyyaml==5.4.1 # Often denylisted for unsafe usage
    ```
    Save this content to a file named `requirements.txt` and upload it.
4.  **Click "Analyze Code"**.

After the analysis, you'll see a table of **Generated Code Artifacts**, displaying their filenames, sources, and content hashes.

<aside class="positive">
Each `CodeArtifact` now has a unique `artifact_id` and an immutable `content_hash`. This is your foundation for all subsequent security analysis. If you need to trace back a finding, you can link it directly to this artifact and its immutable hash. This level of traceability is crucial for security compliance and incident response, ensuring that you can always verify the exact version of the code that was scanned.
</aside>

## 4. Static Analysis and Findings Dashboard
Duration: 0:15:00

<aside class="positive">
Now that we've ingested the code, it's time to find the vulnerabilities! This step focuses on the core static analysis capabilities and how findings are presented.
</aside>

I've successfully run our initial set of regex-based checks, followed by AST analysis. The output clearly shows several critical and high-severity findings, such as hard-coded API keys, potential SQL injection, dangerous dynamic execution (`eval()`, `subprocess.run(shell=True)`), and unsafe deserialization (`pickle.loads()`), along with the use of a weak cryptographic hash (MD5). These findings are particularly important because they represent high-impact vulnerabilities that a simple text search might miss or misinterpret.

For each finding, I get the exact line number and the snippet of code that triggered the rule, making it easy to pinpoint and verify the vulnerability. This immediate feedback helps me understand the attack surface generated by the AI and prioritize my remediation efforts. For instance, a `CRITICAL` secret finding would prompt an immediate action to remove the secret and implement a secure secret management solution.

Knowing that `pickle.loads` is explicitly called within the AST node provides definitive evidence of unsafe deserialization. This level of precision is invaluable for a developer, allowing me to trust the findings and focus on targeted remediation, preventing potential remote code execution or data corruption.

### Navigating to "Findings Dashboard"

1.  In the sidebar, select **"Findings Dashboard"** from the "Go to" dropdown.

If you performed the analysis in the previous step, you should now see a dashboard summarizing the identified security findings.

### Static Analysis Techniques

The application employs two primary static analysis techniques:

1.  **Regex-based Scanning**: Simple, fast pattern matching for common, easily identifiable patterns like hardcoded secrets or `eval()`.
2.  **AST-based Scanning**: More sophisticated analysis that inspects the Abstract Syntax Tree (AST) of the Python code. This allows for detection of vulnerabilities that depend on code structure and function calls, such as `subprocess.run(shell=True)` or `pickle.loads()`.

The `source.py` module contains functions like `find_vulnerabilities_regex` and `find_vulnerabilities_ast`:

```python
# From source.py (simplified)
import re
import ast
from typing import List, Dict, Any

# Assuming CodeArtifact and Finding models are defined as above
# And global list all_findings is available

STATIC_RULES = {
    "regex": [
        {"id": "S101", "type": FindingType.HARDCODED_SECRET, "severity": Severity.CRITICAL,
         "pattern": r"(api_key|secret|token|password)\s*=\s*['\"]\w{16,128}['\"]",
         "description": "Hardcoded secret found.", "remediation": "Use environment variables or a secrets manager."},
        {"id": "S102", "type": FindingType.DANGEROUS_EXECUTION, "severity": Severity.HIGH,
         "pattern": r"eval\(", "description": "Use of eval() detected.", "remediation": "Avoid eval() due to arbitrary code execution risks."},
        {"id": "S103", "type": FindingType.WEAK_CRYPTO, "severity": Severity.MEDIUM,
         "pattern": r"hashlib\.md5\(", "description": "Use of MD5 detected.", "remediation": "Use strong cryptographic hashes like SHA256."},
    ],
    "ast": [
        {"id": "A201", "type": FindingType.DANGEROUS_EXECUTION, "severity": Severity.HIGH,
         "func_name": "subprocess.run", "args_check": {"shell": True},
         "description": "subprocess.run with shell=True detected.", "remediation": "Avoid shell=True with untrusted input."},
        {"id": "A202", "type": FindingType.INSECURE_DESERIALIZATION, "severity": Severity.CRITICAL,
         "func_name": "pickle.loads", "args_check": {},
         "description": "pickle.loads detected, insecure deserialization risk.", "remediation": "Avoid pickle for untrusted data."},
    ]
}

def find_vulnerabilities_regex(artifact: CodeArtifact, rules: Dict[str, Any]):
    """Scans code using regex patterns."""
    if artifact.language != "python": return # Only scan python for now
    for rule in rules.get("regex", []):
        for i, line in enumerate(artifact.content.splitlines()):
            if re.search(rule["pattern"], line):
                finding = Finding(
                    artifact_id=artifact.artifact_id,
                    rule_id=rule["id"],
                    finding_type=rule["type"],
                    severity=rule["severity"],
                    description=rule["description"],
                    location=f"Line {i+1}",
                    evidence_snippet=line.strip(),
                    remediation_guidance=rule["remediation"]
                )
                st.session_state.all_findings_state.append(finding) # Store in session state

def find_vulnerabilities_ast(artifact: CodeArtifact, rules: Dict[str, Any]):
    """Scans code using Abstract Syntax Tree (AST) analysis."""
    if artifact.language != "python": return
    try:
        tree = ast.parse(artifact.content)
        for node in ast.walk(tree):
            # Example: subprocess.run(..., shell=True)
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
               node.func.attr == 'run' and isinstance(node.func.value, ast.Name) and \
               node.func.value.id == 'subprocess':
                # Check for shell=True argument
                for keyword in node.keywords:
                    if keyword.arg == 'shell' and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                        rule = next((r for r in rules.get("ast", []) if r.get("id") == "A201"), None)
                        if rule:
                            finding = Finding(
                                artifact_id=artifact.artifact_id,
                                rule_id=rule["id"],
                                finding_type=rule["type"],
                                severity=rule["severity"],
                                description=rule["description"],
                                location=f"Line {node.lineno}",
                                evidence_snippet=ast.get_source_segment(artifact.content, node) or "",
                                remediation_guidance=rule["remediation"]
                            )
                            st.session_state.all_findings_state.append(finding)
            # Example: pickle.loads()
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and \
               node.func.attr == 'loads' and isinstance(node.func.value, ast.Name) and \
               node.func.value.id == 'pickle':
                rule = next((r for r in rules.get("ast", []) if r.get("id") == "A202"), None)
                if rule:
                    finding = Finding(
                        artifact_id=artifact.artifact_id,
                        rule_id=rule["id"],
                        finding_type=rule["type"],
                        severity=rule["severity"],
                        description=rule["description"],
                        location=f"Line {node.lineno}",
                        evidence_snippet=ast.get_source_segment(artifact.content, node) or "",
                        remediation_guidance=rule["remediation"]
                    )
                    st.session_state.all_findings_state.append(finding)
    except SyntaxError as e:
        st.warning(f"Syntax error in {artifact.filename}: {e}")
    except Exception as e:
        st.error(f"Error during AST analysis for {artifact.filename}: {e}")
```

The `run_full_analysis` function orchestrates these scans:

```python
# From main.py (excerpt)
def run_full_analysis():
    # ... artifact generation ...
    artifacts_for_sast = [a for a in source.all_artifacts if a.language == "python" and not a.filename.endswith(('.txt', '.toml', '.json'))]
    
    for artifact in artifacts_for_sast:
        source.find_vulnerabilities_regex(artifact, source.STATIC_RULES)
    for artifact in artifacts_for_sast:
        source.find_vulnerabilities_ast(artifact, source.STATIC_RULES)
    # ... rest of analysis ...
    st.session_state.all_findings_state = list(source.all_findings) # Update session state
    st.session_state.analysis_performed = True
    st.success("Analysis complete!")
```

The "Findings Dashboard" displays the collected `Finding` objects, allowing you to filter by `Severity` and `Finding Type`. Selecting a specific finding provides detailed information, including the `evidence_snippet` and `remediation_guidance`.

## 5. Dependency Risk Assessment
Duration: 0:12:00

<aside class="positive">
AI-generated code isn't just about the code itself; it's also about the ecosystem of dependencies it suggests. This step focuses on identifying risks in third-party libraries.
</aside>

AI code assistants can generate `requirements.txt` or `pyproject.toml` entries that might include outdated, insecure, or even entirely fabricated (hallucinated) packages. As a Software Developer, reviewing dependencies is a crucial part of securing the supply chain. I need to ensure that all packages conform to our organization's approved lists and flag any suspicious entries that could be hallucinations.

Supply chain attacks are a major threat, and AI can inadvertently contribute by suggesting insecure or non-existent packages. My role involves parsing these dependency files and comparing them against our internal `allowlist` (approved packages) and `denylist` (known risky packages). Beyond that, AI sometimes "hallucinates" packages that don't exist or have misleading names (e.g., `requests-pro`). Detecting these hallucinations is vital to prevent developers from unknowingly installing malicious or non-functional libraries. This step directly mitigates supply chain risks.

The process involves:
*   Parsing the dependency file to extract package names and versions.
*   Checking against the `allowlist` and `denylist`.
*   Applying heuristics (like custom suffixes) to detect potential `hallucinated_package` risks.

### Navigating to "Dependency Analyzer"

1.  In the sidebar, select **"Dependency Analyzer"** from the "Go to" dropdown.

Here, you'll see a table summarizing all detected dependencies and their statuses.

### How Dependencies are Analyzed

The `source.parse_and_analyze_dependencies` function is responsible for this task:

```python
# From source.py (simplified)
import re
from typing import List, Dict, Any

# Assuming CodeArtifact, Finding, DependencyRecord models are defined
# And global lists all_dependencies, all_findings are available
# And DEPENDENCY_ALLOWLIST, DEPENDENCY_DENYLIST are defined

DEPENDENCY_ALLOWLIST = ["requests", "pandas", "numpy", "streamlit"]
DEPENDENCY_DENYLIST = ["pyyaml", "unsafe-package-xyz"]

def parse_and_analyze_dependencies(filename: str, content: str, artifact_id: str):
    """Parses dependency files and checks packages against allow/denylists and for hallucinations."""
    packages = []
    if filename.endswith("requirements.txt"):
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                match = re.match(r"([\w.-]+)(==|>=|<=|>|<|~=)?([\w.]+)?", line)
                if match:
                    pkg_name = match.group(1)
                    pkg_version = match.group(3)
                    packages.append({"name": pkg_name, "version": pkg_version})
    # Future: Add support for pyproject.toml etc.

    for pkg in packages:
        status = "UNKNOWN"
        # Check against allowlist
        if pkg["name"].lower() in [p.lower() for p in DEPENDENCY_ALLOWLIST]:
            status = "ALLOW"
        # Check against denylist
        elif pkg["name"].lower() in [p.lower() for p in DEPENDENCY_DENYLIST]:
            status = "DENY"

        # Hallucination detection heuristic: common AI suffix, or non-alphanumeric patterns
        # Also ensure it's not in an allow/denylist already to avoid false positives
        if re.search(r"(-pro|-ai|-enterprise|secure-pro|gpt)", pkg["name"].lower()) and \
           pkg["name"].lower() not in [p.lower() for p in DEPENDENCY_ALLOWLIST + DEPENDENCY_DENYLIST]:
            status = "HALLUCINATED"
            # If a hallucination, also add a security finding
            finding = Finding(
                artifact_id=artifact_id,
                rule_id="DEP_H01",
                finding_type=FindingType.HALLUCINATED_PACKAGE,
                severity=Severity.HIGH,
                description=f"Potential hallucinated package '{pkg['name']}' detected.",
                location=f"File: {filename}",
                evidence_snippet=pkg["name"],
                remediation_guidance="Verify if this package truly exists and is legitimate. Avoid installing unverified packages."
            )
            st.session_state.all_findings_state.append(finding) # Add to general findings

        dep_record = DependencyRecord(
            artifact_id=artifact_id,
            name=pkg["name"],
            version=pkg["version"],
            status=status,
            source_file=filename
        )
        st.session_state.all_dependencies_state.append(dep_record) # Store in session state
```

The "Dependency Analyzer" displays the `DependencyRecord` objects. It also explicitly flags any packages identified as "Hallucination Risk" by linking them to `FindingType.HALLUCINATED_PACKAGE` findings.

<aside class="positive">
The dependency analysis clearly flags denylisted packages like `pyyaml` (which is often used unsafely without a safe loader) and potential hallucinations such as `flask-secure-pro`. This immediate insight helps me ensure that only trusted and vetted libraries make it into our projects. For a developer, this means less time chasing down obscure build failures or vulnerability alerts from unknown packages, and more confidence in the integrity of our software supply chain. Any package marked as `UNKNOWN` or `DENY` becomes an immediate point of investigation, directly contributing to securing our build process.
</aside>

## 6. CI/CD Gate Plan Generation
Duration: 0:10:00

<aside class="positive">
Identifying vulnerabilities is only half the battle. This step shows how to translate those findings into actionable, automated security controls within your CI/CD pipeline.
</aside>

With all the vulnerabilities and dependency risks identified, the next critical step is to translate these findings into actionable controls for our CI/CD pipeline. This means generating a `sdlc_control_plan.yaml` that defines specific "gates" – automated checks that will either `BLOCK` a deployment or issue a `WARN` based on the severity and type of findings. This ensures that security isn't just an afterthought but an integrated part of our Software Development Lifecycle (SDLC).

My analysis is only useful if it leads to concrete actions. Generating a CI/CD gate plan is where the rubber meets the road. If I find a `CRITICAL` secret or a `HIGH` risk dependency, the pipeline must `BLOCK` the build immediately. For lower-severity issues, a `WARN` might suffice to notify the team without halting development. This YAML plan becomes the blueprint for our automated security controls, ensuring that every piece of AI-generated code, and any changes, passes a strict security review before it ever reaches production. This automates the enforcement of our security policies, reducing human error and "automation complacency."

The mapping logic is as follows:
*   Presence of `HIGH`/`CRITICAL` findings $\rightarrow$ enforce `CI_SECURITY` gate `BLOCK`.
*   Presence of `HARDCODED_SECRET` findings $\rightarrow$ enforce `PRE_COMMIT` secret scanning gate `BLOCK`.
*   Presence of `UNKNOWN` or `DENY` dependencies $\rightarrow$ enforce `CI_BUILD` or `CI_SECURITY` dependency allowlist gate `BLOCK`.
*   Otherwise $\rightarrow$ `WARN` or `PASS` gating allowed for low risk.

Let's define a simple risk score for an artifact to drive decision-making for gating, where $S(f)$ is the severity of finding $f$. We assign weights: $\text{Weight}(\text{CRITICAL}) = 100$, $\text{Weight}(\text{HIGH}) = 50$, $\text{Weight}(\text{MEDIUM}) = 10$, $\text{Weight}(\text{LOW}) = 1$.
The `ArtifactRiskScore` for an artifact $A$ is then:
$$ \text{ArtifactRiskScore}(A) = \sum_{f \in \text{Findings}(A)} \text{Weight}(S(f)) $$
where $A$ represents a code artifact, $f$ represents a finding, $S(f)$ is the severity of finding $f$, and $\text{Weight}(S(f))$ is the assigned weight for that severity. This quantitative score helps to aggregate risk across an artifact and inform the gating decision.

### Navigating to "Gate Plan Generator"

1.  In the sidebar, select **"Gate Plan Generator"** from the "Go to" dropdown.

You will see the generated YAML output, which can be directly integrated into your CI/CD pipeline configuration.

### How the Gate Plan is Generated

The `source.generate_ci_cd_gate_plan` function takes all identified findings and dependencies to produce the `SDLCGatePlan`:

```python
# From source.py (simplified)
from typing import List
import yaml

# Assuming SDLCGatePlan, SDLCGate, GateAction, GateType, Severity, FindingType models are defined
# And Findings and Dependencies lists are passed

def generate_ci_cd_gate_plan(findings: List[Finding], dependencies: List[DependencyRecord]) -> SDLCGatePlan:
    """Generates an SDLC Gate Plan based on findings and dependencies."""
    gates = []
    overall_action = GateAction.PASS
    summary_messages = []

    # Severity weights for risk scoring
    severity_weights = {
        Severity.CRITICAL: 100,
        Severity.HIGH: 50,
        Severity.MEDIUM: 10,
        Severity.LOW: 1,
        Severity.INFO: 0
    }
    total_risk_score = sum(severity_weights.get(f.severity, 0) for f in findings)

    # PRE_COMMIT gate for secrets
    secret_findings = [f for f in findings if f.finding_type == FindingType.HARDCODED_SECRET]
    if secret_findings:
        gates.append(SDLCGate(gate_type=GateType.PRE_COMMIT, action=GateAction.BLOCK,
                              reason="Hardcoded secrets detected.",
                              details={"finding_ids": [f.finding_id for f in secret_findings]}))
        overall_action = GateAction.BLOCK
        summary_messages.append("Pre-commit gate blocking due to hardcoded secrets.")
    else:
        gates.append(SDLCGate(gate_type=GateType.PRE_COMMIT, action=GateAction.PASS,
                              reason="No hardcoded secrets detected."))

    # CI_SECURITY gate for critical/high vulnerabilities
    critical_high_findings = [f for f in findings if f.severity in [Severity.CRITICAL, Severity.HIGH]]
    if critical_high_findings:
        gates.append(SDLCGate(gate_type=GateType.CI_SECURITY, action=GateAction.BLOCK,
                              reason="Critical or High severity security findings detected.",
                              details={"finding_ids": [f.finding_id for f in critical_high_findings], "risk_score": total_risk_score}))
        overall_action = GateAction.BLOCK
        summary_messages.append("CI Security gate blocking due to Critical/High findings.")
    elif total_risk_score > 20: # Example threshold for medium risk to warn
        gates.append(SDLCGate(gate_type=GateType.CI_SECURITY, action=GateAction.WARN,
                              reason="Medium severity security findings detected.",
                              details={"risk_score": total_risk_score}))
        if overall_action == GateAction.PASS: overall_action = GateAction.WARN
        summary_messages.append("CI Security gate warning due to Medium findings.")
    else:
        gates.append(SDLCGate(gate_type=GateType.CI_SECURITY, action=GateAction.PASS,
                              reason="No critical/high findings or significant risk score."))

    # CI_BUILD gate for dependencies
    denylisted_deps = [d for d in dependencies if d.status == "DENY"]
    hallucinated_deps = [d for d in dependencies if d.status == "HALLUCINATED"]
    if denylisted_deps or hallucinated_deps:
        gates.append(SDLCGate(gate_type=GateType.CI_BUILD, action=GateAction.BLOCK,
                              reason="Denylisted or potentially hallucinated dependencies detected.",
                              details={"denylisted": [d.name for d in denylisted_deps],
                                       "hallucinated": [d.name for d in hallucinated_deps]}))
        overall_action = GateAction.BLOCK
        summary_messages.append("CI Build gate blocking due to insecure/hallucinated dependencies.")
    else:
        gates.append(SDLCGate(gate_type=GateType.CI_BUILD, action=GateAction.PASS,
                              reason="All dependencies appear safe."))

    final_summary = "Analysis completed. " + " ".join(summary_messages) if summary_messages else "Analysis completed. No significant risks found to block the pipeline."

    return SDLCGatePlan(gates=gates, summary=final_summary, overall_status=overall_action)
```

The output of this function is then converted to YAML format for display:

```python
# From main.py (excerpt)
sdlc_gate_plan = source.generate_ci_cd_gate_plan(source.all_findings, source.all_dependencies)
sdlc_gate_plan_yaml = yaml.dump(sdlc_gate_plan.model_dump(by_alias=True), indent=2, sort_keys=False)
st.session_state.sdlc_gate_plan_yaml_state = sdlc_gate_plan_yaml
```

<aside class="positive">
The generated YAML output provides a clear, machine-readable `sdlc_control_plan.yaml`. Based on the critical findings (secrets, dangerous execution, denylisted dependencies) identified earlier, the `CI_SECURITY` and `PRE_COMMIT` gates are correctly configured to `BLOCK` the pipeline. This means if any AI-generated code introduces similar vulnerabilities in the future, our pipeline will automatically prevent it from progressing. For me, this is the ultimate goal: automating security enforcement to build a more resilient and secure development process. This plan directly translates my analysis into organizational security policy.
</aside>

## 7. Exports and Evidence
Duration: 0:07:00

<aside class="positive">
The final, crucial step: consolidating all findings and generating auditable reports. This is essential for compliance, collaboration, and maintaining a clear chain of evidence.
</aside>

The final step in my workflow is to consolidate all findings and artifacts into a comprehensive set of auditable reports. This includes JSON files for detailed findings and dependency risks, the YAML gate plan, and a markdown executive summary. Crucially, I also need to generate an `evidence_manifest.json` that hashes all inputs and outputs, providing an immutable record for auditing and compliance.

As a developer in a security-conscious organization, documentation and auditability are paramount. It’s not enough to just find vulnerabilities; I need to provide clear, structured evidence of what was found, where, how it was remediated, and what controls are in place. These export formats (`.json`, `.yaml`, `.md`) are designed to be consumed by different stakeholders: developers for remediation, DevSecOps for pipeline configuration, and leadership for risk oversight. The `evidence_manifest.json` serves as the ultimate proof-of-work, hashing every piece of input and output to ensure non-repudiation and integrity for auditors.

The `inputs_hash` combines the hashes of all `CodeArtifact` contents. The `outputs_hash` combines the hashes of the generated JSON and YAML reports. This creates a chain of custody for the audit.

The `inputs_hash` calculation:
$$ \text{inputs\_hash} = \text{SHA256}(\text{Concat}(\text{CodeArtifact}_1.\text{content\_hash}, \dots, \text{CodeArtifact}_N.\text{content\_hash})) $$
The `outputs_hash` calculation:
$$ \text{outputs\_hash} = \text{SHA256}(\text{Concat}(\text{Hash}(\text{findings.json}), \text{Hash}(\text{deps.json}), \text{Hash}(\text{gateplan.yaml}), \text{Hash}(\text{summary.md}))) $$

### Navigating to "Exports & Evidence"

1.  In the sidebar, select **"Exports & Evidence"** from the "Go to" dropdown.

Here, you'll find download buttons for all the generated reports and the overall analysis hashes.

### Report Generation and Evidence Manifest

The `run_full_analysis` function orchestrates the generation of these reports:

```python
# From main.py (excerpt)
def run_full_analysis():
    # ... previous analysis steps ...

    # Generate various reports
    findings_json_content = json.dumps([f.model_dump(mode='json') for f in source.all_findings], indent=2)
    dependency_report_json_content = json.dumps([d.model_dump(mode='json') for d in source.all_dependencies], indent=2)
    executive_summary_md_content = source.generate_executive_summary(source.all_findings, source.all_dependencies)
    # sdlc_gate_plan_yaml already generated in previous step

    # Calculate inputs and outputs hashes for evidence manifest
    all_artifact_hashes_str = "".join(sorted([a.content_hash for a in source.all_artifacts]))
    inputs_hash = hashlib.sha256(all_artifact_hashes_str.encode('utf-8')).hexdigest()

    combined_outputs_content = findings_json_content + dependency_report_json_content + sdlc_gate_plan_yaml + executive_summary_md_content
    outputs_hash = hashlib.sha256(combined_outputs_content.encode('utf-8')).hexdigest()

    # Create the Evidence Manifest
    manifest = source.EvidenceManifest(
        inputs_hash=inputs_hash,
        outputs_hash=outputs_hash,
        artifacts=[{"artifact_id": str(a.artifact_id), "filename": a.filename, "content_hash": a.content_hash} for a in source.all_artifacts]
    )
    evidence_manifest_json_content = json.dumps(manifest.model_dump(mode='json'), indent=2)

    # Store all generated content in session state
    st.session_state.findings_json_content_state = findings_json_content
    st.session_state.dependency_report_json_content_state = dependency_report_json_content
    st.session_state.executive_summary_md_content_state = executive_summary_md_content
    st.session_state.evidence_manifest_json_content_state = evidence_manifest_json_content
    st.session_state.inputs_hash_state = inputs_hash
    st.session_state.outputs_hash_state = outputs_hash
    st.session_state.analysis_performed = True
    st.success("Analysis complete!")
```

The `source.generate_executive_summary` function creates a human-readable markdown summary:

```python
# From source.py (simplified)
from collections import defaultdict

def generate_executive_summary(findings: List[Finding], dependencies: List[DependencyRecord]) -> str:
    """Generates a markdown executive summary of the analysis."""
    summary_md = "# Executive Summary: AI-Powered Code Risk Assessment\n\n"
    # ... content generation based on findings and dependencies ...
    return summary_md
```

You can download each of these reports using the provided buttons:

<button>
  [Download Findings JSON](data:application/json;base64,eyJzdGF0dXMiOiJkZW1vIn0=)
</button>
<button>
  [Download Dependencies JSON](data:application/json;base64,eyJzdGF0dXMiOiJkZW1vIn0=)
</button>
<button>
  [Download Gate Plan YAML](data:application/x-yaml;base64,c3RhdHVzOiBkZW1v)
</button>
<button>
  [Download Executive Summary MD](data:text/markdown;base64,IyBEZW1vIFN1bW1hcnkKCkEgZGVtbyBleGVjdXRpdmUgc3VtbWFyeS4=)
</button>
<button>
  [Download Evidence Manifest JSON](data:application/json;base64,eyJzdGF0dXMiOiJkZW1vIn0=)
</button>

The overall `Inputs Hash` and `Outputs Hash` are prominently displayed, providing a quick reference for the integrity of the analysis run.

<aside class="positive">
All necessary audit reports have been successfully generated and are available for download. The detailed JSON reports provide granular data for developers, while the YAML gate plan is ready for our DevSecOps team. The executive summary offers a high-level overview for leadership, and critically, the `evidence_manifest.json` provides an immutable record of this entire analysis, linking inputs to outputs via cryptographic hashes. This ensures that every step of my security audit is verifiable, transparent, and defensible, meeting our organization's strict compliance requirements and solidifying our security posture against the evolving risks of AI-generated code.
</aside>
