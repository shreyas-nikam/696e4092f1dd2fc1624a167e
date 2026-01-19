
# Streamlit Application Specification: AI Code-Gen Risk Analyzer + CI/CD Gate Generator

## 1. Application Overview

### Purpose of the Application

The "AI Code-Gen Risk Analyzer + CI/CD Gate Generator" Streamlit application serves as a critical tool for Software Developers and DevSecOps teams at "InnovateTech Solutions." Its primary purpose is to proactively identify and mitigate security risks introduced by AI-assisted code generation. The application performs comprehensive static analysis, assesses third-party dependencies for vulnerabilities and hallucination risks, and automatically generates an enterprise-grade CI/CD gate plan in YAML format. This process ensures that security is integrated into the Software Development Lifecycle (SDLC), preventing hard-coded secrets, insecure APIs, and supply chain vulnerabilities from reaching production, thereby bolstering product integrity and customer trust.

### High-level Story Flow of the Application

The application simulates the daily workflow of a Software Developer focused on securing AI-assisted code. The user navigates through a multi-page experience, moving from code ingestion to final audit report generation:

1.  **Code Input:** The developer starts by providing code—either by pasting snippets into a text editor or uploading individual files or zipped repositories. Each code input is tagged with its origin (e.g., Copilot, Claude, Agent) for traceability.
2.  **Analysis Execution:** Upon submission, the application performs a series of static analyses:
    *   **Regex-based checks:** Rapidly identifies hard-coded secrets (API keys, passwords) and common injection patterns (e.g., SQL f-strings).
    *   **AST-based checks:** Conducts deeper structural analysis to detect dangerous dynamic execution (`eval`, `subprocess.run(shell=True)`) and unsafe deserialization (`pickle.loads`).
3.  **Dependency Risk Assessment:** The application then parses dependency files (e.g., `requirements.txt`) to identify denylisted, unapproved (unknown), or potentially hallucinated packages, flagging them as security risks.
4.  **Findings Dashboard:** All identified security findings (from static and dependency analysis) are consolidated and presented in a filterable dashboard, showing severity, type, location, evidence, and remediation guidance.
5.  **Gate Plan Generation:** Based on the aggregated findings and their severities, the application automatically generates a CI/CD gate plan. This YAML-formatted plan defines pipeline gates (e.g., `PRE_COMMIT`, `CI_SECURITY`) with required checks and failure actions (e.g., `BLOCK`, `WARN`) to enforce security policies.
6.  **Exports & Evidence:** Finally, the developer can export all analysis results (findings, dependency reports, gate plan, executive summary) in auditable formats (JSON, YAML, Markdown). A crucial `evidence_manifest.json` is also generated, providing cryptographic hashes of all inputs and outputs for compliance and non-repudiation.

This flow ensures a systematic, traceable, and automated approach to managing security risks in an AI-accelerated development environment.

## 2. Code Requirements

```python
import streamlit as st
import pandas as pd
import json
import yaml
import zipfile
import io
import os
import shutil
import tempfile
from collections import defaultdict

# Import all functions and global variables from source.py
from source import *

# --- Streamlit Application Global Configuration ---
st.set_page_config(layout="wide", page_title="AI Code-Gen Risk Analyzer")

# --- st.session_state Design ---

# Initialize session state variables if they don't exist
if "current_page" not in st.session_state:
    st.session_state.current_page = "Code Input"
if "code_input_text" not in st.session_state:
    st.session_state.code_input_text = ""
if "uploaded_files_data" not in st.session_state:
    st.session_state.uploaded_files_data = [] # List of {'filename': str, 'content': str}
if "code_source_tag" not in st.session_state:
    st.session_state.code_source_tag = "UNKNOWN"
if "analysis_performed" not in st.session_state:
    st.session_state.analysis_performed = False

# State variables to store results of analysis (persisted across pages)
# These will be populated by copying from source.py's global lists after each run
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

# --- Helper Functions for Analysis Orchestration (to manage source.py globals) ---
def run_full_analysis():
    """
    Orchestrates the full analysis workflow by clearing source.py globals,
    calling source.py functions, and then copying results to session_state.
    """
    # 1. Clear source.py's global lists before a new analysis run
    source.all_artifacts.clear()
    source.all_findings.clear()
    source.all_dependencies.clear()

    # 2. Ingest code and generate artifacts
    artifacts_to_process = []
    if st.session_state.code_input_text:
        artifact = source.generate_code_artifact("snippet.py", st.session_state.code_input_text, st.session_state.code_source_tag)
        artifacts_to_process.append(artifact)
    for file_data in st.session_state.uploaded_files_data:
        artifact = source.generate_code_artifact(file_data['filename'], file_data['content'], st.session_state.code_source_tag)
        artifacts_to_process.append(artifact)

    # If no code was provided, use synthetic data for demonstration
    if not artifacts_to_process and not st.session_state.analysis_performed: # Only use synthetic if no user input and no prior analysis
        st.info("No code provided. Using synthetic code snippets and dependency files for demonstration.")
        for filename, content in source.SYNTHETIC_CODE_SNIPPETS.items():
            source_tag = "COPILOT" if "app_with_secrets.py" in filename else ("CLAUDE" if "data_processor.py" in filename else "UNKNOWN")
            artifact = source.generate_code_artifact(filename, content, source_tag)
            artifacts_to_process.append(artifact)
        
        for dep_filename, dep_content in source.SYNTHETIC_DEPENDENCY_FILES.items():
            dep_artifact = source.generate_code_artifact(dep_filename, dep_content, source="UNKNOWN_DEPENDENCY_FILE")
            dep_records = source.parse_and_analyze_dependencies(dep_filename, dep_content, dep_artifact.artifact_id)
            # Findings from dependency analysis are already appended to source.all_findings by parse_and_analyze_dependencies
            # Dep records are appended to source.all_dependencies

    # Ensure artifacts_to_process contains all artifacts now residing in source.all_artifacts
    # This loop is crucial because generate_code_artifact directly appends to source.all_artifacts
    # The if not artifacts_to_process above is for initial ingestion, but the global list is the source of truth now.
    artifacts_for_sast = [a for a in source.all_artifacts if a.language == "python" and not a.filename.endswith(('.txt', '.toml', '.json'))]
    artifacts_for_deps = [a for a in source.all_artifacts if a.filename.endswith(('.txt', '.toml', '.json'))]


    # 3. Perform Static Analysis (Regex)
    for artifact in artifacts_for_sast:
        source.find_vulnerabilities_regex(artifact, source.STATIC_RULES) # Appends to source.all_findings

    # 4. Perform Static Analysis (AST)
    for artifact in artifacts_for_sast:
        source.find_vulnerabilities_ast(artifact, source.STATIC_RULES) # Appends to source.all_findings

    # 5. Perform Dependency Analysis
    for dep_artifact in artifacts_for_deps:
        source.parse_and_analyze_dependencies(dep_artifact.filename, dep_artifact.content, dep_artifact.artifact_id) # Appends to source.all_dependencies and source.all_findings

    # 6. Generate CI/CD Gate Plan
    sdlc_gate_plan = source.generate_ci_cd_gate_plan(source.all_findings, source.all_dependencies)
    sdlc_gate_plan_yaml = yaml.dump(sdlc_gate_plan.model_dump(by_alias=True), indent=2, sort_keys=False)

    # 7. Generate Export Contents
    findings_json_content = json.dumps([f.model_dump(mode='json') for f in source.all_findings], indent=2)
    dependency_report_json_content = json.dumps([d.model_dump(mode='json') for d in source.all_dependencies], indent=2)
    executive_summary_md_content = source.generate_executive_summary(source.all_findings, source.all_dependencies)

    # Calculate inputs_hash
    all_artifact_hashes_str = "".join(sorted([a.content_hash for a in source.all_artifacts]))
    inputs_hash = hashlib.sha256(all_artifact_hashes_str.encode('utf-8')).hexdigest()

    # Calculate outputs_hash
    combined_outputs_content = findings_json_content + dependency_report_json_content + sdlc_gate_plan_yaml + executive_summary_md_content
    outputs_hash = hashlib.sha256(combined_outputs_content.encode('utf-8')).hexdigest()

    manifest = source.EvidenceManifest(
        inputs_hash=inputs_hash,
        outputs_hash=outputs_hash,
        artifacts=[{"artifact_id": str(a.artifact_id), "filename": a.filename, "content_hash": a.content_hash} for a in source.all_artifacts]
    )
    evidence_manifest_json_content = json.dumps(manifest.model_dump(mode='json'), indent=2)

    # 8. Copy results from source.py globals to st.session_state
    st.session_state.all_artifacts_state = list(source.all_artifacts)
    st.session_state.all_findings_state = list(source.all_findings)
    st.session_state.all_dependencies_state = list(source.all_dependencies)
    st.session_state.sdlc_gate_plan_state = sdlc_gate_plan
    st.session_state.sdlc_gate_plan_yaml_state = sdlc_gate_plan_yaml
    st.session_state.findings_json_content_state = findings_json_content
    st.session_state.dependency_report_json_content_state = dependency_report_json_content
    st.session_state.executive_summary_md_content_state = executive_summary_md_content
    st.session_state.evidence_manifest_json_content_state = evidence_manifest_json_content
    st.session_state.inputs_hash_state = inputs_hash
    st.session_state.outputs_hash_state = outputs_hash
    st.session_state.analysis_performed = True
    st.success("Analysis complete!")


# --- Streamlit UI Structure ---

# Sidebar for navigation
st.sidebar.title("Navigation")
page_options = [
    "Application Overview",
    "Code Input",
    "Findings Dashboard",
    "Dependency Analyzer",
    "Gate Plan Generator",
    "Exports & Evidence"
]
st.session_state.current_page = st.sidebar.selectbox("Go to", page_options, index=page_options.index(st.session_state.current_page) if st.session_state.current_page in page_options else 0)

# --- 1. Application Overview Page ---
if st.session_state.current_page == "Application Overview":
    st.title("AI-Powered Code Generation Risk Assessment and Secure SDLC Controls")

    st.markdown(f"")
    st.markdown(f"## Introduction: Proactive Security for AI-Assisted Development")
    st.markdown(f"As a Software Developer at \"InnovateTech Solutions,\" I'm constantly leveraging AI code assistants to boost productivity. However, this has brought a new challenge: a noticeable increase in security incidents linked to AI-generated code. From hard-coded secrets to vulnerable dependencies, these issues threaten our product integrity and customer trust.")
    st.markdown(f"")
    st.markdown(f"My primary responsibility is to ensure that while we embrace AI's power, we don't compromise on security. Leadership has mandated a proactive approach: identifying and mitigating these risks *before* they hit production. This means performing thorough static analysis, assessing third-party dependencies, and integrating robust security gates into our CI/CD pipelines.")
    st.markdown(f"")
    st.markdown(f"This application simulates my daily workflow, demonstrating how I utilize static analysis techniques and risk assessment to secure our codebase. We'll process code artifacts, identify common AI-introduced vulnerabilities, analyze dependencies, and ultimately generate an automated CI/CD gate plan to enforce our security policies.")
    st.markdown(f"---")
    st.markdown(f"")
    st.markdown(f"## Data Models Overview")
    st.markdown(f"As a Software Developer, I rely on well-defined structures to manage complex data, especially when dealing with security findings. Pydantic helps me create robust, type-safe data models for code artifacts, security findings, dependency records, and our CI/CD gate plans. This ensures consistency and makes it easier to process and export audit results.")
    st.markdown(f"")
    st.markdown(f"My first step in building any robust analysis tool is defining the data structures that will hold my findings. This is crucial for maintaining clarity, ensuring data integrity, and facilitating easy export and integration with other systems. Using Pydantic means I'm not just storing data; I'm storing *structured, validated* data, which is essential for auditability and reliability in a security context. These models mirror the artifacts I'll be working with – code snippets, vulnerability findings, dependency information, and the final CI/CD gate configurations.")
    st.markdown(f"")
    st.markdown(f"The `GateType` and `FindingType` enumerations, for example, define the standardized categories for our security checks and pipeline actions. This prevents ambiguity and ensures that everyone on the team understands the classification of risks and controls. The `Severity` enumeration allows for consistent risk prioritization, guiding our remediation efforts.")
    st.markdown(f"")
    st.markdown(f"Each of my input code snippets has now been converted into a structured `CodeArtifact`. I can see the unique ID and the content hash for each. This is my foundation for all subsequent security analysis. If I need to trace back a finding, I can link it directly to this artifact and its immutable hash. This level of traceability is crucial for security compliance and incident response, ensuring that I can always verify the exact version of the code that was scanned.")
    st.markdown(f"")
    st.markdown(f"These Pydantic models serve as the schema for all the data our analysis will generate. When I process a code file, its metadata and content will conform to `CodeArtifact`. Any security issues found will be stored as `Finding` objects, complete with severity, description, and remediation advice. Dependencies found in files like `requirements.txt` will be structured as `DependencyRecord`s. This structured approach is critical for creating consistent, machine-readable security reports, which are invaluable for tracking risks and demonstrating compliance to auditors. The enumerations standardize our security vocabulary across the team.")
    st.markdown(f"")
    st.markdown(f"---")

    if not st.session_state.analysis_performed:
        st.info("No analysis has been performed yet. You can proceed to 'Code Input' to start, or click the button below to run an analysis on synthetic data for demonstration.")
        if st.button("Run Analysis with Synthetic Data (Demo)"):
            run_full_analysis()
            st.session_state.current_page = "Findings Dashboard" # Navigate to findings after demo run
            st.rerun()

# --- 2. Code Input Page ---
elif st.session_state.current_page == "Code Input":
    st.title("Code Ingestion and Artifact Generation")

    st.markdown(f"As a developer, my first practical step is to get the code into a format I can analyze. This often means ingesting raw code snippets or files from a repository, creating a standard `CodeArtifact` record for each. This process includes generating a unique `artifact_id` and a content hash (SHA256). The content hash is particularly important for auditability; it's our digital fingerprint of the exact code state at the time of analysis, ensuring that our findings always refer to an immutable piece of evidence.")
    st.markdown(f"")
    st.markdown(f"When AI assists in code generation, I need a reliable way to track exactly *which* code was analyzed. Imagine an AI generating 50 lines of code; I need to ensure that if a vulnerability is found, I can point directly to the exact version of that code. The `content_hash` serves as this unalterable reference. It’s a cryptographic integrity check, ensuring the code hasn't been tampered with since analysis. For instance, if an auditor later questions a finding, I can provide the hash and the corresponding code, proving the finding's validity against that specific version. The `artifact_id` provides a unique identifier for each piece of code, simplifying tracking across multiple analysis runs.")
    st.markdown(f"")
    st.markdown(f"The SHA256 content hash $H$ for a code artifact $C$ is calculated as:")
    st.markdown(r"$$ H = \text{{SHA256}}(\text{{UTF8Encode}}(C)) $$")
    st.markdown(r"where $H$ is the SHA256 hash and $C$ is the code artifact content.")
    st.markdown(f"This operation ensures that any change, no matter how small, to the code $C$ will result in a completely different hash $H$, making it an ideal tool for immutability and auditing.")
    st.markdown(f"---")

    st.subheader("Provide Code for Analysis")

    st.markdown(f"**Step 1: Tag the Source**")
    st.session_state.code_source_tag = st.radio(
        "Who generated this code?",
        ("COPILOT", "CLAUDE", "AGENT", "UNKNOWN"),
        index=("COPILOT", "CLAUDE", "AGENT", "UNKNOWN").index(st.session_state.code_source_tag),
        horizontal=True
    )

    st.markdown(f"**Step 2: Enter Code**")
    col1, col2 = st.columns(2)
    with col1:
        st.session_state.code_input_text = st.text_area(
            "Paste code snippet here (e.g., Python, requirements.txt, pyproject.toml)",
            value=st.session_state.code_input_text,
            height=300,
            placeholder="""
# Example Python snippet
import os
API_KEY = "sk-A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"
def risky_func(data):
    eval(data)
"""
        )
    with col2:
        uploaded_files = st.file_uploader(
            "Upload code files (e.g., .py, .txt, .toml, .json) or a .zip repository",
            type=["py", "txt", "toml", "json", "zip"],
            accept_multiple_files=True
        )

        st.session_state.uploaded_files_data = []
        if uploaded_files:
            for uploaded_file in uploaded_files:
                if uploaded_file.name.endswith(".zip"):
                    with tempfile.TemporaryDirectory() as temp_dir:
                        with zipfile.ZipFile(uploaded_file, 'r') as z:
                            z.extractall(temp_dir)
                        for root, _, files in os.walk(temp_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                relative_path = os.path.relpath(file_path, temp_dir)
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    st.session_state.uploaded_files_data.append({'filename': relative_path, 'content': f.read()})
                else:
                    st.session_state.uploaded_files_data.append({'filename': uploaded_file.name, 'content': uploaded_file.getvalue().decode('utf-8')})
            st.info(f"Loaded {len(st.session_state.uploaded_files_data)} files from upload(s).")

    st.markdown(f"**Step 3: Run Analysis**")
    if st.button("Analyze Code"):
        if not st.session_state.code_input_text and not st.session_state.uploaded_files_data:
            st.warning("Please provide some code (snippet or file upload) or run with synthetic data from the Overview page to perform analysis.")
        else:
            with st.spinner("Running static analysis and dependency checks... This may take a moment."):
                run_full_analysis()
            st.session_state.current_page = "Findings Dashboard"
            st.rerun()

    st.markdown(f"---")
    if st.session_state.all_artifacts_state:
        st.subheader("Generated Code Artifacts:")
        df_artifacts = pd.DataFrame([
            {"Filename": a.filename, "Source": a.source, "Content Hash (SHA256)": a.content_hash[:10] + "...", "Created At": a.created_at.strftime("%Y-%m-%d %H:%M")}
            for a in st.session_state.all_artifacts_state
        ])
        st.dataframe(df_artifacts, use_container_width=True)


# --- 3. Findings Dashboard Page ---
elif st.session_state.current_page == "Findings Dashboard":
    st.title("Findings Dashboard")

    st.markdown(f"I've successfully run our initial set of regex-based checks, followed by AST analysis. The output clearly shows several critical and high-severity findings, such as hard-coded API keys, potential SQL injection, dangerous dynamic execution (`eval()`, `subprocess.run(shell=True)`), and unsafe deserialization (`pickle.loads()`), along with the use of a weak cryptographic hash (MD5). These findings are particularly important because they represent high-impact vulnerabilities that a simple text search might miss or misinterpret.")
    st.markdown(f"")
    st.markdown(f"For each finding, I get the exact line number and the snippet of code that triggered the rule, making it easy to pinpoint and verify the vulnerability. This immediate feedback helps me understand the attack surface generated by the AI and prioritize my remediation efforts. For instance, a `CRITICAL` secret finding would prompt an immediate action to remove the secret and implement a secure secret management solution.")
    st.markdown(f"")
    st.markdown(f"Knowing that `pickle.loads` is explicitly called within the AST node provides definitive evidence of unsafe deserialization. This level of precision is invaluable for a developer, allowing me to trust the findings and focus on targeted remediation, preventing potential remote code execution or data corruption.")
    st.markdown(f"---")

    if not st.session_state.analysis_performed or not st.session_state.all_findings_state:
        st.warning("No findings to display. Please go to 'Code Input' to run an analysis or click 'Run Analysis with Synthetic Data (Demo)' on the Overview page.")
    else:
        df_findings = pd.DataFrame([f.model_dump() for f in st.session_state.all_findings_state])
        df_findings['artifact_filename'] = df_findings['artifact_id'].apply(lambda x: next((a.filename for a in st.session_state.all_artifacts_state if a.artifact_id == x), "N/A"))
        df_findings = df_findings[[
            "severity", "finding_type", "rule_id", "artifact_filename", "location", "description", "evidence_snippet", "remediation_guidance"
        ]]

        st.subheader(f"Total Findings: {len(df_findings)}")

        # Filters
        unique_severities = df_findings["severity"].unique().tolist()
        unique_finding_types = df_findings["finding_type"].unique().tolist()

        filter_severity = st.multiselect("Filter by Severity", options=unique_severities, default=unique_severities)
        filter_type = st.multiselect("Filter by Finding Type", options=unique_finding_types, default=unique_finding_types)

        filtered_findings = df_findings[
            (df_findings["severity"].isin(filter_severity)) &
            (df_findings["finding_type"].isin(filter_type))
        ]

        st.dataframe(filtered_findings, use_container_width=True, hide_index=True)

        if not filtered_findings.empty:
            st.subheader("Finding Details and Remediation")
            selected_finding_idx = st.selectbox(
                "Select a finding to view details:",
                options=range(len(filtered_findings)),
                format_func=lambda x: f"{filtered_findings.iloc[x]['severity']} - {filtered_findings.iloc[x]['rule_id']} in {filtered_findings.iloc[x]['artifact_filename']} at {filtered_findings.iloc[x]['location']}"
            )
            selected_finding = filtered_findings.iloc[selected_finding_idx]

            col_detail1, col_detail2 = st.columns(2)
            with col_detail1:
                st.markdown(f"**Description:** {selected_finding['description']}")
                st.markdown(f"**File:** {selected_finding['artifact_filename']}")
                st.markdown(f"**Location:** {selected_finding['location']}")
                st.markdown(f"**Rule ID:** `{selected_finding['rule_id']}`")
                st.markdown(f"**Severity:** :red[{selected_finding['severity']}]")
            with col_detail2:
                st.markdown(f"**Evidence Snippet:**")
                st.code(selected_finding['evidence_snippet'], language='python')
                st.markdown(f"**Remediation Guidance:** {selected_finding['remediation_guidance']}")

# --- 4. Dependency Analyzer Page ---
elif st.session_state.current_page == "Dependency Analyzer":
    st.title("Dependency Risk Assessment")

    st.markdown(f"AI code assistants can generate `requirements.txt` or `pyproject.toml` entries that might include outdated, insecure, or even entirely fabricated (hallucinated) packages. As a Software Developer, reviewing dependencies is a crucial part of securing the supply chain. I need to ensure that all packages conform to our organization's approved lists and flag any suspicious entries that could be hallucinations.")
    st.markdown(f"")
    st.markdown(f"Supply chain attacks are a major threat, and AI can inadvertently contribute by suggesting insecure or non-existent packages. My role involves parsing these dependency files and comparing them against our internal `allowlist` (approved packages) and `denylist` (known risky packages). Beyond that, AI sometimes \"hallucinates\" packages that don't exist or have misleading names (e.g., `requests-pro`). Detecting these hallucinations is vital to prevent developers from unknowingly installing malicious or non-functional libraries. This step directly mitigates supply chain risks.")
    st.markdown(f"")
    st.markdown(f"The process involves:")
    st.markdown(f"- Parsing the dependency file to extract package names and versions.")
    st.markdown(f"- Checking against the `allowlist` and `denylist`.")
    st.markdown(f"- Applying heuristics (like custom suffixes) to detect potential `hallucinated_package` risks.")
    st.markdown(f"---")

    if not st.session_state.analysis_performed or not st.session_state.all_dependencies_state:
        st.warning("No dependencies to display. Please go to 'Code Input' to run an analysis or click 'Run Analysis with Synthetic Data (Demo)' on the Overview page.")
    else:
        df_dependencies = pd.DataFrame([d.model_dump() for d in st.session_state.all_dependencies_state])

        st.subheader(f"Total Dependencies Found: {len(df_dependencies)}")

        # Filters
        unique_statuses = df_dependencies["status"].unique().tolist()
        filter_status = st.multiselect("Filter by Status", options=unique_statuses, default=unique_statuses)
        
        hallucination_findings = [f for f in st.session_state.all_findings_state if f.finding_type == FindingType.HALLUCINATED_PACKAGE]
        hallucination_packages = {f.description.split("'")[1].lower() for f in hallucination_findings}
        
        if not df_dependencies.empty:
            df_dependencies['Hallucination Risk'] = df_dependencies['name'].apply(lambda x: "Yes" if x in hallucination_packages else "No")
            filter_hallucination = st.checkbox("Show only Hallucination Risks", value=False)
        else:
            filter_hallucination = False

        filtered_dependencies = df_dependencies[df_dependencies["status"].isin(filter_status)]
        if filter_hallucination:
            filtered_dependencies = filtered_dependencies[filtered_dependencies["Hallucination Risk"] == "Yes"]

        st.dataframe(filtered_dependencies, use_container_width=True, hide_index=True)

        if st.session_state.all_dependencies_state:
            st.markdown(f"")
            st.markdown(f"The dependency analysis clearly flags denylisted packages like `pyyaml` (which is often used unsafely without a safe loader) and potential hallucinations such as `flask-secure-pro`. This immediate insight helps me ensure that only trusted and vetted libraries make it into our projects. For a developer, this means less time chasing down obscure build failures or vulnerability alerts from unknown packages, and more confidence in the integrity of our software supply chain. Any package marked as `UNKNOWN` or `DENY` becomes an immediate point of investigation, directly contributing to securing our build process.")

# --- 5. Gate Plan Generator Page ---
elif st.session_state.current_page == "Gate Plan Generator":
    st.title("CI/CD Gate Plan Generation")

    st.markdown(f"With all the vulnerabilities and dependency risks identified, the next critical step is to translate these findings into actionable controls for our CI/CD pipeline. This means generating a `sdlc_control_plan.yaml` that defines specific \"gates\" – automated checks that will either `BLOCK` a deployment or issue a `WARN` based on the severity and type of findings. This ensures that security isn't just an afterthought but an integrated part of our Software Development Lifecycle (SDLC).")
    st.markdown(f"")
    st.markdown(f"My analysis is only useful if it leads to concrete actions. Generating a CI/CD gate plan is where the rubber meets the road. If I find a `CRITICAL` secret or a `HIGH` risk dependency, the pipeline must `BLOCK` the build immediately. For lower-severity issues, a `WARN` might suffice to notify the team without halting development. This YAML plan becomes the blueprint for our automated security controls, ensuring that every piece of AI-generated code, and any changes, passes a strict security review before it ever reaches production. This automates the enforcement of our security policies, reducing human error and \"automation complacency.\"")
    st.markdown(f"")
    st.markdown(f"The mapping logic is as follows:")
    st.markdown(f"- Presence of `HIGH`/`CRITICAL` findings $\rightarrow$ enforce `CI_SECURITY` gate `BLOCK`.")
    st.markdown(f"- Presence of `SECRET` findings $\rightarrow$ enforce `PRE_COMMIT` secret scanning gate `BLOCK`.")
    st.markdown(f"- Presence of `UNKNOWN` or `DENY` dependencies $\rightarrow$ enforce `CI_BUILD` or `CI_SECURITY` dependency allowlist gate `BLOCK`.")
    st.markdown(f"- Otherwise $\rightarrow$ `WARN` gating allowed for low risk.")
    st.markdown(f"")
    st.markdown(f"Let's define a simple risk score for an artifact to drive decision-making for gating, where $S(f)$ is the severity of finding $f$. We assign weights: $\text{{Weight}}(\text{{CRITICAL}}) = 100$, $\text{{Weight}}(\text{{HIGH}}) = 50$, $\text{{Weight}}(\text{{MEDIUM}}) = 10$, $\text{{Weight}}(\text{{LOW}}) = 1$.")
    st.markdown(f"The `ArtifactRiskScore` for an artifact $A$ is then:")
    st.markdown(r"$$ \text{{ArtifactRiskScore}}(A) = \sum_{{f \in \text{{Findings}}(A)}} \text{{Weight}}(S(f)) $$")
    st.markdown(r"where $A$ represents a code artifact, $f$ represents a finding, $S(f)$ is the severity of finding $f$, and $\text{{Weight}}(S(f))$ is the assigned weight for that severity.")
    st.markdown(f"This quantitative score helps to aggregate risk across an artifact and inform the gating decision.")
    st.markdown(f"---")

    if not st.session_state.analysis_performed or not st.session_state.sdlc_gate_plan_yaml_state:
        st.warning("No gate plan generated. Please go to 'Code Input' to run an analysis or click 'Run Analysis with Synthetic Data (Demo)' on the Overview page.")
    else:
        st.subheader("Generated CI/CD Gate Plan (YAML Preview)")
        st.code(st.session_state.sdlc_gate_plan_yaml_state, language="yaml", height=600)

        st.markdown(f"")
        st.markdown(f"The generated YAML output provides a clear, machine-readable `sdlc_control_plan.yaml`. Based on the critical findings (secrets, dangerous execution, denylisted dependencies) identified earlier, the `CI_SECURITY` and `PRE_COMMIT` gates are correctly configured to `BLOCK` the pipeline. This means if any AI-generated code introduces similar vulnerabilities in the future, our pipeline will automatically prevent it from progressing. For me, this is the ultimate goal: automating security enforcement to build a more resilient and secure development process. This plan directly translates my analysis into organizational security policy.")

# --- 6. Exports & Evidence Page ---
elif st.session_state.current_page == "Exports & Evidence":
    st.title("Consolidating Findings and Exporting Auditable Results")

    st.markdown(f"The final step in my workflow is to consolidate all findings and artifacts into a comprehensive set of auditable reports. This includes JSON files for detailed findings and dependency risks, the YAML gate plan, and a markdown executive summary. Crucially, I also need to generate an `evidence_manifest.json` that hashes all inputs and outputs, providing an immutable record for auditing and compliance.")
    st.markdown(f"")
    st.markdown(f"As a developer in a security-conscious organization, documentation and auditability are paramount. It’s not enough to just find vulnerabilities; I need to provide clear, structured evidence of what was found, where, how it was remediated, and what controls are in place. These export formats (`.json`, `.yaml`, `.md`) are designed to be consumed by different stakeholders: developers for remediation, DevSecOps for pipeline configuration, and leadership for risk oversight. The `evidence_manifest.json` serves as the ultimate proof-of-work, hashing every piece of input and output to ensure non-repudiation and integrity for auditors.")
    st.markdown(f"")
    st.markdown(f"The `inputs_hash` combines the hashes of all `CodeArtifact` contents. The `outputs_hash` combines the hashes of the generated JSON and YAML reports. This creates a chain of custody for the audit.")
    st.markdown(r"$$ \text{{inputs\_hash}} = \text{{SHA256}}(\text{{Concat}}(\text{{CodeArtifact}}_1.\text{{content\_hash}}, \dots, \text{{CodeArtifact}}_N.\text{{content\_hash}})) $$")
    st.markdown(r"where $\text{{CodeArtifact}}_i.\text{{content\_hash}}$ is the content hash of the $i$-th code artifact and $\text{{Concat}}$ denotes string concatenation.")
    st.markdown(r"$$ \text{{outputs\_hash}} = \text{{SHA256}}(\text{{Concat}}(\text{{Hash}}(\text{{findings.json}}), \text{{Hash}}(\text{{deps.json}}), \text{{Hash}}(\text{{gateplan.yaml}}))) $$")
    st.markdown(r"where $\text{{Hash}}(\cdot)$ refers to the SHA256 hash of the content of the respective report file.")
    st.markdown(f"---")

    if not st.session_state.analysis_performed:
        st.warning("No reports generated. Please go to 'Code Input' to run an analysis or click 'Run Analysis with Synthetic Data (Demo)' on the Overview page.")
    else:
        st.subheader("Download Auditable Reports")

        col_dl1, col_dl2, col_dl3, col_dl4, col_dl5 = st.columns(5)

        with col_dl1:
            st.download_button(
                label="Findings JSON",
                data=st.session_state.findings_json_content_state,
                file_name="code_gen_risk_findings.json",
                mime="application/json",
                help="Detailed list of all identified security findings."
            )
        with col_dl2:
            st.download_button(
                label="Dependencies JSON",
                data=st.session_state.dependency_report_json_content_state,
                file_name="dependency_risk_report.json",
                mime="application/json",
                help="Report on all parsed dependencies, their status, and risks."
            )
        with col_dl3:
            st.download_button(
                label="Gate Plan YAML",
                data=st.session_state.sdlc_gate_plan_yaml_state,
                file_name="sdlc_control_plan.yaml",
                mime="application/x-yaml",
                help="CI/CD gate configuration based on analysis findings."
            )
        with col_dl4:
            st.download_button(
                label="Executive Summary MD",
                data=st.session_state.executive_summary_md_content_state,
                file_name="case5_executive_summary.md",
                mime="text/markdown",
                help="High-level summary of risks and control plan for leadership."
            )
        with col_dl5:
            st.download_button(
                label="Evidence Manifest JSON",
                data=st.session_state.evidence_manifest_json_content_state,
                file_name="evidence_manifest.json",
                mime="application/json",
                help="Immutable record of analysis run, inputs, and outputs hashes."
            )

        st.markdown(f"---")
        st.subheader("Overall Analysis Hashes")
        st.markdown(f"**Inputs Hash (SHA256):** `{st.session_state.inputs_hash_state}`")
        st.markdown(f"**Outputs Hash (SHA256):** `{st.session_state.outputs_hash_state}`")

        st.markdown(f"---")
        st.markdown(f"")
        st.markdown(f"All necessary audit reports have been successfully generated and are available for download. The detailed JSON reports provide granular data for developers, while the YAML gate plan is ready for our DevSecOps team. The executive summary offers a high-level overview for leadership, and critically, the `evidence_manifest.json` provides an immutable record of this entire analysis, linking inputs to outputs via cryptographic hashes. This ensures that every step of my security audit is verifiable, transparent, and defensible, meeting our organization's strict compliance requirements and solidifying our security posture against the evolving risks of AI-generated code.")

```
