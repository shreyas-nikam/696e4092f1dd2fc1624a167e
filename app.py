import os
import streamlit as st
import pandas as pd
import json
import yaml
import zipfile
import io
import os
import shutil
import tempfile
import hashlib
import re
from collections import defaultdict
import source
from source import *

st.set_page_config(
    page_title="QuLab: AI-Powered Code Generation Risk Assessment + Secure SDLC Controls", layout="wide")
st.sidebar.image("https://www.quantuniversity.com/assets/img/logo5.jpg")
st.sidebar.divider()
st.title("QuLab: AI-Powered Code Generation Risk Assessment + Secure SDLC Controls")
st.divider()

# --- st.session_state Design ---
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
if "zip_generated" not in st.session_state:
    st.session_state.zip_generated = False
if "zip_data" not in st.session_state:
    st.session_state.zip_data = None
if "zip_size" not in st.session_state:
    st.session_state.zip_size = 0
if "auto_clear_next" not in st.session_state:
    st.session_state.auto_clear_next = False


def run_full_analysis():
    source.all_artifacts.clear()
    source.all_findings.clear()
    source.all_dependencies.clear()

    artifacts_to_process = []
    if st.session_state.code_input_text:
        # Auto-detect content type and use appropriate filename
        content = st.session_state.code_input_text.strip()
        filename = "snippet.py"

        # Check if content looks like a requirements.txt file
        lines = content.splitlines()
        non_comment_lines = [
            l.strip() for l in lines if l.strip() and not l.strip().startswith('#')]
        if non_comment_lines:
            # If majority of lines match package==version or package>=version pattern, it's likely requirements.txt
            requirements_pattern = re.compile(r'^[a-zA-Z0-9_\-\.]+\s*[<>=!~]+')
            matching_lines = sum(
                1 for l in non_comment_lines if requirements_pattern.match(l))
            if matching_lines / len(non_comment_lines) > 0.5:
                filename = "requirements.txt"

        artifact = source.generate_code_artifact(
            filename, st.session_state.code_input_text, st.session_state.code_source_tag)
        artifacts_to_process.append(artifact)
    for file_data in st.session_state.uploaded_files_data:
        artifact = source.generate_code_artifact(
            file_data['filename'], file_data['content'], st.session_state.code_source_tag)
        artifacts_to_process.append(artifact)

    if not artifacts_to_process and not st.session_state.analysis_performed:
        st.info(
            "No code provided. Using synthetic code snippets and dependency files for demonstration.")
        for filename, content in source.SYNTHETIC_CODE_SNIPPETS.items():
            source_tag = "COPILOT" if "app_with_secrets.py" in filename else (
                "CLAUDE" if "data_processor.py" in filename else "UNKNOWN")
            artifact = source.generate_code_artifact(
                filename, content, source_tag)
            artifacts_to_process.append(artifact)
        for dep_filename, dep_content in source.SYNTHETIC_DEPENDENCY_FILES.items():
            dep_artifact = source.generate_code_artifact(
                dep_filename, dep_content, source="UNKNOWN_DEPENDENCY_FILE")

    # Debug: Log artifact creation
    print(
        f"DEBUG: Total artifacts in source.all_artifacts: {len(source.all_artifacts)}")
    for a in source.all_artifacts:
        print(
            f"DEBUG: Artifact - {a.filename}, Language: {a.language}, Content length: {len(a.content)}")

    artifacts_for_sast = [a for a in source.all_artifacts if a.language ==
                          "python" and not a.filename.endswith(('.txt', '.toml', '.json'))]
    artifacts_for_deps = [a for a in source.all_artifacts if a.filename.endswith(
        ('.txt', '.toml', '.json'))]

    print(f"DEBUG: Artifacts for SAST: {len(artifacts_for_sast)}")
    print(f"DEBUG: Artifacts for deps: {len(artifacts_for_deps)}")

    for artifact in artifacts_for_sast:
        print(f"DEBUG: Running regex analysis on {artifact.filename}")
        regex_findings = source.find_vulnerabilities_regex(
            artifact, source.STATIC_RULES)
        source.all_findings.extend(regex_findings)
        print(f"DEBUG: Found {len(regex_findings)} regex findings")

    for artifact in artifacts_for_sast:
        print(f"DEBUG: Running AST analysis on {artifact.filename}")
        ast_findings = source.find_vulnerabilities_ast(
            artifact, source.STATIC_RULES)
        source.all_findings.extend(ast_findings)
        print(f"DEBUG: Found {len(ast_findings)} AST findings")

    print(f"DEBUG: Total findings after analysis: {len(source.all_findings)}")
    for dep_artifact in artifacts_for_deps:
        source.parse_and_analyze_dependencies(
            dep_artifact.filename, dep_artifact.content, dep_artifact.artifact_id)

    sdlc_gate_plan = source.generate_ci_cd_gate_plan(
        source.all_findings, source.all_dependencies)
    sdlc_gate_plan_yaml = yaml.dump(sdlc_gate_plan.model_dump(
        by_alias=True), indent=2, sort_keys=False)

    findings_json_content = json.dumps(
        [f.model_dump(mode='json') for f in source.all_findings], indent=2)
    dependency_report_json_content = json.dumps(
        [d.model_dump(mode='json') for d in source.all_dependencies], indent=2)
    executive_summary_md_content = source.generate_executive_summary(
        source.all_findings, source.all_dependencies)

    all_artifact_hashes_str = "".join(
        sorted([a.content_hash for a in source.all_artifacts]))
    inputs_hash = hashlib.sha256(
        all_artifact_hashes_str.encode('utf-8')).hexdigest()
    combined_outputs_content = findings_json_content + \
        dependency_report_json_content + sdlc_gate_plan_yaml + executive_summary_md_content
    outputs_hash = hashlib.sha256(
        combined_outputs_content.encode('utf-8')).hexdigest()

    manifest = source.EvidenceManifest(
        inputs_hash=inputs_hash,
        outputs_hash=outputs_hash,
        artifacts=[{"artifact_id": str(a.artifact_id), "filename": a.filename,
                    "content_hash": a.content_hash} for a in source.all_artifacts]
    )
    evidence_manifest_json_content = json.dumps(
        manifest.model_dump(mode='json'), indent=2)

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


st.sidebar.title("Navigation")
page_options = [
    "Application Overview",
    "Analysis Dashboard",
    "Gate Plan Generator",
    "Exports & Evidence"
]

# Handle potential key error if state mismatch
if st.session_state.current_page not in page_options:
    st.session_state.current_page = page_options[0]

selected_page = st.sidebar.selectbox(
    "Go to", page_options, index=page_options.index(st.session_state.current_page))
if selected_page != st.session_state.current_page:
    st.session_state.current_page = selected_page
    st.rerun()

if st.session_state.current_page == "Application Overview":
    st.markdown(f"")
    st.markdown(
        f"## Introduction: Proactive Security for AI-Assisted Development")
    st.markdown(f"As a Software Developer at \"InnovateTech Solutions,\" I'm constantly leveraging AI code assistants to boost productivity. However, this has brought a new challenge: a noticeable increase in security incidents linked to AI-generated code. From hard-coded secrets to vulnerable dependencies, these issues threaten our product integrity and customer trust.")
    st.markdown(f"")
    st.markdown(f"My primary responsibility is to ensure that while we embrace AI's power, we don't compromise on security. Leadership has mandated a proactive approach: identifying and mitigating these risks *before* they hit production. This means performing thorough static analysis, assessing third-party dependencies, and integrating robust security gates into our CI/CD pipelines.")
    st.markdown(f"")
    st.markdown(f"This application simulates my daily workflow, demonstrating how I utilize static analysis techniques and risk assessment to secure our codebase. We'll process code artifacts, identify common AI-introduced vulnerabilities, analyze dependencies, and ultimately generate an automated CI/CD gate plan to enforce our security policies.")


elif st.session_state.current_page == "Analysis Dashboard":
    st.title("Security Analysis Dashboard")
    st.markdown(
        "Perform static analysis, identify vulnerabilities, and assess dependency risks in real-time.")

    # ========== CODE INPUT SECTION ==========
    st.markdown("---")
    st.header("Code Input & Analysis")

    # Sample Code Snippets
    with st.expander("View Sample Vulnerable Code Snippets", expanded=False):
        st.markdown("### Sample 1: Hard-coded Secrets & SQL Injection")
        st.code('''import os
import sqlite3

# CRITICAL: Hard-coded API key
API_KEY = "sk-A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6"
AWS_SECRET = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def fetch_user(username):
    # HIGH: SQL Injection vulnerability
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return cursor.fetchall()
''', language='python')

        st.markdown("### Sample 2: Dangerous Code Execution")
        st.code('''import subprocess
import pickle

def execute_user_input(user_code):
    # CRITICAL: Dangerous use of eval()
    result = eval(user_code)
    return result

def run_command(cmd):
    # HIGH: Shell injection via subprocess
    subprocess.run(cmd, shell=True, check=True)

def load_data(serialized_data):
    # HIGH: Unsafe deserialization
    return pickle.loads(serialized_data)
''', language='python')

        st.markdown("### Sample 3: Weak Cryptography")
        st.code('''import hashlib
import random

def hash_password(password):
    # MEDIUM: Using weak MD5 hash
    return hashlib.md5(password.encode()).hexdigest()

def generate_token():
    # MEDIUM: Insecure randomness
    return random.randint(1000, 9999)
''', language='python')

        st.markdown("### Sample 4: Vulnerable Dependencies")
        st.code('''pyyaml==5.3.1
requests==2.25.0
flask-secure-pro==1.0.0
django-utils-advanced==2.3.4
numpy-extras==1.18.0
''', language='text')
        st.caption(
            "⚠️ Contains denylisted packages (pyyaml) and hallucinated packages (flask-secure-pro, django-utils-advanced, numpy-extras)")

    # Code Input Form
    col_tag, col_button = st.columns([3, 1])
    with col_tag:
        st.session_state.code_source_tag = st.radio(
            "AI Source:",
            ("COPILOT", "CLAUDE", "AGENT", "UNKNOWN"),
            index=("COPILOT", "CLAUDE", "AGENT", "UNKNOWN").index(
                st.session_state.code_source_tag),
            horizontal=True
        )

    col1, col2 = st.columns(2)
    with col1:
        st.session_state.code_input_text = st.text_area(
            "Paste Python Code Snippet:",
            value=st.session_state.code_input_text,
            height=250,
            placeholder="# Paste your Python code or requirements.txt content here"
        )
    with col2:
        uploaded_files = st.file_uploader(
            "Or Upload Files (.py, .txt, .toml, .json, .zip):",
            type=["py", "txt", "toml", "json", "zip"],
            accept_multiple_files=True
        )
        if uploaded_files:
            st.session_state.uploaded_files_data = []
            for uploaded_file in uploaded_files:
                if uploaded_file.name.endswith(".zip"):
                    with tempfile.TemporaryDirectory() as temp_dir:
                        with zipfile.ZipFile(uploaded_file, 'r') as z:
                            z.extractall(temp_dir)
                        for root, _, files in os.walk(temp_dir):
                            for file in files:
                                file_path = os.path.join(root, file)
                                relative_path = os.path.relpath(
                                    file_path, temp_dir)
                                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                    st.session_state.uploaded_files_data.append(
                                        {'filename': relative_path, 'content': f.read()})
                else:
                    st.session_state.uploaded_files_data.append(
                        {'filename': uploaded_file.name, 'content': uploaded_file.getvalue().decode('utf-8')})
            st.success(
                f"Loaded {len(st.session_state.uploaded_files_data)} file(s)")
        elif st.session_state.uploaded_files_data:
            st.info(
                f"{len(st.session_state.uploaded_files_data)} file(s) previously loaded")

    col_analyze1, col_analyze2, col_analyze3 = st.columns([2, 2, 2])
    with col_analyze2:
        if st.button("Analyze Code", type="primary", use_container_width=True):
            if not st.session_state.code_input_text and not st.session_state.uploaded_files_data:
                st.warning("Please provide code or upload files to analyze.")
            else:
                with st.spinner("Running security analysis..."):
                    run_full_analysis()

                # Show detailed analysis results
                artifacts_count = len(st.session_state.all_artifacts_state)
                findings_count = len(st.session_state.all_findings_state)

                if artifacts_count == 0:
                    st.error(
                        "ERROR: No artifacts were created! The code input may not have been captured.")
                elif findings_count == 0:
                    st.warning(
                        f"Analysis complete! Processed {artifacts_count} artifact(s), but found NO vulnerabilities. Check terminal/logs and the 'View Generated Artifacts' section to verify your code was captured correctly.")
                else:
                    st.success(
                        f"Analysis complete! Processed {artifacts_count} artifact(s), found {findings_count} finding(s).")
                st.rerun()

    # ========== RESULTS SECTIONS (Only show if analysis performed) ==========
    if st.session_state.analysis_performed:
        st.markdown("---")

        # Metrics Row
        col_m1, col_m2, col_m3, col_m4 = st.columns(4)
        with col_m1:
            total_findings = len(st.session_state.all_findings_state)
            st.metric("Total Findings", total_findings)
        with col_m2:
            critical_findings = sum(
                1 for f in st.session_state.all_findings_state if f.severity == "CRITICAL")
            st.metric("Critical", critical_findings, delta=None if critical_findings ==
                      0 else f"-{critical_findings}", delta_color="inverse")
        with col_m3:
            high_findings = sum(
                1 for f in st.session_state.all_findings_state if f.severity == "HIGH")
            st.metric("High", high_findings, delta=None if high_findings ==
                      0 else f"-{high_findings}", delta_color="inverse")
        with col_m4:
            total_deps = len(st.session_state.all_dependencies_state)
            risky_deps = sum(1 for d in st.session_state.all_dependencies_state if d.status in [
                             "DENY", "UNKNOWN"])
            st.metric("Dependencies", total_deps, delta=None if risky_deps ==
                      0 else f"{risky_deps} risky", delta_color="inverse")

        # ========== FINDINGS SECTION ==========
        st.markdown("---")
        st.header("Security Findings")

        if not st.session_state.all_findings_state:
            st.info("No security findings detected in the analyzed code.")
        else:
            df_findings = pd.DataFrame(
                [f.model_dump() for f in st.session_state.all_findings_state])
            df_findings['artifact_filename'] = df_findings['artifact_id'].apply(lambda x: next(
                (a.filename for a in st.session_state.all_artifacts_state if a.artifact_id == x), "N/A"))

            col_filter1, col_filter2 = st.columns(2)
            with col_filter1:
                unique_severities = df_findings["severity"].unique().tolist()
                filter_severity = st.multiselect(
                    "Filter by Severity:",
                    options=unique_severities,
                    default=unique_severities)
            with col_filter2:
                unique_finding_types = df_findings["finding_type"].unique(
                ).tolist()
                filter_type = st.multiselect(
                    "Filter by Type:",
                    options=unique_finding_types,
                    default=unique_finding_types)

            filtered_findings = df_findings[
                (df_findings["severity"].isin(filter_severity)) &
                (df_findings["finding_type"].isin(filter_type))
            ]

            display_df = filtered_findings[[
                "severity", "finding_type", "rule_id", "artifact_filename", "location", "description"
            ]].copy()

            st.dataframe(display_df, use_container_width=True,
                         hide_index=True, height=300)

            if not filtered_findings.empty:
                st.markdown("#### Finding Details")
                selected_finding_idx = st.selectbox(
                    "Select finding:",
                    options=range(len(filtered_findings)),
                    format_func=lambda x: f"{filtered_findings.iloc[x]['severity']} - {filtered_findings.iloc[x]['rule_id']} ({filtered_findings.iloc[x]['artifact_filename']})"
                )
                selected_finding = filtered_findings.iloc[selected_finding_idx]

                col_detail1, col_detail2 = st.columns(2)
                with col_detail1:
                    st.markdown(
                        f"**Severity:** :red[{selected_finding['severity']}]")
                    st.markdown(f"**Rule:** `{selected_finding['rule_id']}`")
                    st.markdown(
                        f"**File:** {selected_finding['artifact_filename']}")
                    st.markdown(
                        f"**Location:** {selected_finding['location']}")
                    st.markdown(
                        f"**Description:** {selected_finding['description']}")
                with col_detail2:
                    st.markdown("**Evidence:**")
                    st.code(
                        selected_finding['evidence_snippet'], language='python')
                    st.markdown(
                        f"**Remediation:** {selected_finding['remediation_guidance']}")

        # ========== DEPENDENCIES SECTION ==========
        st.markdown("---")
        st.header("Dependency Risk Assessment")

        if not st.session_state.all_dependencies_state:
            st.info("No dependency files found in analysis.")
        else:
            df_dependencies = pd.DataFrame(
                [d.model_dump() for d in st.session_state.all_dependencies_state])

            col_dep_filter1, col_dep_filter2 = st.columns(2)
            with col_dep_filter1:
                unique_statuses = df_dependencies["status"].unique().tolist()
                filter_status = st.multiselect(
                    "Filter by Status:",
                    options=unique_statuses,
                    default=unique_statuses)
            with col_dep_filter2:
                hallucination_findings = [
                    f for f in st.session_state.all_findings_state
                    if f.finding_type == source.FindingType.HALLUCINATED_PACKAGE]
                hallucination_packages = {f.description.split("'")[1].lower()
                                          for f in hallucination_findings if "'" in f.description}

                if not df_dependencies.empty:
                    df_dependencies['hallucination_risk'] = df_dependencies['name'].apply(
                        lambda x: "Yes" if x.lower() in hallucination_packages else "No")
                    filter_hallucination = st.checkbox(
                        "Show only Hallucination Risks", value=False)
                else:
                    filter_hallucination = False

            filtered_dependencies = df_dependencies[df_dependencies["status"].isin(
                filter_status)]
            if filter_hallucination:
                filtered_dependencies = filtered_dependencies[
                    filtered_dependencies["hallucination_risk"] == "Yes"]

            display_cols = ["name", "version", "status", "source_file"]
            if 'hallucination_risk' in filtered_dependencies.columns:
                display_cols.append("hallucination_risk")

            st.dataframe(filtered_dependencies[display_cols],
                         use_container_width=True, hide_index=True, height=300)

            # Summary
            deny_count = len(
                filtered_dependencies[filtered_dependencies["status"] == "DENY"])
            unknown_count = len(
                filtered_dependencies[filtered_dependencies["status"] == "UNKNOWN"])
            hallucination_count = len(hallucination_packages)

            if deny_count > 0 or unknown_count > 0 or hallucination_count > 0:
                st.warning(
                    f"Risk Summary: {deny_count} denylisted, {unknown_count} unknown, {hallucination_count} potential hallucinations")
            else:
                st.success("All dependencies are on the allowlist!")

        # ========== ARTIFACTS SECTION ==========
        if st.session_state.all_artifacts_state:
            # Show artifacts expanded if no findings (helps with debugging)
            expand_artifacts = len(st.session_state.all_findings_state) == 0
            with st.expander("View Generated Artifacts", expanded=expand_artifacts):
                st.markdown(
                    f"**Total Artifacts:** {len(st.session_state.all_artifacts_state)}")
                df_artifacts = pd.DataFrame([
                    {"Filename": a.filename, "Source": a.source,
                        "Language": a.language,
                        "Content Hash": a.content_hash[:16] + "...",
                        "Created": a.created_at.strftime("%Y-%m-%d %H:%M")}
                    for a in st.session_state.all_artifacts_state
                ])
                st.dataframe(
                    df_artifacts, use_container_width=True, hide_index=True)

elif st.session_state.current_page == "Gate Plan Generator":
    st.title("CI/CD Gate Plan Generation")
    st.markdown(f"With all the vulnerabilities and dependency risks identified, the next critical step is to translate these findings into actionable controls for our CI/CD pipeline. This means generating a `sdlc_control_plan.yaml` that defines specific \"gates\" – automated checks that will either `BLOCK` a deployment or issue a `WARN` based on the severity and type of findings. This ensures that security isn't just an afterthought but an integrated part of our Software Development Lifecycle (SDLC).")
    st.markdown(f"")
    st.markdown(f"My analysis is only useful if it leads to concrete actions. Generating a CI/CD gate plan is where the rubber meets the road. If I find a `CRITICAL` secret or a `HIGH` risk dependency, the pipeline must `BLOCK` the build immediately. For lower-severity issues, a `WARN` might suffice to notify the team without halting development. This YAML plan becomes the blueprint for our automated security controls, ensuring that every piece of AI-generated code, and any changes, passes a strict security review before it ever reaches production. This automates the enforcement of our security policies, reducing human error and \"automation complacency.\"")
    st.markdown(f"")
    st.markdown(f"The mapping logic is as follows:")
    st.markdown(
        f"- Presence of `HIGH`/`CRITICAL` findings $\\rightarrow$ enforce `CI_SECURITY` gate `BLOCK`.")
    st.markdown(
        f"- Presence of `SECRET` findings $\\rightarrow$ enforce `PRE_COMMIT` secret scanning gate `BLOCK`.")
    st.markdown(f"- Presence of `UNKNOWN` or `DENY` dependencies $\\rightarrow$ enforce `CI_BUILD` or `CI_SECURITY` dependency allowlist gate `BLOCK`.")
    st.markdown(
        f"- Otherwise $\\rightarrow$ `WARN` gating allowed for low risk.")
    st.markdown(f"")
    st.markdown(
        r"Let's define a simple risk score for an artifact to drive decision-making for gating, where $S(f)$ is the severity of finding $f$. We assign weights: $\text{Weight}(\text{CRITICAL}) = 100$, $\text{Weight}(\text{HIGH}) = 50$, $\text{Weight}(\text{MEDIUM}) = 10$, $\text{Weight}(\text{LOW}) = 1$.")
    st.markdown(f"The `ArtifactRiskScore` for an artifact $A$ is then:")
    st.markdown(
        r"$$ \text{ArtifactRiskScore}(A) = \sum_{f \in \text{Findings}(A)} \text{Weight}(S(f)) $$")
    st.markdown(
        r"where $A$ represents a code artifact, $f$ represents a finding, $S(f)$ is the severity of finding $f$, and $\text{Weight}(S(f))$ is the assigned weight for that severity.")
    st.markdown(
        f"This quantitative score helps to aggregate risk across an artifact and inform the gating decision.")
    st.markdown(f"---")
    if not st.session_state.analysis_performed or not st.session_state.sdlc_gate_plan_yaml_state:
        st.warning(
            "No gate plan generated. Please go to 'Analysis Dashboard' to run an analysis.")
    else:
        st.subheader("Generated CI/CD Gate Plan (YAML Preview)")
        st.code(st.session_state.sdlc_gate_plan_yaml_state,
                language="yaml", height=600)
        st.markdown(f"")
        st.markdown(f"The generated YAML output provides a clear, machine-readable `sdlc_control_plan.yaml`. Based on the critical findings (secrets, dangerous execution, denylisted dependencies) identified earlier, the `CI_SECURITY` and `PRE_COMMIT` gates are correctly configured to `BLOCK` the pipeline. This means if any AI-generated code introduces similar vulnerabilities in the future, our pipeline will automatically prevent it from progressing. For me, this is the ultimate goal: automating security enforcement to build a more resilient and secure development process. This plan directly translates my analysis into organizational security policy.")

elif st.session_state.current_page == "Exports & Evidence":
    st.title("Consolidating Findings and Exporting Auditable Results")
    st.markdown(f"The final step in my workflow is to consolidate all findings and artifacts into a comprehensive set of auditable reports. This includes JSON files for detailed findings and dependency risks, the YAML gate plan, and a markdown executive summary. Crucially, I also need to generate an `evidence_manifest.json` that hashes all inputs and outputs, providing an immutable record for auditing and compliance.")
    st.markdown(f"")
    st.markdown(f"As a developer in a security-conscious organization, documentation and auditability are paramount. It's not enough to just find vulnerabilities; I need to provide clear, structured evidence of what was found, where, how it was remediated, and what controls are in place. These export formats (`.json`, `.yaml`, `.md`) are designed to be consumed by different stakeholders: developers for remediation, DevSecOps for pipeline configuration, and leadership for risk oversight. The `evidence_manifest.json` serves as the ultimate proof-of-work, hashing every piece of input and output to ensure non-repudiation and integrity for auditors.")
    st.markdown(f"")
    st.markdown(f"The `inputs_hash` combines the hashes of all `CodeArtifact` contents. The `outputs_hash` combines the hashes of the generated JSON and YAML reports. This creates a chain of custody for the audit.")
    st.markdown(
        r"$$ \text{inputs\_hash} = \text{SHA256}(\text{Concat}(\text{CodeArtifact}_1.\text{content\_hash}, \dots, \text{CodeArtifact}_N.\text{content\_hash})) $$")
    st.markdown(
        r"$$ \text{outputs\_hash} = \text{SHA256}(\text{Concat}(\text{Hash}(\text{findings.json}), \text{Hash}(\text{deps.json}), \text{Hash}(\text{gateplan.yaml}))) $$")
    st.markdown(f"---")
    if not st.session_state.analysis_performed:
        st.warning(
            "No reports generated. Please go to 'Analysis Dashboard' to run an analysis.")
    else:
        st.subheader("Download Auditable Reports")

        # Generate Zip button and workflow
        if not st.session_state.zip_generated:
            # Check if we need to auto-clear from previous download
            if st.session_state.auto_clear_next:
                st.session_state.zip_generated = False
                st.session_state.zip_data = None
                st.session_state.zip_size = 0
                st.session_state.auto_clear_next = False
            
            if st.button("Generate Zip", type="primary"):
                # Create zip file in memory
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    # Add all artifacts
                    for artifact in st.session_state.all_artifacts_state:
                        zip_file.writestr(
                            f"artifacts/{artifact.filename}", artifact.content)

                    # Add reports
                    zip_file.writestr(
                        "code_gen_risk_findings.json", st.session_state.findings_json_content_state)
                    zip_file.writestr(
                        "dependency_risk_report.json", st.session_state.dependency_report_json_content_state)
                    zip_file.writestr("sdlc_control_plan.yaml",
                                      st.session_state.sdlc_gate_plan_yaml_state)
                    zip_file.writestr(
                        "case5_executive_summary.md", st.session_state.executive_summary_md_content_state)
                    zip_file.writestr(
                        "evidence_manifest.json", st.session_state.evidence_manifest_json_content_state)

                # Store zip data in session state
                st.session_state.zip_data = zip_buffer.getvalue()
                st.session_state.zip_size = len(st.session_state.zip_data)
                st.session_state.zip_generated = True
                st.rerun()
        else:
            # Show zip size
            size_kb = st.session_state.zip_size / 1024
            size_mb = size_kb / 1024
            if size_mb >= 1:
                size_str = f"{size_mb:.2f} MB"
            else:
                size_str = f"{size_kb:.2f} KB"

            st.info(f"Zip file generated successfully! Size: {size_str}")

            col_zip1, col_zip2, col_zip3 = st.columns([1, 1, 1])
            with col_zip2:
                # Download button - set flag to clear on next rerun
                st.download_button(
                    label="Download Zip",
                    data=st.session_state.zip_data,
                    file_name="audit_reports_package.zip",
                    mime="application/zip",
                    type="primary",
                    use_container_width=True,
                    on_click=lambda: st.session_state.update({"auto_clear_next": True})
                )
        st.markdown(f"---")
        st.markdown(f"")
        st.markdown(f"All necessary audit reports have been successfully generated and are available for download. The detailed JSON reports provide granular data for developers, while the YAML gate plan is ready for our DevSecOps team. The executive summary offers a high-level overview for leadership, and critically, the `evidence_manifest.json` provides an immutable record of this entire analysis, linking inputs to outputs via cryptographic hashes. This ensures that every step of my security audit is verifiable, transparent, and defensible, meeting our organization's strict compliance requirements and solidifying our security posture against the evolving risks of AI-generated code.")


# License
st.caption('''
---
## QuantUniversity License

© QuantUniversity 2025  
This notebook was created for **educational purposes only** and is **not intended for commercial use**.  

- You **may not copy, share, or redistribute** this notebook **without explicit permission** from QuantUniversity.  
- You **may not delete or modify this license cell** without authorization.  
- This notebook was generated using **QuCreate**, an AI-powered assistant.  
- Content generated by AI may contain **hallucinated or incorrect information**. Please **verify before using**.  

All rights reserved. For permissions or commercial licensing, contact: [info@qusandbox.com](mailto:info@qusandbox.com)
''')
