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


def run_full_analysis():
    source.all_artifacts.clear()
    source.all_findings.clear()
    source.all_dependencies.clear()

    artifacts_to_process = []
    if st.session_state.code_input_text:
        artifact = source.generate_code_artifact(
            "snippet.py", st.session_state.code_input_text, st.session_state.code_source_tag)
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

    artifacts_for_sast = [a for a in source.all_artifacts if a.language ==
                          "python" and not a.filename.endswith(('.txt', '.toml', '.json'))]
    artifacts_for_deps = [a for a in source.all_artifacts if a.filename.endswith(
        ('.txt', '.toml', '.json'))]

    for artifact in artifacts_for_sast:
        source.find_vulnerabilities_regex(artifact, source.STATIC_RULES)
    for artifact in artifacts_for_sast:
        source.find_vulnerabilities_ast(artifact, source.STATIC_RULES)
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


elif st.session_state.current_page == "Code Input":
    st.title("Code Ingestion and Artifact Generation")
    st.markdown(f"As a developer, my first practical step is to get the code into a format I can analyze. This often means ingesting raw code snippets or files from a repository, creating a standard `CodeArtifact` record for each. This process includes generating a unique `artifact_id` and a content hash (SHA256). The content hash is particularly important for auditability; it's our digital fingerprint of the exact code state at the time of analysis, ensuring that our findings always refer to an immutable piece of evidence.")
    st.markdown(f"")
    st.markdown(f"When AI assists in code generation, I need a reliable way to track exactly *which* code was analyzed. Imagine an AI generating 50 lines of code; I need to ensure that if a vulnerability is found, I can point directly to the exact version of that code. The `content_hash` serves as this unalterable reference. It’s a cryptographic integrity check, ensuring the code hasn't been tampered with since analysis. For instance, if an auditor later questions a finding, I can provide the hash and the corresponding code, proving the finding's validity against that specific version. The `artifact_id` provides a unique identifier for each piece of code, simplifying tracking across multiple analysis runs.")
    st.markdown(f"")
    st.markdown(f"---")
    st.subheader("Provide Code for Analysis")
    st.markdown(f"**Step 1: Tag the Source**")
    st.session_state.code_source_tag = st.radio(
        "Who generated this code?",
        ("COPILOT", "CLAUDE", "AGENT", "UNKNOWN"),
        index=("COPILOT", "CLAUDE", "AGENT", "UNKNOWN").index(
            st.session_state.code_source_tag),
        horizontal=True
    )
    st.markdown(f"**Step 2: Enter Code**")
    col1, col2 = st.columns(2)
    with col1:
        st.session_state.code_input_text = st.text_area(
            "Paste code snippet here (e.g., Python, requirements.txt, pyproject.toml)",
            value=st.session_state.code_input_text,
            height=300,
            placeholder="# Example Python snippet\nimport os\nAPI_KEY = \"sk-A1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6\"\ndef risky_func(data):\n    eval(data)\n"
        )
    with col2:
        uploaded_files = st.file_uploader(
            "Upload code files (e.g., .py, .txt, .toml, .json) or a .zip repository",
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
            st.info(
                f"Loaded {len(st.session_state.uploaded_files_data)} files from upload(s).")
        elif st.session_state.uploaded_files_data:
            st.info(
                f"Using {len(st.session_state.uploaded_files_data)} previously uploaded files.")
    st.markdown(f"**Step 3: Run Analysis**")
    if st.button("Analyze Code"):
        if not st.session_state.code_input_text and not st.session_state.uploaded_files_data:
            st.warning(
                "Please provide some code (snippet or file upload) or run with synthetic data from the Overview page to perform analysis.")
        else:
            with st.spinner("Running static analysis and dependency checks... This may take a moment."):
                run_full_analysis()
            st.success(
                "Analysis complete! Redirecting to Findings Dashboard...")
            st.session_state.current_page = "Findings Dashboard"
            st.rerun()
    st.markdown(f"---")
    if st.session_state.all_artifacts_state:
        st.subheader("Generated Code Artifacts:")
        df_artifacts = pd.DataFrame([
            {"Filename": a.filename, "Source": a.source,
                "Content Hash (SHA256)": a.content_hash[:10] + "...", "Created At": a.created_at.strftime("%Y-%m-%d %H:%M")}
            for a in st.session_state.all_artifacts_state
        ])
        st.dataframe(df_artifacts, use_container_width=True)



elif st.session_state.current_page == "Gate Plan Generator":
    st.title("CI/CD Gate Plan Generation")
    st.markdown(f"With all the vulnerabilities and dependency risks identified, the next critical step is to translate these findings into actionable controls for our CI/CD pipeline. This means generating a `sdlc_control_plan.yaml` that defines specific \"gates\" – automated checks that will either `BLOCK` a deployment or issue a `WARN` based on the severity and type of findings. This ensures that security isn't just an afterthought but an integrated part of our Software Development Lifecycle (SDLC).")
    st.markdown(f"")
    st.markdown(f"My analysis is only useful if it leads to concrete actions. Generating a CI/CD gate plan is where the rubber meets the road. If I find a `CRITICAL` secret or a `HIGH` risk dependency, the pipeline must `BLOCK` the build immediately. For lower-severity issues, a `WARN` might suffice to notify the team without halting development. This YAML plan becomes the blueprint for our automated security controls, ensuring that every piece of AI-generated code, and any changes, passes a strict security review before it ever reaches production. This automates the enforcement of our security policies, reducing human error and \"automation complacency.\"")
    st.markdown(f"")
    st.markdown(f"The mapping logic is as follows:")
    st.markdown(
        f"- Presence of `HIGH`/`CRITICAL` findings $\rightarrow$ enforce `CI_SECURITY` gate `BLOCK`.")
    st.markdown(
        f"- Presence of `SECRET` findings $\rightarrow$ enforce `PRE_COMMIT` secret scanning gate `BLOCK`.")
    st.markdown(f"- Presence of `UNKNOWN` or `DENY` dependencies $\rightarrow$ enforce `CI_BUILD` or `CI_SECURITY` dependency allowlist gate `BLOCK`.")
    st.markdown(f"- Otherwise $\rightarrow$ `WARN` gating allowed for low risk.")
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
        st.warning("No gate plan generated. Please go to 'Code Input' to run an analysis or click 'Run Analysis with Synthetic Data (Demo)' on the Overview page.")
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
    st.markdown(f"As a developer in a security-conscious organization, documentation and auditability are paramount. It’s not enough to just find vulnerabilities; I need to provide clear, structured evidence of what was found, where, how it was remediated, and what controls are in place. These export formats (`.json`, `.yaml`, `.md`) are designed to be consumed by different stakeholders: developers for remediation, DevSecOps for pipeline configuration, and leadership for risk oversight. The `evidence_manifest.json` serves as the ultimate proof-of-work, hashing every piece of input and output to ensure non-repudiation and integrity for auditors.")
    st.markdown(f"")
    st.markdown(f"The `inputs_hash` combines the hashes of all `CodeArtifact` contents. The `outputs_hash` combines the hashes of the generated JSON and YAML reports. This creates a chain of custody for the audit.")
    st.markdown(
        r"$$ \text{inputs\_hash} = \text{SHA256}(\text{Concat}(\text{CodeArtifact}_1.\text{content\_hash}, \dots, \text{CodeArtifact}_N.\text{content\_hash})) $$")
    st.markdown(
        r"$$ \text{outputs\_hash} = \text{SHA256}(\text{Concat}(\text{Hash}(\text{findings.json}), \text{Hash}(\text{deps.json}), \text{Hash}(\text{gateplan.yaml}))) $$")
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
        st.markdown(
            f"**Inputs Hash (SHA256):** `{st.session_state.inputs_hash_state}`")
        st.markdown(
            f"**Outputs Hash (SHA256):** `{st.session_state.outputs_hash_state}`")
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
