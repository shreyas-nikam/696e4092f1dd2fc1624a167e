
import pytest
from streamlit.testing.v1 import AppTest
import zipfile
import io
import os
import sys

# Add the directory containing app.py and source.py to the Python path
# This assumes app.py and source.py are in the same directory as the test file
# If they are in a different location, adjust this path accordingly.
sys.path.append(os.path.dirname(os.path.abspath(__file__)))


# Helper function to create a zip file in memory for testing file uploads
def create_zip_file(files_dict):
    """
    Creates an in-memory zip file from a dictionary of filenames and contents.
    files_dict: dict of {filename: content_string}
    Returns: BytesIO object containing the zip file.
    """
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files_dict.items():
            zf.writestr(filename, content)
    zip_buffer.seek(0)
    return zip_buffer


def test_initial_app_load():
    """Verifies the initial state and default page on app load."""
    at = AppTest.from_file("app.py").run()
    assert at.title[0].value == "QuLab: Case Study 5: AI-Powered Code Generation Risk Assessment + Secure SDLC Controls"
    assert at.session_state["current_page"] == "Application Overview"
    assert at.markdown[2].value.startswith("## Introduction: Proactive Security for AI-Assisted Development")
    assert not at.session_state["analysis_performed"]


def test_navigation_to_code_input():
    """Tests navigation from Overview to Code Input page."""
    at = AppTest.from_file("app.py").run()

    # Navigate to "Code Input"
    at.selectbox[0].set_value("Code Input").run()
    assert at.session_state["current_page"] == "Code Input"
    assert at.title[0].value == "Code Ingestion and Artifact Generation"
    assert at.radio[0].value == "UNKNOWN"


def test_run_analysis_with_synthetic_data():
    """Tests the 'Run Analysis with Synthetic Data (Demo)' button on the overview page."""
    at = AppTest.from_file("app.py").run()

    # Click the synthetic data button
    at.button[0].click().run()

    assert at.session_state["analysis_performed"]
    assert at.session_state["current_page"] == "Findings Dashboard"
    assert len(at.session_state["all_artifacts_state"]) > 0
    assert len(at.session_state["all_findings_state"]) > 0
    assert len(at.session_state["all_dependencies_state"]) > 0
    assert at.session_state["sdlc_gate_plan_state"] is not None
    assert "findings_json_content_state" in at.session_state
    assert "inputs_hash_state" in at.session_state


def test_code_input_text_area_and_analysis():
    """Tests code input via text area and running analysis."""
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("Code Input").run()

    test_code = "# Sensitive code\nAPI_KEY = 'my_secret_key'\ndef process(data):\n    print(data)\n"
    at.text_area[0].set_value(test_code).run()
    at.radio[0].set_value("COPILOT").run() # Set source tag

    at.button[0].click().run() # Click Analyze Code button

    assert at.session_state["analysis_performed"]
    assert at.session_state["current_page"] == "Findings Dashboard"
    assert len(at.session_state["all_artifacts_state"]) > 0
    assert any(a.content == test_code for a in at.session_state["all_artifacts_state"])
    assert at.session_state["code_source_tag"] == "COPILOT"


def test_file_upload_python_file_and_analysis():
    """Tests uploading a single Python file and running analysis."""
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("Code Input").run()

    py_file_content = "import os\ndef do_something():\n    pass\n"
    uploaded_file = io.BytesIO(py_file_content.encode('utf-8'))
    uploaded_file.name = "test_module.py"

    at.file_uploader[0].upload(uploaded_file).run()
    at.button[0].click().run()

    assert at.session_state["analysis_performed"]
    assert at.session_state["current_page"] == "Findings Dashboard"
    assert len(at.session_state["uploaded_files_data"]) == 1
    assert at.session_state["uploaded_files_data"][0]['filename'] == "test_module.py"
    assert at.session_state["uploaded_files_data"][0]['content'] == py_file_content
    assert any(a.filename == "test_module.py" for a in at.session_state["all_artifacts_state"])


def test_file_upload_zip_file_and_analysis():
    """Tests uploading a zip file containing multiple files and running analysis."""
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("Code Input").run()

    zip_files_content = {
        "src/main.py": "print('Hello')",
        "config.txt": "setting=123"
    }
    zip_buffer = create_zip_file(zip_files_content)
    zip_buffer.name = "my_project.zip"

    at.file_uploader[0].upload(zip_buffer).run()
    at.button[0].click().run()

    assert at.session_state["analysis_performed"]
    assert at.session_state["current_page"] == "Findings Dashboard"
    assert len(at.session_state["uploaded_files_data"]) == 2
    assert any(f['filename'] == "src/main.py" for f in at.session_state["uploaded_files_data"])
    assert any(f['filename'] == "config.txt" for f in at.session_state["uploaded_files_data"])
    assert any(a.filename == "src/main.py" for a in at.session_state["all_artifacts_state"])
    assert any(a.filename == "config.txt" for a in at.session_state["all_artifacts_state"])


def test_analyze_code_button_no_input_warning():
    """Tests clicking 'Analyze Code' with no input shows a warning."""
    at = AppTest.from_file("app.py").run()
    at.selectbox[0].set_value("Code Input").run()

    # Ensure text area is empty and no files are uploaded
    at.text_area[0].set_value("").run()
    at.session_state["uploaded_files_data"] = [] # Clear session state if previous tests left data

    at.button[0].click().run()

    assert not at.session_state["analysis_performed"]
    assert at.warning[0].value == "Please provide some code (snippet or file upload) or run with synthetic data from the Overview page to perform analysis."


def test_findings_dashboard_display_and_filters():
    """Tests Findings Dashboard display, filters, and detail selection."""
    at = AppTest.from_file("app.py").run()
    at.button[0].click().run() # Run analysis with synthetic data to populate findings

    assert at.session_state["current_page"] == "Findings Dashboard"
    assert at.subheader[0].value.startswith("Total Findings:")
    assert len(at.dataframe) > 0 # Check if dataframe of findings is present

    # Test severity filter (assuming synthetic data has CRITICAL findings)
    at.multiselect[0].set_values(["CRITICAL"]).run()
    assert at.dataframe[0].value.apply(lambda x: x["severity"] == "CRITICAL", axis=1).all()

    # Test finding type filter (assuming synthetic data has SECRET findings)
    at.multiselect[1].set_values(["SECRET"]).run()
    df_filtered = at.dataframe[0].value
    assert df_filtered["finding_type"].isin(["SECRET"]).all()

    # Test selectbox for finding details
    if not df_filtered.empty:
        selected_finding_idx = 0
        at.selectbox[1].set_value(selected_finding_idx).run()
        # Verify details are displayed (e.g., description, evidence snippet)
        assert at.markdown[3].value.startswith("**Description:**")
        assert at.code[0].value == df_filtered.iloc[selected_finding_idx]["evidence_snippet"]


def test_dependency_analyzer_display_and_filters():
    """Tests Dependency Analyzer display and filters."""
    at = AppTest.from_file("app.py").run()
    at.button[0].click().run() # Run analysis with synthetic data

    at.selectbox[0].set_value("Dependency Analyzer").run()
    assert at.session_state["current_page"] == "Dependency Analyzer"
    assert at.subheader[0].value.startswith("Total Dependencies Found:")
    assert len(at.dataframe) > 0 # Check if dataframe of dependencies is present

    # Test status filter (assuming synthetic data has DENY dependencies)
    at.multiselect[0].set_values(["DENY"]).run()
    assert at.dataframe[0].value.apply(lambda x: x["status"] == "DENY", axis=1).all()

    # Test hallucination risk checkbox
    at.checkbox[0].check().run()
    df_filtered = at.dataframe[0].value
    assert df_filtered["Hallucination Risk"].isin(["Yes"]).all()


def test_gate_plan_generator_display():
    """Tests Gate Plan Generator displays YAML content."""
    at = AppTest.from_file("app.py").run()
    at.button[0].click().run() # Run analysis with synthetic data

    at.selectbox[0].set_value("Gate Plan Generator").run()
    assert at.session_state["current_page"] == "Gate Plan Generator"
    assert at.code[0].value == at.session_state["sdlc_gate_plan_yaml_state"]
    assert "action: BLOCK" in at.code[0].value or "action: WARN" in at.code[0].value


def test_exports_and_evidence_display():
    """Tests Exports & Evidence page displays hashes and download buttons."""
    at = AppTest.from_file("app.py").run()
    at.button[0].click().run() # Run analysis with synthetic data

    at.selectbox[0].set_value("Exports & Evidence").run()
    assert at.session_state["current_page"] == "Exports & Evidence"

    # Check for download buttons (cannot actually download, but can assert their existence)
    assert at.download_button[0].label == "Findings JSON"
    assert at.download_button[1].label == "Dependencies JSON"
    assert at.download_button[2].label == "Gate Plan YAML"
    assert at.download_button[3].label == "Executive Summary MD"
    assert at.download_button[4].label == "Evidence Manifest JSON"

    # Check if hashes are displayed
    assert at.markdown[4].value == f"**Inputs Hash (SHA256):** `{at.session_state['inputs_hash_state']}`"
    assert at.markdown[5].value == f"**Outputs Hash (SHA256):** `{at.session_state['outputs_hash_state']}`"

