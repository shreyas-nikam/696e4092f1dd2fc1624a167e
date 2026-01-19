Here's a comprehensive `README.md` file for your Streamlit application lab project, formatted with proper markdown.

---

# QuLab: Case Study 5 - AI-Powered Code Generation Risk Assessment + Secure SDLC Controls

![QuantUniversity Logo](https://www.quantuniversity.com/assets/img/logo5.jpg)

## Project Description

This Streamlit application, "QuLab: Case Study 5," addresses the critical security challenges introduced by AI-powered code generation in modern software development. As AI code assistants become integral to boosting developer productivity, they also bring an increased risk of introducing vulnerabilities, such as hard-coded secrets, insecure dependencies, and unsafe coding patterns.

This project simulates a developer's workflow at "InnovateTech Solutions," demonstrating a proactive approach to identify and mitigate these risks *before* they hit production. The application provides a robust framework for performing static analysis, assessing third-party dependencies, and integrating strong security gates into CI/CD pipelines.

By processing code artifacts, identifying common AI-introduced vulnerabilities, analyzing software dependencies, and generating an automated CI/CD gate plan, this tool aims to enforce security policies and ensure the integrity of AI-assisted codebases. The entire process is designed with auditability in mind, producing structured evidence and reports for compliance and incident response.

## Features

The application provides a comprehensive suite of tools organized into several key modules:

1.  **Application Overview**:
    *   Introduction to the problem and the solution's context.
    *   Explanation of the Pydantic-based data models (`CodeArtifact`, `Finding`, `DependencyRecord`, `SDLCGatePlan`, `EvidenceManifest`) that ensure structured, validated data for security analysis.
    *   Option to run a full analysis with synthetic data for quick demonstration.

2.  **Code Ingestion and Artifact Generation**:
    *   **Flexible Code Input**: Paste code snippets directly or upload individual files (`.py`, `.txt`, `.toml`, `.json`) or entire code repositories as `.zip` archives.
    *   **Source Tagging**: Attribute code origins (e.g., `COPILOT`, `CLAUDE`, `AGENT`, `UNKNOWN`) for better traceability.
    *   **Immutable Code Artifacts**: Automatically generates a `CodeArtifact` for each piece of code, including a unique `artifact_id` and a SHA256 `content_hash` for auditability and integrity verification.

3.  **Findings Dashboard (Static Application Security Testing - SAST)**:
    *   **Vulnerability Detection**: Performs static analysis using both regex-based and Abstract Syntax Tree (AST)-based rules to identify common vulnerabilities (e.g., hard-coded secrets, SQL injection, dangerous `eval()`, unsafe deserialization, weak cryptography).
    *   **Detailed Findings**: Presents findings with severity, type, rule ID, affected file, exact location, evidence snippet, and remediation guidance.
    *   **Interactive Filtering**: Filter findings by severity and finding type for focused review.

4.  **Dependency Analyzer (Software Composition Analysis - SCA)**:
    *   **Dependency Parsing**: Analyzes `requirements.txt`, `pyproject.toml`, and other dependency files to extract package names and versions.
    *   **Risk Categorization**: Checks packages against predefined `allowlist` and `denylist` to identify approved, risky, or unknown dependencies.
    *   **Hallucination Detection**: Identifies potential "hallucinated" or non-existent packages, a common issue with AI-generated dependency lists.

5.  **CI/CD Gate Plan Generator**:
    *   **Automated Gate Plan Creation**: Generates a `sdlc_control_plan.yaml` based on the cumulative security findings and dependency risks.
    *   **Dynamic Gating Logic**: Defines CI/CD gates (e.g., `PRE_COMMIT`, `CI_BUILD`, `CI_SECURITY`) with `BLOCK` or `WARN` actions driven by the severity and type of identified vulnerabilities and dependency statuses.
    *   **Risk Scoring**: Utilizes a quantitative risk score for artifacts to inform gating decisions, ensuring higher-risk changes are blocked.

6.  **Exports & Evidence**:
    *   **Comprehensive Reporting**: Download detailed reports in various formats:
        *   `code_gen_risk_findings.json`: All identified security findings.
        *   `dependency_risk_report.json`: Full dependency analysis report.
        *   `sdlc_control_plan.yaml`: The generated CI/CD gate plan.
        *   `case5_executive_summary.md`: A high-level summary for leadership.
    *   **Auditable Evidence Manifest**: Generates an `evidence_manifest.json` that includes cryptographic SHA256 hashes of all input code artifacts and all generated output reports, ensuring an immutable and verifiable record for auditing and compliance.

## Getting Started

Follow these instructions to set up and run the Streamlit application on your local machine.

### Prerequisites

*   Python 3.8+
*   `pip` (Python package installer)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/quolab-case5-ai-code-risk-assessment.git
    cd quolab-case5-ai-code-risk-assessment
    ```
    *(Replace `your-username/quolab-case5-ai-code-risk-assessment` with the actual repository URL)*

2.  **Create a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    ```

3.  **Install dependencies:**
    The application relies on several Python libraries. It is assumed a `requirements.txt` file exists in the root directory. If not, create one manually with the following contents:

    `requirements.txt`:
    ```
    streamlit>=1.20
    pandas>=1.0
    PyYAML>=6.0
    pydantic>=2.0
    # Add any other libraries imported in source.py if applicable
    ```
    Then run:
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: Ensure `source.py` contains the necessary Pydantic models and helper functions, as implied by `import source` and `from source import *`.)*

## Usage

1.  **Run the Streamlit application:**
    ```bash
    streamlit run app.py
    ```
    This command will start the Streamlit server and automatically open the application in your default web browser (usually `http://localhost:8501`).

2.  **Navigate the Application:**
    *   **Application Overview**: Read the introduction and understand the data models. You can also run a demo analysis with synthetic data from here.
    *   **Code Input**:
        *   Select the **Code Source** (e.g., `COPILOT`, `CLAUDE`).
        *   **Paste code snippets** directly into the text area, or **Upload files** (Python, dependency files like `requirements.txt`, etc., or a `.zip` archive containing multiple files).
        *   Click **"Analyze Code"** to trigger the full assessment pipeline.
    *   **Findings Dashboard**: Review identified static analysis vulnerabilities, filter by severity, and examine detailed remediation guidance.
    *   **Dependency Analyzer**: Inspect the status of declared dependencies, identify denylisted or hallucinated packages.
    *   **Gate Plan Generator**: See the automatically generated CI/CD gate plan in YAML format, outlining security controls based on the analysis.
    *   **Exports & Evidence**: Download all generated reports (JSON, YAML, Markdown) and the crucial `evidence_manifest.json` for auditing.

## Project Structure

```
.
├── app.py                      # Main Streamlit application file
├── source/                     # Directory for core logic and models
│   └── __init__.py             # Makes 'source' a Python package
│   └── source.py               # Contains Pydantic data models, static analysis rules,
│                               # dependency analysis logic, gate plan generation,
│                               # and utility functions.
├── requirements.txt            # Python dependencies for the project
└── README.md                   # This README file
```

The `source/source.py` module is critical and is expected to contain:
*   Pydantic models for `CodeArtifact`, `Finding`, `DependencyRecord`, `SDLCGatePlan`, `EvidenceManifest`, `GateType`, `FindingType`, `Severity`.
*   Static analysis rules (regex and AST patterns).
*   Functions for generating code artifacts, performing SAST, analyzing dependencies, and creating the CI/CD gate plan.
*   Logic for generating the executive summary and evidence manifest.
*   Synthetic data used for demonstration purposes.

## Technology Stack

*   **Python**: The core programming language.
*   **Streamlit**: For building the interactive web application interface.
*   **Pydantic**: For data validation and settings management, ensuring robust and type-safe data models.
*   **Pandas**: For efficient data manipulation and display in DataFrames within Streamlit.
*   **PyYAML**: For handling YAML serialization/deserialization, especially for the CI/CD gate plan.
*   **JSON**: For data interchange and report generation.
*   **`hashlib`**: For generating cryptographic hashes (SHA256) to ensure data integrity and auditability.
*   **`zipfile`**: For handling `.zip` archive uploads.
*   **`io`, `os`, `shutil`, `tempfile`**: For various file system operations and temporary file handling.
*   **Custom `source` Module**: Encapsulates the core business logic, data models, and security analysis algorithms.

## Contributing

Contributions are welcome! If you have suggestions for improvements, new features, or bug fixes, please follow these steps:

1.  Fork the repository.
2.  Create a new branch (`git checkout -b feature/your-feature-name`).
3.  Make your changes.
4.  Commit your changes (`git commit -m 'Add new feature'`).
5.  Push to the branch (`git push origin feature/your-feature-name`).
6.  Open a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
*(Note: You will need to create a `LICENSE` file in the root of your repository if it doesn't exist.)*

## Contact

For any questions or inquiries, please contact:

*   **QuantUniversity**
*   **Project Maintainer**: [Your Name/Email/GitHub Profile] (e.g., `srikanth@quantuniversity.com` or `github.com/srikanthchelluri`)

---