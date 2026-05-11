// API client for backend communication.

import { ExplainResponse, Finding, ScanError, ScanResponse } from "../types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function uploadZipFile(file: File): Promise<ScanResponse> {
    const formData = new FormData();
    formData.append("file", file);

    const response = await fetch(`${API_BASE_URL}/api/v1/scan/zip`, {
        method: "POST",
        body: formData,
    });

    if (!response.ok) {
        const error: ScanError = await response.json();
        throw new Error(error.detail || "Failed to scan ZIP file");
    }

    const scanResponse: ScanResponse = await response.json();
    return scanResponse;
}

export async function scanGitHubRepo(repoUrl: string): Promise<ScanResponse> {
    const response = await fetch(`${API_BASE_URL}/api/v1/scan/github`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({ repo_url: repoUrl }),
    });

    if (!response.ok) {
        const error: ScanError = await response.json();
        throw new Error(error.detail || "Failed to scan GitHub repository");
    }

    const scanResponse: ScanResponse = await response.json();
    return scanResponse;
}

export async function explainFinding(finding: Finding): Promise<ExplainResponse> {
    const { rule_id, title, severity, file, line, evidence, recommendation } = finding;
    const response = await fetch(`${API_BASE_URL}/api/v1/explain`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            finding: { rule_id, title, severity, file, line, evidence, recommendation },
        }),
    });

    if (!response.ok) {
        return {
            explanation: "AI explanation is currently unavailable. Refer to the recommendation above.",
            attack_scenario: "",
            fix_details: "",
        };
    }

    const explanation: ExplainResponse = await response.json();
    return explanation;
}
