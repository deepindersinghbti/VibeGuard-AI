// API client for backend communication.

import { ExplainResponse, Finding, ScanError, ScanResponse } from "../types";

const DEFAULT_API_BASE_URL = "http://localhost:8000";

function getApiBaseUrl(): string {
    const configuredUrl = process.env.NEXT_PUBLIC_API_BASE_URL?.trim();

    if (configuredUrl) {
        return configuredUrl;
    }

    if (process.env.NODE_ENV === "production") {
        throw new Error("NEXT_PUBLIC_API_BASE_URL is required in production.");
    }

    return DEFAULT_API_BASE_URL;
}

export async function uploadZipFile(file: File): Promise<ScanResponse> {
    const formData = new FormData();
    formData.append("file", file);
    const apiBaseUrl = getApiBaseUrl();

    const response = await fetch(`${apiBaseUrl}/api/v1/scan/zip`, {
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
    const apiBaseUrl = getApiBaseUrl();
    const response = await fetch(`${apiBaseUrl}/api/v1/scan/github`, {
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
    const apiBaseUrl = getApiBaseUrl();
    const response = await fetch(`${apiBaseUrl}/api/v1/explain`, {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
        },
        body: JSON.stringify({
            finding: { rule_id, title, severity, file, line, evidence, recommendation },
        }),
    });

    if (!response.ok) {
        let errorMessage = "Couldn't generate explanation. Please try again.";
        try {
            const errorData = await response.json();
            if (errorData.detail) {
                errorMessage = errorData.detail;
            } else if (errorData.error) {
                errorMessage = errorData.error;
            } else if (errorData.message) {
                errorMessage = errorData.message;
            }
        } catch {
            // If response is not JSON or parsing fails, use default message
        }
        throw new Error(errorMessage);
    }

    const explanation: ExplainResponse = await response.json();

    // Validate that the explanation response has required fields
    if (!explanation.explanation || typeof explanation.explanation !== "string") {
        throw new Error("Invalid explanation response from server. Please try again.");
    }

    return explanation;
}
