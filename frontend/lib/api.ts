// API client for backend communication.

import { Finding, ScanError } from "../types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

export async function uploadZipFile(file: File): Promise<Finding[]> {
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

    const findings: Finding[] = await response.json();
    return findings;
}
