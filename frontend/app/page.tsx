"use client";

import React, { useState } from "react";
import { scanGitHubRepo, uploadZipFile } from "../lib/api";
import ScanResults from "../components/ScanResults";
import { Finding, ScanSummary } from "../types";

type ScanMode = "zip" | "github";

export default function Home() {
    const [scanMode, setScanMode] = useState<ScanMode>("zip");
    const [file, setFile] = useState<File | null>(null);
    const [repoUrl, setRepoUrl] = useState("");
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [findings, setFindings] = useState<Finding[]>([]);
    const [summary, setSummary] = useState<ScanSummary | null>(null);
    const [scanned, setScanned] = useState(false);

    const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
        const selectedFile = e.target.files?.[0];
        if (selectedFile) {
            if (selectedFile.name.toLowerCase().endsWith(".zip")) {
                setFile(selectedFile);
                setError(null);
            } else {
                setError("Please select a .zip file");
                setFile(null);
            }
        }
    };

    const handleScan = async () => {
        if (scanMode === "zip" && !file) {
            setError("Please select a file first");
            return;
        }
        if (scanMode === "github" && !repoUrl.trim()) {
            setError("Please enter a GitHub repository URL");
            return;
        }

        setLoading(true);
        setError(null);
        setSummary(null);
        setScanned(false);

        try {
            const results =
                scanMode === "zip"
                    ? await uploadZipFile(file as File)
                    : await scanGitHubRepo(repoUrl.trim());
            setFindings(results.findings);
            setSummary(results.summary);
            setScanned(true);
        } catch (err) {
            setError(
                err instanceof Error ? err.message : "An error occurred during scanning"
            );
            setScanned(true);
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 py-12 px-4">
            <div className="max-w-4xl mx-auto">
                {/* Header */}
                <div className="text-center mb-12">
                    <h1 className="text-4xl font-bold text-gray-900 mb-2">VibeGuard AI</h1>
                    <p className="text-xl text-gray-600">
                        Static Security Scanner for Source Code
                    </p>
                </div>

                {/* Main Card */}
                <div className="bg-white rounded-lg shadow-lg p-8 mb-8">
                    {/* Upload Section */}
                    <div className="mb-8">
                        <div className="mb-6 flex rounded border border-gray-200 overflow-hidden">
                            <button
                                type="button"
                                onClick={() => setScanMode("zip")}
                                disabled={loading}
                                className={`flex-1 px-4 py-2 text-sm font-semibold ${
                                    scanMode === "zip"
                                        ? "bg-blue-600 text-white"
                                        : "bg-white text-gray-700 hover:bg-gray-50"
                                } disabled:opacity-50`}
                            >
                                Upload ZIP
                            </button>
                            <button
                                type="button"
                                onClick={() => setScanMode("github")}
                                disabled={loading}
                                className={`flex-1 px-4 py-2 text-sm font-semibold ${
                                    scanMode === "github"
                                        ? "bg-blue-600 text-white"
                                        : "bg-white text-gray-700 hover:bg-gray-50"
                                } disabled:opacity-50`}
                            >
                                GitHub URL
                            </button>
                        </div>

                        {scanMode === "zip" && (
                            <label className="block mb-4">
                                <span className="text-lg font-semibold text-gray-700 block mb-4">
                                    Upload a ZIP file to scan
                                </span>
                                <input
                                    type="file"
                                    accept=".zip"
                                    onChange={handleFileChange}
                                    disabled={loading}
                                    className="block w-full text-sm text-gray-500 file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:font-semibold file:bg-blue-50 file:text-blue-700 hover:file:bg-blue-100 disabled:opacity-50"
                                />
                            </label>
                        )}

                        {scanMode === "github" && (
                            <label className="block mb-4">
                                <span className="text-lg font-semibold text-gray-700 block mb-4">
                                    Public GitHub repository URL
                                </span>
                                <input
                                    type="url"
                                    value={repoUrl}
                                    onChange={(event) => {
                                        setRepoUrl(event.target.value);
                                        setError(null);
                                    }}
                                    disabled={loading}
                                    placeholder="https://github.com/owner/repo"
                                    className="block w-full px-3 py-2 border border-gray-300 rounded text-sm text-gray-900 disabled:opacity-50"
                                />
                            </label>
                        )}

                        {scanMode === "zip" && file && (
                            <div className="mb-4 p-3 bg-blue-50 rounded border border-blue-200">
                                <p className="text-sm text-blue-900">
                                    <strong>Selected:</strong> {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
                                </p>
                            </div>
                        )}

                        <button
                            onClick={handleScan}
                            disabled={
                                loading ||
                                (scanMode === "zip" && !file) ||
                                (scanMode === "github" && !repoUrl.trim())
                            }
                            className="w-full px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
                        >
                            {loading ? (
                                <>
                                    <span className="inline-block animate-spin mr-2">⏳</span>
                                    Scanning...
                                </>
                            ) : (
                                scanMode === "zip" ? "Scan ZIP File" : "Scan GitHub Repository"
                            )}
                        </button>
                    </div>

                    {/* Error Display */}
                    {error && scanned && (
                        <div className="mb-6 p-4 bg-red-50 border border-red-200 rounded">
                            <p className="text-red-900 font-semibold">Error:</p>
                            <p className="text-red-700 text-sm mt-1">{error}</p>
                        </div>
                    )}

                    {/* Results */}
                    {scanned && !error && summary && (
                        <ScanResults summary={summary} findings={findings} />
                    )}
                </div>

                {/* Info Section */}
                <div className="bg-white rounded-lg shadow p-6">
                    <h3 className="text-lg font-semibold text-gray-900 mb-4">About</h3>
                    <ul className="space-y-2 text-sm text-gray-700">
                        <li>
                            ✓ Detects hardcoded API keys, secrets, and credentials
                        </li>
                        <li>
                            ✓ Identifies dangerous code patterns (eval, exec, shell commands)
                        </li>
                        <li>
                            ✓ Flags CORS misconfigurations and environment file exposure
                        </li>
                        <li>
                            ✓ Scans Python, JavaScript, TypeScript, and configuration files
                        </li>
                        <li>
                            ✓ Maximum file size: 25MB
                        </li>
                    </ul>
                </div>
            </div>
        </div>
    );
}
