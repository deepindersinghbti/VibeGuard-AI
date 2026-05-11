"use client";

import React, { useState } from "react";
import { uploadZipFile } from "../lib/api";
import ScanResults from "../components/ScanResults";
import { Finding } from "../types";

export default function Home() {
    const [file, setFile] = useState<File | null>(null);
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState<string | null>(null);
    const [findings, setFindings] = useState<Finding[]>([]);
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
        if (!file) {
            setError("Please select a file first");
            return;
        }

        setLoading(true);
        setError(null);
        setScanned(false);

        try {
            const results = await uploadZipFile(file);
            setFindings(results);
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

                        {file && (
                            <div className="mb-4 p-3 bg-blue-50 rounded border border-blue-200">
                                <p className="text-sm text-blue-900">
                                    <strong>Selected:</strong> {file.name} ({(file.size / 1024 / 1024).toFixed(2)} MB)
                                </p>
                            </div>
                        )}

                        <button
                            onClick={handleScan}
                            disabled={!file || loading}
                            className="w-full px-6 py-3 bg-blue-600 text-white font-semibold rounded-lg hover:bg-blue-700 disabled:bg-gray-400 disabled:cursor-not-allowed transition-colors"
                        >
                            {loading ? (
                                <>
                                    <span className="inline-block animate-spin mr-2">⏳</span>
                                    Scanning...
                                </>
                            ) : (
                                "Scan ZIP File"
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
                    {scanned && !error && <ScanResults findings={findings} />}
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
