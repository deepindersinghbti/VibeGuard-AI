"use client";

import React, { useState, useEffect, useRef } from "react";
import { scanGitHubRepo, uploadZipFile } from "../lib/api";
import ScanResults from "../components/ScanResults";
import { Finding, ScanSummary } from "../types";

type ScanMode = "zip" | "github";

export default function Home() {
    const [scanMode, setScanMode] = useState<ScanMode>("zip");
    const [file, setFile] = useState<File | null>(null);
    const [repoUrl, setRepoUrl] = useState("");
    const [loading, setLoading] = useState(false);
    const [showColdStartHint, setShowColdStartHint] = useState(false);
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

    const resetResults = () => {
        setError(null);
        setSummary(null);
        setFindings([]);
        setScanned(false);
    };

    const handleModeChange = (mode: ScanMode) => {
        setScanMode(mode);
        resetResults();
    };

    const handleScan = async () => {
        if (scanMode === "zip" && !file) {
            setError("Please select a file first");
            setScanned(true);
            return;
        }
        if (scanMode === "github" && !repoUrl.trim()) {
            setError("Please enter a GitHub repository URL");
            setScanned(true);
            return;
        }

        setLoading(true);
        setError(null);
        setSummary(null);
        setFindings([]);
        setScanned(false);

        try {
            const results =
                scanMode === "zip"
                    ? await uploadZipFile(file as File)
                    : await scanGitHubRepo(repoUrl.trim());
            setFindings(results.findings);
            setSummary(results.summary);
            setScanned(true);
            try {
                if (typeof window !== "undefined") {
                    sessionStorage.setItem("vg_cold_start_shown", "1");
                }
            } catch (e) {
                // ignore sessionStorage errors
            }
        } catch (err) {
            setError(
                err instanceof Error ? err.message : "An error occurred during scanning"
            );
            setScanned(true);
        } finally {
            setLoading(false);
        }
    };

    const coldStartTimerRef = useRef<number | null>(null);

    useEffect(() => {
        // Only run client-side
        if (typeof window === "undefined") return;

        // If loading starts and we haven't recorded a successful backend response this session,
        // start a delayed timer to show a helpful cold-start hint.
        if (loading) {
            try {
                const alreadyShown = sessionStorage.getItem("vg_cold_start_shown");
                if (!alreadyShown) {
                    coldStartTimerRef.current = window.setTimeout(() => {
                        setShowColdStartHint(true);
                    }, 3500);
                }
            } catch (e) {
                // ignore sessionStorage access errors
            }
        } else {
            // loading finished: clear any pending timer and hide the hint immediately
            if (coldStartTimerRef.current) {
                clearTimeout(coldStartTimerRef.current);
                coldStartTimerRef.current = null;
            }
            setShowColdStartHint(false);
        }

        return () => {
            if (coldStartTimerRef.current) {
                clearTimeout(coldStartTimerRef.current);
                coldStartTimerRef.current = null;
            }
        };
    }, [loading]);

    const loadingText =
        scanMode === "github" ? "Scanning repository..." : "Analyzing files...";

    return (
        <main className="min-h-screen bg-slate-50 text-slate-950">
            <div className="mx-auto max-w-6xl px-4 py-8 sm:px-6 lg:px-8">
                <header className="mb-8">
                    <div className="flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                        <div>
                            <p className="mb-2 text-sm font-semibold uppercase tracking-wide text-blue-700">
                                VibeGuard AI
                            </p>
                            <h1 className="text-3xl font-bold tracking-tight text-slate-950 sm:text-4xl">
                                Static Security Scanner for Code
                            </h1>
                            <p className="mt-3 max-w-2xl text-base text-slate-600">
                                Scan source code for secrets, dangerous patterns, and risky configuration before it ships.
                            </p>
                        </div>
                    </div>
                </header>

                <section className="mb-8 rounded-lg bg-white p-5 shadow-sm ring-1 ring-slate-200 sm:p-6">
                    <div className="mb-5 flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
                        <div>
                            <h2 className="text-lg font-semibold text-slate-950">Choose Scan Source</h2>
                            <p className="mt-1 text-sm text-slate-600">
                                Upload a ZIP or scan a public GitHub repository.
                            </p>
                        </div>
                        <div className="grid grid-cols-2 rounded-md bg-slate-100 p-1">
                            <button
                                type="button"
                                onClick={() => handleModeChange("zip")}
                                disabled={loading}
                                className={`rounded px-4 py-2 text-sm font-semibold transition ${scanMode === "zip"
                                        ? "bg-white text-blue-700 shadow-sm"
                                        : "text-slate-600 hover:text-slate-950"
                                    } disabled:cursor-not-allowed disabled:opacity-50`}
                            >
                                Upload ZIP
                            </button>
                            <button
                                type="button"
                                onClick={() => handleModeChange("github")}
                                disabled={loading}
                                className={`rounded px-4 py-2 text-sm font-semibold transition ${scanMode === "github"
                                        ? "bg-white text-blue-700 shadow-sm"
                                        : "text-slate-600 hover:text-slate-950"
                                    } disabled:cursor-not-allowed disabled:opacity-50`}
                            >
                                GitHub URL
                            </button>
                        </div>
                    </div>

                    <div className="grid gap-4 lg:grid-cols-[1fr_auto] lg:items-end">
                        {scanMode === "zip" ? (
                            <div>
                                <label className="mb-2 block text-sm font-medium text-slate-700">
                                    ZIP file
                                </label>
                                <input
                                    type="file"
                                    accept=".zip"
                                    onChange={handleFileChange}
                                    disabled={loading}
                                    className="block w-full text-sm text-slate-600 file:mr-4 file:rounded file:border-0 file:bg-blue-50 file:px-4 file:py-2 file:text-sm file:font-semibold file:text-blue-700 hover:file:bg-blue-100 disabled:opacity-50"
                                />
                                {file && (
                                    <p className="mt-2 text-sm text-slate-600">
                                        Selected: <span className="font-medium text-slate-900">{file.name}</span>{" "}
                                        ({(file.size / 1024 / 1024).toFixed(2)} MB)
                                    </p>
                                )}
                            </div>
                        ) : (
                            <div>
                                <label className="mb-2 block text-sm font-medium text-slate-700">
                                    Public GitHub repository
                                </label>
                                <input
                                    type="url"
                                    value={repoUrl}
                                    onChange={(event) => {
                                        setRepoUrl(event.target.value);
                                        setError(null);
                                    }}
                                    disabled={loading}
                                    placeholder="https://github.com/owner/repo"
                                    className="block w-full rounded-md border border-slate-300 px-3 py-2 text-sm text-slate-950 shadow-sm outline-none transition placeholder:text-slate-400 focus:border-blue-500 focus:ring-2 focus:ring-blue-100 disabled:bg-slate-100 disabled:opacity-70"
                                />
                            </div>
                        )}

                        <button
                            onClick={handleScan}
                            disabled={
                                loading ||
                                (scanMode === "zip" && !file) ||
                                (scanMode === "github" && !repoUrl.trim())
                            }
                            className="inline-flex h-11 items-center justify-center rounded-md bg-blue-600 px-6 text-sm font-semibold text-white shadow-sm transition hover:bg-blue-700 disabled:cursor-not-allowed disabled:bg-slate-400 lg:min-w-52"
                        >
                            {loading ? (
                                <>
                                    <span className="mr-2 h-4 w-4 animate-spin rounded-full border-2 border-white border-t-transparent" />
                                    {loadingText}
                                </>
                            ) : scanMode === "zip" ? (
                                "Scan ZIP File"
                            ) : (
                                "Scan Repository"
                            )}
                        </button>
                    </div>

                    {loading && (
                        <div className="mt-5 rounded-md bg-blue-50 px-4 py-3 text-sm text-blue-900">
                            {loadingText} This may take a moment for larger projects.
                        </div>
                    )}
                    {showColdStartHint && (
                        <div className="mt-3 rounded-md bg-white px-4 py-3 text-sm text-slate-700 ring-1 ring-slate-100">
                            <p className="font-medium">Waking up the scanner...</p>
                            <p className="mt-1 text-sm text-slate-600">The backend may take a few seconds to start because it is hosted on Render. This usually happens only on the first scan after inactivity.</p>
                        </div>
                    )}
                </section>

                {error && scanned && (
                    <section className="mb-8 rounded-lg bg-red-50 p-4 text-sm ring-1 ring-red-200">
                        <p className="font-semibold text-red-900">Scan failed</p>
                        <p className="mt-1 text-red-700">{error}</p>
                    </section>
                )}

                {scanned && !error && summary && (
                    <ScanResults
                        summary={summary}
                        findings={findings}
                        scanContext={{
                            scanType: scanMode === "zip" ? "ZIP upload" : "GitHub repository scan",
                            sourceName: scanMode === "zip" ? file?.name ?? "Uploaded ZIP file" : repoUrl.trim(),
                        }}
                    />
                )}
            </div>
        </main>
    );
}
