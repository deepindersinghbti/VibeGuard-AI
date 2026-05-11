"use client";

import React from "react";
import { explainFinding } from "../lib/api";
import { ExplainResponse, Finding, ScanSummary, Severity } from "../types";

interface ScanResultsProps {
    summary: ScanSummary;
    findings: Finding[];
}

const SEVERITY_COLORS: Record<Severity, string> = {
    critical: "bg-red-100 border-red-300 text-red-900",
    high: "bg-orange-100 border-orange-300 text-orange-900",
    medium: "bg-yellow-100 border-yellow-300 text-yellow-900",
    low: "bg-green-100 border-green-300 text-green-900",
};

const SEVERITY_BADGE: Record<Severity, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-600 text-white",
    medium: "bg-yellow-600 text-white",
    low: "bg-green-600 text-white",
};

const SUMMARY_COUNT_COLORS: Record<Severity, string> = {
    critical: "text-red-700",
    high: "text-orange-700",
    medium: "text-yellow-700",
    low: "text-green-700",
};

function scoreColor(score: number): string {
    if (score >= 80) {
        return "bg-green-600";
    }
    if (score >= 50) {
        return "bg-yellow-500";
    }
    return "bg-red-600";
}

function ScanSummaryPanel({ summary }: { summary: ScanSummary }) {
    return (
        <div className="mb-8 p-5 border border-gray-200 rounded-lg bg-gray-50">
            <h2 className="text-xl font-bold text-gray-900 mb-4">Scan Summary</h2>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-5">
                <div>
                    <p className="text-sm text-gray-600">Total Issues</p>
                    <p className="text-2xl font-bold text-gray-900">{summary.total}</p>
                </div>
                {(["critical", "high", "medium", "low"] as Severity[]).map((severity) => (
                    <div key={severity}>
                        <p className="text-sm text-gray-600 capitalize">{severity}</p>
                        <p className={`text-2xl font-bold ${SUMMARY_COUNT_COLORS[severity]}`}>
                            {summary[severity]}
                        </p>
                    </div>
                ))}
            </div>
            <div>
                <div className="flex items-center justify-between mb-2">
                    <p className="font-semibold text-gray-800">Security Score</p>
                    <p className="font-bold text-gray-900">{summary.score} / 100</p>
                </div>
                <div className="h-3 bg-gray-200 rounded overflow-hidden">
                    <div
                        className={`h-full ${scoreColor(summary.score)}`}
                        style={{ width: `${summary.score}%` }}
                    />
                </div>
            </div>
        </div>
    );
}

export default function ScanResults({ summary, findings }: ScanResultsProps) {
    const [explanations, setExplanations] = React.useState<Record<string, ExplainResponse>>({});
    const [loadingExplanations, setLoadingExplanations] = React.useState<Record<string, boolean>>({});
    const [openExplanations, setOpenExplanations] = React.useState<Record<string, boolean>>({});

    const findingKey = (finding: Finding, idx: number) =>
        `${finding.rule_id}:${finding.file}:${finding.line}:${idx}`;

    const handleExplain = async (finding: Finding, key: string) => {
        setOpenExplanations((current) => ({ ...current, [key]: true }));

        if (loadingExplanations[key] || explanations[key]) {
            return;
        }

        setLoadingExplanations((current) => ({ ...current, [key]: true }));
        try {
            const explanation = await explainFinding(finding);
            setExplanations((current) => ({ ...current, [key]: explanation }));
        } catch {
            setExplanations((current) => ({
                ...current,
                [key]: {
                    explanation:
                        "AI explanation is currently unavailable. Refer to the recommendation above.",
                    attack_scenario: "",
                    fix_details: "",
                },
            }));
        } finally {
            setLoadingExplanations((current) => ({ ...current, [key]: false }));
        }
    };

    if (findings.length === 0) {
        return (
            <div className="mt-8">
                <ScanSummaryPanel summary={summary} />
                <div className="p-6 bg-green-50 border border-green-200 rounded-lg">
                    <h2 className="text-lg font-semibold text-green-900">No issues found</h2>
                    <p className="text-green-700 mt-2">The scanned project appears to be secure.</p>
                </div>
            </div>
        );
    }

    const groupedByFile: Record<string, Finding[]> = {};
    findings.forEach((finding) => {
        if (!groupedByFile[finding.file]) {
            groupedByFile[finding.file] = [];
        }
        groupedByFile[finding.file].push(finding);
    });

    return (
        <div className="mt-8">
            <ScanSummaryPanel summary={summary} />

            <h2 className="text-2xl font-bold mb-4">
                {findings.length} Issue{findings.length !== 1 ? "s" : ""} Found
            </h2>

            {Object.entries(groupedByFile).map(([file, fileFinding]) => (
                <div key={file} className="mb-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-3">{file}</h3>
                    <div className="space-y-3">
                        {fileFinding.map((finding, idx) => {
                            const key = findingKey(finding, idx);
                            const explanation = explanations[key];
                            const isLoading = loadingExplanations[key];
                            const isOpen = openExplanations[key];

                            return (
                            <div
                                key={key}
                                className={`border-l-4 p-4 rounded ${SEVERITY_COLORS[finding.severity]}`}
                            >
                                <div className="flex items-start justify-between">
                                    <div className="flex-1">
                                        <div className="flex items-center gap-2 mb-2">
                                            <span
                                                className={`px-2 py-1 rounded text-sm font-semibold ${
                                                    SEVERITY_BADGE[finding.severity]
                                                }`}
                                            >
                                                {finding.severity.toUpperCase()}
                                            </span>
                                            <span className="text-sm font-mono text-gray-600">
                                                Line {finding.line}
                                            </span>
                                        </div>
                                        <h4 className="font-semibold mb-2">{finding.title}</h4>
                                        <div className="bg-gray-100 p-2 rounded mb-2 font-mono text-sm overflow-x-auto">
                                            {finding.evidence}
                                        </div>
                                        <p className="text-sm mb-2">
                                            <strong>Category:</strong> {finding.category}
                                        </p>
                                        <p className="text-sm">
                                            <strong>Fix:</strong> {finding.recommendation}
                                        </p>
                                        <button
                                            type="button"
                                            onClick={() => handleExplain(finding, key)}
                                            disabled={isLoading || Boolean(explanation)}
                                            className="mt-3 px-3 py-2 bg-gray-900 text-white text-sm font-semibold rounded hover:bg-gray-800 disabled:bg-gray-500 disabled:cursor-not-allowed"
                                        >
                                            {isLoading
                                                ? "Generating explanation..."
                                                : explanation
                                                  ? "Explanation generated"
                                                  : "Explain"}
                                        </button>
                                        {isOpen && (
                                            <div className="mt-4 p-4 bg-white border border-gray-200 rounded text-gray-900">
                                                <p className="mb-3 text-xs font-semibold text-gray-500">
                                                    AI explanation only — detection is rule-based
                                                </p>
                                                {isLoading && (
                                                    <p className="text-sm text-gray-600">
                                                        Generating explanation...
                                                    </p>
                                                )}
                                                {explanation && (
                                                    <div className="space-y-3 text-sm">
                                                        <div>
                                                            <h5 className="font-semibold mb-1">
                                                                Why this is dangerous
                                                            </h5>
                                                            <p>{explanation.explanation}</p>
                                                        </div>
                                                        {explanation.attack_scenario && (
                                                            <div>
                                                                <h5 className="font-semibold mb-1">
                                                                    Attack scenario
                                                                </h5>
                                                                <p>{explanation.attack_scenario}</p>
                                                            </div>
                                                        )}
                                                        {explanation.fix_details && (
                                                            <div>
                                                                <h5 className="font-semibold mb-1">
                                                                    How to fix it
                                                                </h5>
                                                                <p>{explanation.fix_details}</p>
                                                            </div>
                                                        )}
                                                    </div>
                                                )}
                                            </div>
                                        )}
                                    </div>
                                </div>
                            </div>
                            );
                        })}
                    </div>
                </div>
            ))}
        </div>
    );
}
