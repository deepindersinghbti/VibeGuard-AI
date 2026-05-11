"use client";

import React from "react";
import { explainFinding } from "../lib/api";
import { ExplainResponse, Finding, ScanSummary, Severity } from "../types";

interface ScanResultsProps {
    summary: ScanSummary;
    findings: Finding[];
}

const SEVERITY_BADGE: Record<Severity, string> = {
    critical: "bg-red-100 text-red-700 ring-red-200",
    high: "bg-orange-100 text-orange-700 ring-orange-200",
    medium: "bg-yellow-100 text-yellow-800 ring-yellow-200",
    low: "bg-green-100 text-green-700 ring-green-200",
};

const SEVERITY_TEXT: Record<Severity, string> = {
    critical: "text-red-700",
    high: "text-orange-700",
    medium: "text-yellow-700",
    low: "text-green-700",
};

const SEVERITY_ACCENT: Record<Severity, string> = {
    critical: "border-red-300",
    high: "border-orange-300",
    medium: "border-yellow-300",
    low: "border-green-300",
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

function riskLabel(score: number): string {
    if (score >= 80) {
        return "Safe";
    }
    if (score >= 50) {
        return "Moderate Risk";
    }
    return "Critical Risk";
}

function summaryMessage(summary: ScanSummary): string {
    if (summary.critical > 0) {
        return "⚠️ Critical issues found. Fix immediately before deploying.";
    }

    if (summary.total > 0) {
        return "⚠️ Some issues found. Review before deploying.";
    }

    return "✅ No security issues found. Your code looks safe.";
}

function ScanSummaryPanel({ summary }: { summary: ScanSummary }) {
    return (
        <section className="sticky top-4 z-10 mb-8 rounded-lg bg-white p-5 shadow-sm ring-1 ring-slate-200">
            <div className="grid gap-5 lg:grid-cols-[220px_1fr] lg:items-center">
                <div>
                    <p className="text-sm font-medium text-slate-500">Security Score</p>
                    <div className="mt-2 flex items-end gap-2">
                        <span className="text-5xl font-bold tracking-tight text-slate-950">
                            {summary.score}
                        </span>
                        <span className="pb-2 text-sm font-semibold text-slate-500">/ 100</span>
                    </div>
                    <p className="mt-2 text-sm font-semibold text-slate-600">
                        Security Score: {summary.score} / 100 ({riskLabel(summary.score)})
                    </p>
                    <div className="mt-4 h-2 overflow-hidden rounded-full bg-slate-200">
                        <div
                            className={`h-full rounded-full ${scoreColor(summary.score)}`}
                            style={{ width: `${summary.score}%` }}
                        />
                    </div>
                    <p className="mt-3 text-sm text-slate-500">{summaryMessage(summary)}</p>
                </div>

                <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
                    <SummaryMetric label="Total issues" value={summary.total} className="text-slate-950" />
                    <SummaryMetric label="Critical" value={summary.critical} className={SEVERITY_TEXT.critical} />
                    <SummaryMetric label="High" value={summary.high} className={SEVERITY_TEXT.high} />
                    <SummaryMetric label="Medium" value={summary.medium} className={SEVERITY_TEXT.medium} />
                    <SummaryMetric label="Low" value={summary.low} className={SEVERITY_TEXT.low} />
                </div>
            </div>
        </section>
    );
}

function SummaryMetric({
    label,
    value,
    className,
}: {
    label: string;
    value: number;
    className: string;
}) {
    return (
        <div className="rounded-md bg-slate-50 px-4 py-3">
            <p className="text-xs font-medium uppercase tracking-wide text-slate-500">{label}</p>
            <p className={`mt-1 text-2xl font-bold ${className}`}>{value}</p>
        </div>
    );
}

function EmptyState({ summary }: { summary: ScanSummary }) {
    return (
        <div className="space-y-8">
            <ScanSummaryPanel summary={summary} />
            <section className="rounded-lg bg-white px-6 py-14 text-center shadow-sm ring-1 ring-slate-200">
                <div className="mx-auto mb-4 flex h-12 w-12 items-center justify-center rounded-full bg-green-100 text-2xl">
                    ✅
                </div>
                <h2 className="text-xl font-semibold text-slate-950">No security issues found</h2>
                <p className="mt-2 text-sm text-slate-600">Your code looks safe.</p>
            </section>
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
        return <EmptyState summary={summary} />;
    }

    const groupedByFile: Record<string, Finding[]> = {};
    findings.forEach((finding) => {
        if (!groupedByFile[finding.file]) {
            groupedByFile[finding.file] = [];
        }
        groupedByFile[finding.file].push(finding);
    });

    return (
        <div>
            <ScanSummaryPanel summary={summary} />

            <section>
                <div className="mb-5 flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between">
                    <div>
                        <h2 className="text-2xl font-bold tracking-tight text-slate-950">Security Findings</h2>
                        <p className="mt-1 text-sm text-slate-600">
                            Findings are grouped by file and sorted by severity.
                        </p>
                    </div>
                    <p className="text-sm font-medium text-slate-500">
                        {findings.length} issue{findings.length !== 1 ? "s" : ""} found
                    </p>
                </div>

                <div className="space-y-8">
                    {Object.entries(groupedByFile).map(([file, fileFindings]) => (
                        <div key={file}>
                            <div className="mb-3 flex items-center justify-between gap-4">
                                <h3 className="min-w-0 flex-1 truncate text-base font-semibold text-slate-900">
                                    {file}
                                </h3>
                                <span className="shrink-0 rounded-full bg-slate-100 px-3 py-1 text-xs font-semibold text-slate-600">
                                    {fileFindings.length} issue{fileFindings.length !== 1 ? "s" : ""}
                                </span>
                            </div>

                            <div className="ml-0 space-y-3 border-l border-slate-200 pl-4 sm:ml-3 sm:pl-5">
                                {fileFindings.map((finding, idx) => {
                                    const key = findingKey(finding, idx);
                                    const explanation = explanations[key];
                                    const isLoading = loadingExplanations[key];
                                    const isOpen = openExplanations[key];

                                    return (
                                        <article
                                            key={key}
                                            className={`rounded-lg border-l-4 bg-white p-5 shadow-sm ring-1 ring-slate-200 ${SEVERITY_ACCENT[finding.severity]}`}
                                        >
                                            <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
                                                <div>
                                                    <div className="mb-2 flex flex-wrap items-center gap-2">
                                                        <span
                                                            className={`rounded-full px-2.5 py-1 text-xs font-bold uppercase tracking-wide ring-1 ${SEVERITY_BADGE[finding.severity]}`}
                                                        >
                                                            {finding.severity}
                                                        </span>
                                                        <span className="text-xs font-medium text-slate-500">
                                                            {finding.file}:{finding.line}
                                                        </span>
                                                    </div>
                                                    <h4 className="text-base font-semibold text-slate-950">
                                                        {finding.title}
                                                    </h4>
                                                </div>
                                                <button
                                                    type="button"
                                                    onClick={() => handleExplain(finding, key)}
                                                    disabled={isLoading || Boolean(explanation)}
                                                    className="inline-flex h-9 items-center justify-center rounded-md border border-slate-700 bg-slate-950 px-3 text-sm font-semibold text-white shadow-sm transition hover:bg-slate-900 hover:shadow disabled:cursor-not-allowed disabled:border-slate-400 disabled:bg-slate-400"
                                                >
                                                    {isLoading
                                                        ? "Generating explanation..."
                                                        : explanation
                                                          ? "Explanation generated"
                                                          : "Explain"}
                                                </button>
                                            </div>

                                            <div className="mt-4 rounded-lg bg-slate-950 p-4 text-sm text-slate-100">
                                                <code className="block overflow-x-auto whitespace-pre-wrap break-words font-mono">
                                                    {finding.evidence}
                                                </code>
                                            </div>

                                            <div className="mt-4 rounded-md bg-slate-50 p-3 text-sm text-slate-700">
                                                <p className="font-semibold text-slate-900">Fix recommendation</p>
                                                <p className="mt-1">{finding.recommendation}</p>
                                            </div>

                                            {isOpen && (
                                                <div className="mt-4 rounded-md bg-blue-50 p-4 text-sm text-slate-800 ring-1 ring-blue-100">
                                                    <div className="mb-3 flex flex-col gap-1 sm:flex-row sm:items-center sm:justify-between">
                                                        <h5 className="font-semibold text-slate-950">
                                                            AI Explanation
                                                        </h5>
                                                        <p className="text-xs font-medium text-slate-500">
                                                            AI explanation only — detection is rule-based
                                                        </p>
                                                    </div>

                                                    {isLoading && (
                                                        <p className="text-slate-600">Generating explanation...</p>
                                                    )}

                                                    {explanation && (
                                                        <div className="space-y-4">
                                                            <div>
                                                                <p className="font-semibold text-slate-900">
                                                                    Why this is dangerous
                                                                </p>
                                                                <p className="mt-1">{explanation.explanation}</p>
                                                            </div>
                                                            {explanation.attack_scenario && (
                                                                <div>
                                                                    <p className="font-semibold text-slate-900">
                                                                        Attack scenario
                                                                    </p>
                                                                    <p className="mt-1">
                                                                        {explanation.attack_scenario}
                                                                    </p>
                                                                </div>
                                                            )}
                                                            {explanation.fix_details && (
                                                                <div>
                                                                    <p className="font-semibold text-slate-900">
                                                                        How to fix it
                                                                    </p>
                                                                    <p className="mt-1">{explanation.fix_details}</p>
                                                                </div>
                                                            )}
                                                        </div>
                                                    )}
                                                </div>
                                            )}
                                        </article>
                                    );
                                })}
                            </div>
                        </div>
                    ))}
                </div>
            </section>
        </div>
    );
}
