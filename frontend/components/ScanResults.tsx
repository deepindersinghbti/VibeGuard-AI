"use client";

import React from "react";
import { Finding, Severity } from "../types";

interface ScanResultsProps {
    findings: Finding[];
}

const SEVERITY_COLORS: Record<Severity, string> = {
    critical: "bg-red-100 border-red-300 text-red-900",
    high: "bg-orange-100 border-orange-300 text-orange-900",
    medium: "bg-yellow-100 border-yellow-300 text-yellow-900",
    low: "bg-blue-100 border-blue-300 text-blue-900",
};

const SEVERITY_BADGE: Record<Severity, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-600 text-white",
    medium: "bg-yellow-600 text-white",
    low: "bg-blue-600 text-white",
};

export default function ScanResults({ findings }: ScanResultsProps) {
    if (findings.length === 0) {
        return (
            <div className="mt-8 p-6 bg-green-50 border border-green-200 rounded-lg">
                <h2 className="text-lg font-semibold text-green-900">✓ No issues found</h2>
                <p className="text-green-700 mt-2">The scanned project appears to be secure.</p>
            </div>
        );
    }

    // Group findings by severity
    const groupedByFile: Record<string, Finding[]> = {};
    findings.forEach((finding) => {
        if (!groupedByFile[finding.file]) {
            groupedByFile[finding.file] = [];
        }
        groupedByFile[finding.file].push(finding);
    });

    return (
        <div className="mt-8">
            <h2 className="text-2xl font-bold mb-4">
                {findings.length} Issue{findings.length !== 1 ? "s" : ""} Found
            </h2>

            {Object.entries(groupedByFile).map(([file, fileFinding]) => (
                <div key={file} className="mb-6">
                    <h3 className="text-lg font-semibold text-gray-800 mb-3">{file}</h3>
                    <div className="space-y-3">
                        {fileFinding.map((finding, idx) => (
                            <div
                                key={idx}
                                className={`border-l-4 p-4 rounded ${SEVERITY_COLORS[finding.severity]}`}
                            >
                                <div className="flex items-start justify-between">
                                    <div className="flex-1">
                                        <div className="flex items-center gap-2 mb-2">
                                            <span
                                                className={`px-2 py-1 rounded text-sm font-semibold ${SEVERITY_BADGE[finding.severity]
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
                                    </div>
                                </div>
                            </div>
                        ))}
                    </div>
                </div>
            ))}
        </div>
    );
}
