"use client";

import React from "react";
import { VibeGuardPdfReport } from "./VibeGuardPdfReport";
import { ExplainResponse, Finding, ScanSummary } from "../../types";
import { buildReportFilename, ScanContext } from "../../utils/reportSummary";

type DownloadPdfReportButtonProps = {
    summary: ScanSummary;
    findings: Finding[];
    explanations: Record<string, ExplainResponse>;
    scanContext: ScanContext;
};

type PDFDownloadLinkComponent = React.ComponentType<{
    document: React.ReactElement;
    fileName: string;
    className?: string;
    children: (params: { loading: boolean; error?: Error | null }) => React.ReactNode;
}>;

const buttonClassName =
    "inline-flex h-9 items-center justify-center rounded-md border border-slate-300 bg-white px-3 text-sm font-semibold text-slate-700 shadow-sm transition hover:border-slate-400 hover:bg-slate-50 hover:text-slate-950 disabled:cursor-not-allowed disabled:border-slate-200 disabled:bg-slate-100 disabled:text-slate-400";

export function DownloadPdfReportButton({
    summary,
    findings,
    explanations,
    scanContext,
}: DownloadPdfReportButtonProps) {
    const [PDFDownloadLink, setPDFDownloadLink] = React.useState<PDFDownloadLinkComponent | null>(null);
    const generatedAt = React.useMemo(() => new Date(), [summary, findings]);

    React.useEffect(() => {
        let mounted = true;

        import("@react-pdf/renderer").then((module) => {
            if (mounted) {
                setPDFDownloadLink(() => module.PDFDownloadLink as PDFDownloadLinkComponent);
            }
        });

        return () => {
            mounted = false;
        };
    }, []);

    if (!PDFDownloadLink) {
        return (
            <button type="button" disabled className={buttonClassName}>
                Preparing PDF...
            </button>
        );
    }

    return (
        <PDFDownloadLink
            document={
                <VibeGuardPdfReport
                    summary={summary}
                    findings={findings}
                    explanations={explanations}
                    scanContext={scanContext}
                    generatedAt={generatedAt}
                />
            }
            fileName={buildReportFilename(generatedAt)}
            className={buttonClassName}
        >
            {({ loading, error }) => {
                if (loading) {
                    return "Preparing PDF...";
                }

                if (error) {
                    return "Retry PDF Report";
                }

                return "Download PDF Report";
            }}
        </PDFDownloadLink>
    );
}
