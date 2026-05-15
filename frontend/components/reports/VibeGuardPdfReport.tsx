import React from "react";
import { Document, Page, StyleSheet, Text, View } from "@react-pdf/renderer";
import type { Style } from "@react-pdf/types";
import { normalizeExplanation } from "../../lib/normalizeExplanation";
import { ExplainResponse, Finding, ScanSummary, Severity } from "../../types";
import {
    buildExecutiveSummary,
    formatReportDate,
    getFindingReportKey,
    ScanContext,
} from "../../utils/reportSummary";

type VibeGuardPdfReportProps = {
    summary: ScanSummary;
    findings: Finding[];
    explanations: Record<string, ExplainResponse>;
    scanContext: ScanContext;
    generatedAt: Date;
};

const SEVERITY_STYLES: Record<Severity, { badge: Style; accent: Style }> = {
    critical: {
        badge: { backgroundColor: "#fee2e2", color: "#991b1b", borderColor: "#fecaca" },
        accent: { borderLeftColor: "#dc2626" },
    },
    high: {
        badge: { backgroundColor: "#ffedd5", color: "#9a3412", borderColor: "#fed7aa" },
        accent: { borderLeftColor: "#ea580c" },
    },
    medium: {
        badge: { backgroundColor: "#fef3c7", color: "#854d0e", borderColor: "#fde68a" },
        accent: { borderLeftColor: "#d97706" },
    },
    low: {
        badge: { backgroundColor: "#dcfce7", color: "#166534", borderColor: "#bbf7d0" },
        accent: { borderLeftColor: "#16a34a" },
    },
};

const styles = StyleSheet.create({
    page: {
        paddingTop: 46,
        paddingRight: 46,
        paddingBottom: 64,
        paddingLeft: 46,
        backgroundColor: "#f8fafc",
        color: "#0f172a",
        fontFamily: "Helvetica",
        fontSize: 10,
        lineHeight: 1.5,
    },
    header: {
        marginBottom: 26,
        paddingBottom: 16,
        borderBottomWidth: 1,
        borderBottomColor: "#cbd5e1",
        flexDirection: "row",
        justifyContent: "space-between",
        alignItems: "flex-start",
    },
    brandMark: {
        width: 28,
        height: 28,
        borderRadius: 6,
        backgroundColor: "#2563eb",
        marginRight: 10,
    },
    brandRow: {
        flexDirection: "row",
        alignItems: "center",
    },
    brand: {
        fontSize: 15,
        fontWeight: 700,
        color: "#0f172a",
        letterSpacing: -0.3,
    },
    brandSubline: {
        marginTop: 2,
        fontSize: 9,
        color: "#64748b",
    },
    generated: {
        fontSize: 9,
        color: "#475569",
        textAlign: "right",
    },
    hero: {
        marginBottom: 24,
        padding: 22,
        borderRadius: 12,
        backgroundColor: "#ffffff",
        borderWidth: 1,
        borderColor: "#e2e8f0",
    },
    title: {
        fontSize: 26,
        fontWeight: 700,
        color: "#0f172a",
        letterSpacing: -0.5,
    },
    subtitle: {
        marginTop: 8,
        maxWidth: 440,
        fontSize: 11,
        color: "#475569",
        lineHeight: 1.5,
    },
    metaGrid: {
        marginTop: 20,
        flexDirection: "row",
        gap: 12,
    },
    metaItem: {
        flexGrow: 1,
        flexBasis: 0,
        padding: 12,
        borderRadius: 10,
        backgroundColor: "#f8fafc",
        borderWidth: 1,
        borderColor: "#e2e8f0",
    },
    metaLabel: {
        fontSize: 8,
        textTransform: "uppercase",
        letterSpacing: 0.8,
        color: "#64748b",
    },
    metaValue: {
        marginTop: 6,
        fontSize: 15,
        fontWeight: 700,
        color: "#0f172a",
    },
    section: {
        marginBottom: 24,
    },
    sectionTitle: {
        marginBottom: 12,
        paddingBottom: 6,
        borderBottomWidth: 1,
        borderBottomColor: "#e2e8f0",
        fontSize: 16,
        fontWeight: 700,
        color: "#0f172a",
        letterSpacing: -0.3,
    },
    bodyCard: {
        padding: 16,
        borderRadius: 10,
        backgroundColor: "#ffffff",
        borderWidth: 1,
        borderColor: "#e2e8f0",
    },
    paragraph: {
        marginBottom: 6,
        color: "#334155",
        fontSize: 11,
    },
    warningCard: {
        marginBottom: 16,
        padding: 16,
        borderRadius: 10,
        backgroundColor: "#ffffff",
        borderWidth: 1,
        borderColor: "#cbd5e1",
        borderLeftWidth: 4,
    },
    warningHeader: {
        marginBottom: 10,
        flexDirection: "row",
        justifyContent: "space-between",
        alignItems: "center",
        gap: 12,
    },
    warningTitle: {
        width: "75%",
        fontSize: 13,
        fontWeight: 700,
        color: "#0f172a",
        letterSpacing: -0.2,
    },
    badge: {
        paddingTop: 4,
        paddingRight: 8,
        paddingBottom: 4,
        paddingLeft: 8,
        borderRadius: 999,
        borderWidth: 1,
        fontSize: 8,
        fontWeight: 700,
        textTransform: "uppercase",
        textAlign: "center",
    },
    detailRow: {
        marginTop: 4,
        color: "#475569",
        fontSize: 10,
    },
    detailLabel: {
        fontWeight: 700,
        color: "#1e293b",
    },
    codeBlock: {
        marginTop: 12,
        padding: 10,
        borderRadius: 8,
        backgroundColor: "#0f172a",
        color: "#f8fafc",
        fontFamily: "Courier",
        fontSize: 9,
        lineHeight: 1.4,
    },
    recommendation: {
        marginTop: 12,
        padding: 12,
        borderRadius: 8,
        backgroundColor: "#f8fafc",
        borderWidth: 1,
        borderColor: "#e2e8f0",
    },
    explanation: {
        marginTop: 12,
        padding: 12,
        borderRadius: 8,
        backgroundColor: "#eff6ff",
        borderWidth: 1,
        borderColor: "#bfdbfe",
    },
    miniHeading: {
        marginBottom: 6,
        fontSize: 10,
        fontWeight: 700,
        color: "#0f172a",
        letterSpacing: -0.1,
    },
    markdownLine: {
        marginBottom: 4,
        color: "#334155",
        fontSize: 10,
    },
    markdownStrong: {
        fontWeight: 700,
        color: "#0f172a",
    },
    footer: {
        position: "absolute",
        left: 46,
        right: 46,
        bottom: 30,
        paddingTop: 12,
        borderTopWidth: 1,
        borderTopColor: "#cbd5e1",
        flexDirection: "row",
        justifyContent: "space-between",
        alignItems: "center",
        color: "#64748b",
        fontSize: 9,
    },
    emptyState: {
        padding: 20,
        borderRadius: 10,
        backgroundColor: "#f0fdf4",
        borderWidth: 1,
        borderColor: "#bbf7d0",
        color: "#166534",
    },
    warningDetailsSection: {
        marginTop: 20,
        marginBottom: 24,
    }
});

export function VibeGuardPdfReport({
    summary,
    findings,
    explanations,
    scanContext,
    generatedAt,
}: VibeGuardPdfReportProps) {
    const executiveSummary = buildExecutiveSummary(summary, findings);
    const groupedFindings = groupFindingsByFile(findings);

    return (
        <Document
            title="VibeGuard AI Security Scan Report"
            author="VibeGuard AI"
            subject="Security scan findings"
            creator="VibeGuard AI"
            creationDate={generatedAt}
        >
            <Page size="A4" style={styles.page} wrap>
                <ReportHeader generatedAt={generatedAt} />

                <View style={styles.hero}>
                    <Text style={styles.title}>Security Scan Report</Text>
                    <Text style={styles.subtitle}>
                        Automated risk analysis for exposed secrets, unsafe files, and repository hygiene.
                    </Text>
                    <View style={styles.metaGrid}>
                        <StatCard label="Total warnings" value={summary.total} />
                        <StatCard label="Critical / High" value={summary.critical + summary.high} />
                        <StatCard label="Medium" value={summary.medium} />
                        <StatCard label="Low" value={summary.low} />
                    </View>
                </View>

                <View style={styles.section}>
                    <Text style={styles.sectionTitle}>Scan Metadata</Text>
                    <View style={styles.bodyCard}>
                        <Text style={styles.detailRow}>
                            <Text style={styles.detailLabel}>Generated: </Text>
                            {formatReportDate(generatedAt)}
                        </Text>
                        <Text style={styles.detailRow}>
                            <Text style={styles.detailLabel}>Source: </Text>
                            {scanContext.sourceName}
                        </Text>
                        <Text style={styles.detailRow}>
                            <Text style={styles.detailLabel}>Scan type: </Text>
                            {scanContext.scanType}
                        </Text>
                        <Text style={styles.detailRow}>
                            <Text style={styles.detailLabel}>Security score: </Text>
                            {summary.score} / 100 ({summary.risk_label})
                        </Text>
                        <Text style={styles.detailRow}>
                            <Text style={styles.detailLabel}>Files scanned: </Text>
                            {summary.scanned_files} scanned, {summary.ignored_files} ignored,{" "}
                            {summary.skipped_generated_dependency_files} generated/dependency files skipped
                        </Text>
                    </View>
                </View>

                <View style={styles.section}>
                    <Text style={styles.sectionTitle}>Executive Summary</Text>
                    <View style={styles.bodyCard}>
                        {summary.warning_message ? <Text style={styles.paragraph}>{summary.warning_message}</Text> : null}
                        {executiveSummary.map((sentence) => (
                            <Text key={sentence} style={styles.paragraph}>
                                {sentence}
                            </Text>
                        ))}
                        <Text style={styles.paragraph}>{criticalContextLine(summary)}</Text>
                    </View>
                </View>

                <ReportFooter />
            </Page>

            {/* Page 2+: Warning Details */}
            <Page size="A4" style={styles.page} wrap>
                <ReportHeader generatedAt={generatedAt} />

                <View style={styles.section}>
                    <Text style={styles.sectionTitle}>Warning Details</Text>
                    {findings.length === 0 ? (
                        <View style={styles.emptyState}>
                            <Text>No warnings were found in this scan.</Text>
                        </View>
                    ) : (
                        Object.entries(groupedFindings).map(([file, fileFindings]) => (
                            <View key={file}>
                                {fileFindings.map((finding, index) => {
                                    const key = getFindingReportKey(finding, index);
                                    const explanation = explanations[key];

                                    return (
                                        <WarningCard
                                            key={key}
                                            finding={finding}
                                            explanation={explanation}
                                        />
                                    );
                                })}
                            </View>
                        ))
                    )}
                </View>

                <ReportFooter />
            </Page>
        </Document>
    );
}

function ReportHeader({ generatedAt }: { generatedAt: Date }) {
    return (
        <View style={styles.header} fixed>
            <View style={styles.brandRow}>
                <View style={styles.brandMark} />
                <View>
                    <Text style={styles.brand}>VibeGuard AI</Text>
                    <Text style={styles.brandSubline}>Security and code-risk analysis</Text>
                </View>
            </View>
            <Text style={styles.generated}>Generated on {formatReportDate(generatedAt)}</Text>
        </View>
    );
}

function ReportFooter() {
    return (
        <View style={styles.footer} fixed>
            <Text>Generated by VibeGuard AI. This report assists manual security review and may not catch every issue.</Text>
            <Text render={({ pageNumber, totalPages }) => `Page ${pageNumber} of ${totalPages}`} />
        </View>
    );
}

function StatCard({ label, value }: { label: string; value: number }) {
    return (
        <View style={styles.metaItem}>
            <Text style={styles.metaLabel}>{label}</Text>
            <Text style={styles.metaValue}>{value}</Text>
        </View>
    );
}

function WarningCard({ finding, explanation }: { finding: Finding; explanation?: ExplainResponse }) {
    const severityStyle = SEVERITY_STYLES[finding.severity];

    return (
        <View style={[styles.warningCard, severityStyle.accent]}>
            <View wrap={false}>
                <View style={styles.warningHeader}>
                    <Text style={styles.warningTitle}>{finding.title}</Text>
                    <Text style={[styles.badge, severityStyle.badge]}>{finding.severity}</Text>
                </View>

                <Text style={styles.detailRow}>
                    <Text style={styles.detailLabel}>File path: </Text>
                    {finding.file}
                </Text>
                <Text style={styles.detailRow}>
                    <Text style={styles.detailLabel}>Line: </Text>
                    {finding.line}
                </Text>
                <Text style={styles.detailRow}>
                    <Text style={styles.detailLabel}>Category: </Text>
                    {finding.category}
                </Text>
                <Text style={styles.detailRow}>
                    <Text style={styles.detailLabel}>File context: </Text>
                    {finding.file_context}
                </Text>
                <Text style={styles.detailRow}>
                    <Text style={styles.detailLabel}>Rule: </Text>
                    {finding.rule_id}
                </Text>
                {finding.original_severity ? (
                    <Text style={styles.detailRow}>
                        <Text style={styles.detailLabel}>Original severity: </Text>
                        {finding.original_severity}
                    </Text>
                ) : null}
                {finding.adjusted_severity_reason ? (
                    <Text style={styles.detailRow}>
                        <Text style={styles.detailLabel}>Severity adjustment: </Text>
                        {finding.adjusted_severity_reason}
                    </Text>
                ) : null}
                {typeof finding.score_penalty === "number" ? (
                    <Text style={styles.detailRow}>
                        <Text style={styles.detailLabel}>Score penalty: </Text>
                        {Math.round(finding.score_penalty)}
                    </Text>
                ) : null}

                <Text style={styles.codeBlock}>{finding.evidence}</Text>

                <View style={styles.recommendation}>
                    <Text style={styles.miniHeading}>Fix recommendation</Text>
                    <MarkdownLikeText content={normalizeExplanation(finding.recommendation)} />
                </View>
            </View>

            <ExistingExplanation explanation={explanation} />
        </View>
    );
}

function ExistingExplanation({ explanation }: { explanation?: ExplainResponse }) {
    if (!explanation || !hasAnyExplanationContent(explanation)) {
        return null;
    }

    const expText = explanation.explanation?.trim();
    const attackText = explanation.attack_scenario?.trim();
    const fixText = explanation.fix_details?.trim();

    return (
        <View style={styles.explanation}>
            {expText && !isFallbackText(expText) ? (
                <View>
                    <Text style={styles.miniHeading}>Why this is dangerous</Text>
                    <MarkdownLikeText content={normalizeExplanation(expText)} />
                </View>
            ) : null}
            {attackText && !isFallbackText(attackText) ? (
                <View>
                    <Text style={styles.miniHeading}>Attack scenario</Text>
                    <MarkdownLikeText content={normalizeExplanation(attackText)} />
                </View>
            ) : null}
            {fixText && !isFallbackText(fixText) ? (
                <View>
                    <Text style={styles.miniHeading}>How to fix it</Text>
                    <MarkdownLikeText content={normalizeExplanation(fixText)} />
                </View>
            ) : null}
        </View>
    );
}

function MarkdownLikeText({ content }: { content: string }) {
    const lines = content
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);

    if (lines.length === 0) {
        return null;
    }

    return (
        <View>
            {lines.map((line, index) => (
                <Text key={`${line}-${index}`} style={styles.markdownLine}>
                    <InlineMarkdownText text={line} />
                </Text>
            ))}
        </View>
    );
}

function InlineMarkdownText({ text }: { text: string }) {
    const bulletMatch = text.match(/^([-*]|\d+\.)\s+(.*)$/);
    const content = bulletMatch ? `- ${bulletMatch[2]}` : text;
    const parts = content.split(/(\*\*[^*]+\*\*)/g).filter(Boolean);

    return (
        <>
            {parts.map((part, index) => {
                const strongMatch = part.match(/^\*\*([^*]+)\*\*$/);

                return strongMatch ? (
                    <Text key={`${part}-${index}`} style={styles.markdownStrong}>
                        {strongMatch[1]}
                    </Text>
                ) : (
                    <Text key={`${part}-${index}`}>{part.replace(/`/g, "")}</Text>
                );
            })}
        </>
    );
}

function isFallbackText(text: string): boolean {
    const lower = text.toLowerCase();
    return lower.includes("unavailable") || lower.includes("not available") || lower.includes("use the recommendation shown");
}

function hasAnyExplanationContent(explanation: ExplainResponse): boolean {
    const expText = explanation.explanation?.trim() || "";
    const attackText = explanation.attack_scenario?.trim() || "";
    const fixText = explanation.fix_details?.trim() || "";

    const hasRealExp = expText && !isFallbackText(expText);
    const hasRealAttack = attackText && !isFallbackText(attackText);
    const hasRealFix = fixText && !isFallbackText(fixText);

    return Boolean(hasRealExp || hasRealAttack || hasRealFix);
}

function groupFindingsByFile(findings: Finding[]): Record<string, Finding[]> {
    return findings.reduce<Record<string, Finding[]>>((current, finding) => {
        if (!current[finding.file]) {
            current[finding.file] = [];
        }

        current[finding.file].push(finding);
        return current;
    }, {});
}

function criticalContextLine(summary: ScanSummary): string {
    const productionCritical = summary.production_critical_count ?? 0;
    const envCritical = summary.env_critical_count ?? 0;
    const testDemoCritical = summary.test_demo_critical_count ?? 0;
    const docsTemplateCritical = summary.docs_template_critical_count ?? 0;
    const generatedCritical = summary.generated_dependency_critical_count ?? 0;
    const totalCritical = productionCritical + envCritical + testDemoCritical + docsTemplateCritical + generatedCritical;

    return `Critical context: ${totalCritical} total, ${productionCritical} production, ${envCritical} env/config, ${testDemoCritical} test/demo, ${docsTemplateCritical} docs/templates, ${generatedCritical} generated/dependencies.`;
}
