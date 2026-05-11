"use client";

import React from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";

type MarkdownContentProps = {
    content: string;
    className?: string;
};

function isExternalLink(href?: string): boolean {
    return Boolean(href && /^https?:\/\//i.test(href));
}

export function MarkdownContent({ content, className }: MarkdownContentProps) {
    return (
        <div
            className={[
                "markdown-content w-full min-w-0 break-words text-sm leading-6 text-slate-700",
                className ?? "",
            ]
                .filter(Boolean)
                .join(" ")}
        >
            <ReactMarkdown
                remarkPlugins={[remarkGfm]}
                components={{
                    p: ({ children }) => <p className="my-0.5 whitespace-pre-wrap">{children}</p>,
                    ul: ({ children }) => <ul className="my-1 list-disc space-y-1 pl-5">{children}</ul>,
                    ol: ({ children }) => <ol className="my-1 list-decimal space-y-1 pl-5">{children}</ol>,
                    li: ({ children }) => <li className="pl-1">{children}</li>,
                    strong: ({ children }) => <strong className="font-semibold text-slate-950">{children}</strong>,
                    code: ({ className, children }) => {
                        const isBlockCode = Boolean(className);

                        return isBlockCode ? (
                            <code className="block whitespace-pre-wrap break-words rounded-md bg-slate-100 p-3 font-mono text-[0.85em] text-slate-900">
                                {children}
                            </code>
                        ) : (
                            <code className="break-words rounded bg-slate-200 px-1.5 py-0.5 font-mono text-[0.85em] text-slate-900">
                                {children}
                            </code>
                        );
                    },
                    pre: ({ children }) => <pre className="my-1 overflow-x-auto">{children}</pre>,
                    a: ({ href, children }) => {
                        const external = isExternalLink(href);

                        return (
                            <a
                                href={href}
                                target={external ? "_blank" : undefined}
                                rel={external ? "noopener noreferrer" : undefined}
                                className="break-words font-medium text-blue-700 underline decoration-blue-300 underline-offset-2 transition hover:text-blue-800 hover:decoration-blue-500"
                            >
                                {children}
                            </a>
                        );
                    },
                    blockquote: ({ children }) => (
                        <blockquote className="my-1 border-l-4 border-slate-300 pl-3 text-slate-600">
                            {children}
                        </blockquote>
                    ),
                    h1: ({ children }) => <h1 className="my-1 text-base font-semibold text-slate-950">{children}</h1>,
                    h2: ({ children }) => <h2 className="my-1 text-sm font-semibold text-slate-950">{children}</h2>,
                    h3: ({ children }) => <h3 className="my-1 text-sm font-semibold text-slate-950">{children}</h3>,
                }}
            >
                {content}
            </ReactMarkdown>
        </div>
    );
}
