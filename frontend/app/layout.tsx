import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
    title: "VibeGuard AI - Security Scanner",
    description: "Static security scanner for source code",
};

export default function RootLayout({
    children,
}: {
    children: React.ReactNode;
}) {
    return (
        <html lang="en">
            <body className="bg-gray-50">{children}</body>
        </html>
    );
}
