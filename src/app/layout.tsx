import type { Metadata } from 'next';

export const metadata: Metadata = {
  title: 'Security Knowledge Graph',
  description:
    'Connects vulnerabilities, asset context, and real-world traffic patterns',
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
