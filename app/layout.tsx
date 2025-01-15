import "./globals.css"
import type { Metadata } from "next"
import { Inter } from "next/font/google"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "PyGuard",
  description: "Obfuscate your Python code with multi-layer security",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className={`${inter.className} bg-gray-100 min-h-screen flex flex-col`}>
        <div className="flex-1">{children}</div>
        <footer className="border-grid border-t py-6 md:px-8 md:py-0">
      <div className="container-wrapper">
        <div className="container py-4">
          <div className="text-balance text-center text-sm leading-loose text-muted-foreground">
            Built by{" "}
            <a
              href={"https://github.com/InsanelyAvner"}
              target="_blank"
              rel="noreferrer"
              className="font-medium underline underline-offset-4"
            >
              InsanelyAvner
            </a>
            . The source code is available on{" "}
            <a
              href={"https://github.com/InsanelyAvner/pyguard"}
              target="_blank"
              rel="noreferrer"
              className="font-medium underline underline-offset-4"
            >
              GitHub
            </a>
            .
          </div>
        </div>
      </div>
    </footer>
      </body>
    </html>
  )
}
