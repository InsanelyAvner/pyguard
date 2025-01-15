"use client"

import { useState } from "react"
import { motion } from "framer-motion"
import { obfuscateCode } from "@/lib/obfuscate"

// Example shadcn UI button
import { Button } from "@/components/ui/button"

export default function HomePage() {
  const [inputValue, setInputValue] = useState("")
  const [obfuscated, setObfuscated] = useState("")
  const [copied, setCopied] = useState(false)

  const handleObfuscate = () => {
    setCopied(false)
    if (!inputValue.trim()) return
    const result = obfuscateCode(inputValue)
    setObfuscated(result)
  }

  // Copy to Clipboard
  const handleCopy = () => {
    if (!obfuscated) return
    navigator.clipboard.writeText(obfuscated).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    })
  }

  return (
    <main className="container mx-auto max-w-3xl py-8 px-4 space-y-6">
      <h1 className="text-3xl font-bold mb-2">
        PyGuard
      </h1>
      <p className="text-gray-700 mb-4">
        Protect your code with PyGuard, a fast, reliable, and secure Python obfuscator.
      </p>

      <textarea
        className="w-full min-h-[200px] p-3 border border-gray-300 rounded focus:outline-none focus:ring-2 focus:ring-blue-400"
        placeholder="Enter your Python code here..."
        value={inputValue}
        onChange={(e) => setInputValue(e.target.value)}
      />

      <div className="flex items-center space-x-4">
        <Button variant="default" onClick={handleObfuscate}>
          Obfuscate
        </Button>
        {obfuscated && (
          <Button variant="outline" onClick={handleCopy}>
            {copied ? "Copied!" : "Copy to Clipboard"}
          </Button>
        )}
      </div>

      {obfuscated && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ duration: 0.5 }}
          className="mt-6 p-3 bg-white border border-gray-300 rounded"
        >
          <div 
            className="whitespace-pre-wrap max-h-80 overflow-auto font-mono text-sm"
          >
            {obfuscated}
          </div>
        </motion.div>
      )}
    </main>
  )
}
