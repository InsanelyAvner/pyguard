"use client"

import { useState, useEffect, useRef } from "react"
import { useMediaQuery } from "@/hooks/use-media-query"
import CodeEditor from "./code-editor"
import ProgressBar from "./progress-bar"
import { Button } from "@/components/ui/button"
import { Copy, ExternalLink, Code, Wand2 } from "lucide-react"
import { obfuscatePythonCode } from "@/lib/obfuscate"
import { cn } from "@/lib/utils"
import { useToast } from "@/hooks/use-toast"

export default function Obfuscator() {
  const [inputCode, setInputCode] = useState<string>("")
  const [outputCode, setOutputCode] = useState<string>("")
  const [isObfuscating, setIsObfuscating] = useState(false)
  const [progress, setProgress] = useState(0)
  const isMobile = useMediaQuery("(max-width: 768px)")
  const { toast } = useToast()
  const buttonRef = useRef<HTMLButtonElement>(null)
  const [mousePosition, setMousePosition] = useState({ x: 0, y: 0 })
  const [isCopied, setIsCopied] = useState(false)

  // Sample Python code for initial state
  useEffect(() => {
    setInputCode(`def greet(name):
    """This function greets the person passed in as a parameter"""
    print(f"Hello, {name}!")
    return f"Hello, {name}!"

# Call the function
result = greet("World")
print(result)`)
  }, [])

  // Track mouse position for glow effect
  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (buttonRef.current) {
        const rect = buttonRef.current.getBoundingClientRect()
        const x = ((e.clientX - rect.left) / rect.width) * 100
        const y = ((e.clientY - rect.top) / rect.height) * 100
        buttonRef.current.style.setProperty("--x", `${x}%`)
        buttonRef.current.style.setProperty("--y", `${y}%`)
      }

      setMousePosition({ x: e.clientX, y: e.clientY })
    }

    window.addEventListener("mousemove", handleMouseMove)
    return () => window.removeEventListener("mousemove", handleMouseMove)
  }, [])

  const handleObfuscate = async () => {
    if (!inputCode.trim()) {
      toast({
        title: "Empty Code",
        description: "Please enter some Python code to obfuscate.",
        variant: "destructive",
      })
      return
    }

    setIsObfuscating(true)
    setProgress(0)

    // Simulate progress steps
    const updateProgress = () => {
      setProgress((prev) => {
        if (prev >= 100) return 100
        return prev + 10
      })
    }

    const progressInterval = setInterval(updateProgress, 100)

    try {
      // Obfuscate the code with a slight delay to show progress
      await new Promise((resolve) => setTimeout(resolve, 1000))
      const obfuscated = obfuscatePythonCode(inputCode)

      // Ensure progress is at 100% when done
      setProgress(100)
      setTimeout(() => {
        setOutputCode(obfuscated)
        setIsObfuscating(false)
        setProgress(0)
      }, 200)
    } catch (error) {
      toast({
        title: "Obfuscation Failed",
        description: error instanceof Error ? error.message : "An unknown error occurred",
        variant: "destructive",
      })
      setIsObfuscating(false)
      setProgress(0)
    } finally {
      clearInterval(progressInterval)
    }
  }

  const copyToClipboard = () => {
    if (!outputCode) {
      toast({
        title: "Nothing to Copy",
        description: "Please obfuscate some code first.",
        variant: "destructive",
      })
      return
    }

    navigator.clipboard.writeText(outputCode)
    setIsCopied(true)
    
    toast({
      title: "Copied!",
      description: "Obfuscated code copied to clipboard.",
    })

    // Reset the copied state after animation
    setTimeout(() => setIsCopied(false), 2000)
  }

  

  return (
    <div className="relative min-h-[100dvh] w-full flex flex-col">
      {/* Header */}
      <header className="p-4 md:p-6 flex flex-col sm:flex-row justify-between items-start sm:items-center gap-3 z-10">
        <div>
          <h1 className="text-2xl md:text-3xl text-white font-normal tracking-normal flex items-center">
            <Code className="mr-2 h-6 md:h-8 w-6 md:w-6" />
            PyGuard
          </h1>
          <p className="text-gray-400 text-xs md:text-sm mt-1 tracking-normal">
            Secure your code with our powerful obfuscation algorithm
          </p>
        </div>

        {!isMobile && (
          <div className="flex items-center space-x-6">
            <a
              href="https://github.com/python/cpython"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center text-white hover:text-gray-300 transition-colors tracking-normal"
            >
              <span className="mr-1">Python Docs</span>
              <ExternalLink className="h-4 w-4" />
            </a>
            {/* <a
              href="https://docs.python.org/3/library/ast.html"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center text-white hover:text-gray-300 transition-colors tracking-normal"
            >
              <span className="mr-1">AST Module</span>
              <ExternalLink className="h-4 w-4" />
            </a> */}
          </div>
        )}
      </header>

      {/* Main content area */}
      <div
        className={cn(
          "flex-1 flex flex-col md:obfuscator-container p-4 md:p-6 gap-4 overflow-hidden z-10",
          !isMobile && "obfuscator-container",
        )}
      >
        {/* Input section */}
        <div className="flex flex-col h-[300px] md:h-[75vh] code-section">
          <div className="mb-3 flex justify-between items-center">
            <h2 className="text-base md:text-lg text-white font-medium">Input Python Code</h2>
          </div>
          <div className="h-full bg-black/40 backdrop-blur-sm rounded-lg border border-[rgba(255,255,255,0.12)] overflow-hidden shadow-lg">
            <CodeEditor value={inputCode} onChange={setInputCode} language="python" readOnly={isObfuscating} />
          </div>
        </div>

        {/* Middle section with button and progress */}
        <div className="flex flex-col justify-center items-center gap-4 py-4 md:py-0 md:px-4">
          <Button
            ref={buttonRef}
            onClick={handleObfuscate}
            disabled={isObfuscating || !inputCode.trim()}
            className={cn(
              "bg-white hover:bg-gray-200 text-black rounded-full px-6 py-2 flex items-center gap-2 transition-all glow-effect",
              isObfuscating && "opacity-50 cursor-not-allowed",
            )}
          >
            <Wand2 className="h-4 w-4" />
            <span className="tracking-normal">Obfuscate</span>
          </Button>

          {isObfuscating && (
            <div className="w-32">
              <ProgressBar progress={progress} />
            </div>
          )}
        </div>

        {/* Output section */}
        <div className="flex flex-col h-[300px] md:h-[75vh] code-section">
          <div className="mb-3 flex justify-between items-center">
            <h2 className="text-base md:text-lg text-white font-medium">Obfuscated Output</h2>
            <Button
              onClick={copyToClipboard}
              disabled={!outputCode || isObfuscating}
              variant="ghost"
              size="sm"
              className={cn(
                "text-gray-400 hover:text-white hover:bg-white/10 transition-all duration-200",
                isCopied && "text-green-400 bg-green-500/10"
              )}
            >
              <Copy className={cn("h-4 w-4 mr-1", isCopied && "text-green-400")} />
              <span className="hidden sm:inline">
                {isCopied ? "Copied!" : "Copy"}
              </span>
            </Button>
          </div>
          <div className="h-full bg-black/40 backdrop-blur-sm rounded-lg border border-[rgba(255,255,255,0.12)] overflow-hidden shadow-lg">
            <CodeEditor value={outputCode} language="python" readOnly={true} />
          </div>
        </div>
      </div>

      {/* Footer */}
      <footer className="p-4 md:p-6 text-center text-gray-400 text-xs md:text-sm z-10">
        {isMobile && (
          <div className="flex justify-center space-x-4 md:space-x-6 mb-3">
            <a
              href="https://github.com/python/cpython"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center text-white hover:text-gray-300 transition-colors tracking-normal text-xs"
            >
              <span className="mr-1">Python Docs</span>
              <ExternalLink className="h-3 w-3" />
            </a>
            <a
              href="https://docs.python.org/3/library/ast.html"
              target="_blank"
              rel="noopener noreferrer"
              className="flex items-center text-white hover:text-gray-300 transition-colors tracking-normal text-xs"
            >
              <span className="mr-1">AST Module</span>
              <ExternalLink className="h-3 w-3" />
            </a>
          </div>
        )}
        <p>© {new Date().getFullYear()} PyGuard by <a className="underline" href="https://github.com/InsanelyAvner">InsanelyAvner</a>. All rights reserved.</p>
      </footer>
    </div>
  )
}
