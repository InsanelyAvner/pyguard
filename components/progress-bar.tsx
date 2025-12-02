"use client"

import { cn } from "@/lib/utils"

interface ProgressBarProps {
  progress: number
  className?: string
  isIndeterminate?: boolean
}

export default function ProgressBar({ progress, className, isIndeterminate = false }: ProgressBarProps) {
  // Ensure progress is between 0 and 100
  const normalizedProgress = Math.min(Math.max(progress, 0), 100)

  return (
    <div className={cn("w-full bg-black rounded-full h-2 overflow-hidden border border-white p-[1px]", className)}>
      {isIndeterminate ? (
        <div className="h-full relative w-full">
          <div className="h-full bg-white absolute w-[40%] animate-progress-indeterminate rounded-full" />
        </div>
      ) : (
        <div
          className="h-full bg-white transition-all duration-300 rounded-full"
          style={{ width: `${normalizedProgress}%` }}
        />
      )}
    </div>
  )
}
