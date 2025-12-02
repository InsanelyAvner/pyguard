"use client"

import { useEffect, useRef } from "react"
import { cn } from "@/lib/utils"

interface GridBackgroundProps {
  className?: string
}

export default function GridBackground({ className }: GridBackgroundProps) {
  const gridRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const rafRef = useRef<number | null>(null)

  useEffect(() => {
    if (!canvasRef.current || !gridRef.current) return

    const canvas = canvasRef.current
    const context = canvas.getContext("2d")
    if (!context) return

    // Set canvas dimensions
    const updateCanvasSize = () => {
      const width = window.innerWidth
      const height = window.innerHeight
      const dpr = window.devicePixelRatio || 1
      canvas.width = width * dpr
      canvas.height = height * dpr
      canvas.style.width = `${width}px`
      canvas.style.height = `${height}px`
      context.scale(dpr, dpr)
    }

    updateCanvasSize()
    window.addEventListener("resize", updateCanvasSize)

    // Grid properties
    const gridSize = 50
    let offsetX = 0
    let offsetY = 0
    let targetOffsetX = 0
    let targetOffsetY = 0

    // Mouse move handler
    const handleMouseMove = (e: MouseEvent) => {
      const x = (e.clientX / window.innerWidth - 0.5) * 20
      const y = (e.clientY / window.innerHeight - 0.5) * 20

      targetOffsetX = x
      targetOffsetY = y
    }

    // Draw grid
    const drawGrid = () => {
      if (!context) return

      // Smooth movement
      offsetX += (targetOffsetX - offsetX) * 0.05
      offsetY += (targetOffsetY - offsetY) * 0.05

      const { width, height } = canvas

      // Clear canvas
      context.clearRect(0, 0, width, height)

      // Draw grid lines
      context.beginPath()
      context.strokeStyle = "rgba(255, 255, 255, 0.15)"
      context.lineWidth = 1

      // Vertical lines
      for (let x = offsetX % gridSize; x < width; x += gridSize) {
        context.moveTo(x, 0)
        context.lineTo(x, height)
      }

      // Horizontal lines
      for (let y = offsetY % gridSize; y < height; y += gridSize) {
        context.moveTo(0, y)
        context.lineTo(width, y)
      }

      context.stroke()

      // Add subtle glow at intersections
      const drawGlowPoints = false // Set to true to enable glow points
      if (drawGlowPoints) {
        for (let x = offsetX % gridSize; x < width; x += gridSize) {
          for (let y = offsetY % gridSize; y < height; y += gridSize) {
            const gradient = context.createRadialGradient(x, y, 0, x, y, 4)
            gradient.addColorStop(0, "rgba(255, 255, 255, 0.1)")
            gradient.addColorStop(1, "rgba(255, 255, 255, 0)")

            context.fillStyle = gradient
            context.beginPath()
            context.arc(x, y, 4, 0, Math.PI * 2)
            context.fill()
          }
        }
      }

      // Request next frame
      rafRef.current = requestAnimationFrame(drawGrid)
    }

    // Start animation
    window.addEventListener("mousemove", handleMouseMove)
    drawGrid()

    // Cleanup
    return () => {
      window.removeEventListener("resize", updateCanvasSize)
      window.removeEventListener("mousemove", handleMouseMove)
      if (rafRef.current) {
        cancelAnimationFrame(rafRef.current)
      }
    }
  }, [])

  return (
    <div
      ref={gridRef}
      className={cn("fixed inset-0 z-0 bg-black overflow-hidden grid-background-container", className)}
    >
      <div className="absolute inset-0 bg-radial-gradient opacity-50"></div>
      <canvas ref={canvasRef} className="absolute inset-0"></canvas>
    </div>
  )
}
