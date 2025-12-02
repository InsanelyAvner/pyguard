"use client"

import { useEffect, useState } from "react"
import { EditorView, basicSetup } from "codemirror"
import { EditorState } from "@codemirror/state"
import { python } from "@codemirror/lang-python"
import { oneDark } from "@codemirror/theme-one-dark"
import type { ViewUpdate } from "@codemirror/view"

interface CodeEditorProps {
  value: string
  onChange?: (value: string) => void
  language?: "python" | "javascript"
  readOnly?: boolean
}

export default function CodeEditor({ value, onChange, language = "python", readOnly = false }: CodeEditorProps) {
  const [element, setElement] = useState<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!element) return

    // Clear any existing editor
    while (element.firstChild) {
      element.removeChild(element.firstChild)
    }

    // Set up language extension
    const languageExtension = language === "python" ? python() : python()

    // Create editor state
    const startState = EditorState.create({
      doc: value,
      extensions: [
        basicSetup,
        languageExtension,
        oneDark,
        EditorView.updateListener.of((update: ViewUpdate) => {
          if (update.docChanged && onChange) {
            onChange(update.state.doc.toString())
          }
        }),
        EditorView.theme({
          "&": {
            height: "100%",
            fontSize: "14px",
          },
          ".cm-scroller": {
            overflow: "auto",
            fontFamily: "Geist Mono, monospace",
            height: "100%", // Ensure scroller takes full height
          },
          ".cm-gutters": {
            backgroundColor: "transparent",
            border: "none",
            color: "rgba(255, 255, 255, 0.3)",
          },
          ".cm-activeLineGutter": {
            backgroundColor: "rgba(255, 255, 255, 0.05)",
          },
          ".cm-activeLine": {
            backgroundColor: "rgba(255, 255, 255, 0.05)",
          },
          ".cm-content": {
            caretColor: "#fff",
            height: "100%", // Ensure content takes full height
          },
          ".cm-editor": {
            height: "100%", // Ensure editor takes full height
          },
        }),
        EditorState.readOnly.of(readOnly),
      ],
    })

    // Create editor view
    const view = new EditorView({
      state: startState,
      parent: element,
    })

    return () => {
      view.destroy()
    }
  }, [element, language, readOnly])

  // Update editor content when value prop changes
  useEffect(() => {
    if (!element) return

    const editorView = EditorView.findFromDOM(element)
    if (!editorView) return

    const currentContent = editorView.state.doc.toString()
    if (currentContent !== value) {
      editorView.dispatch({
        changes: { from: 0, to: currentContent.length, insert: value },
      })
    }
  }, [value, element])

  return <div ref={setElement} className="code-editor w-full h-full custom-scrollbar" />
}
