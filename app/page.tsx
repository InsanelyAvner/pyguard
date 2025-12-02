import Obfuscator from "@/components/obfuscator"
import GridBackground from "@/components/grid-background"

export default function Home() {
  return (
    <main className="min-h-[100dvh] w-screen overflow-hidden">
      <GridBackground />
      <Obfuscator />
    </main>
  )
}
