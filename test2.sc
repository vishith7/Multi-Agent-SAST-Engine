@main def main() = {
  importCpg("C:/Users/thane/OneDrive/Desktop/project/Multi-agentic-sast-engine/tests/ground_truth/cpg.bin")
  println("CALLS:")
  cpg.call.name.l.distinct.sorted.foreach(println)
}
