import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

@main def main(cpg_path: String) = {
  importCpg(cpg_path)
  
  println("Testing unanchored .*execute.*")
  println(cpg.call.code(".*execute.*").size)
  
  println("Testing anchored \\bexecute\\b without .*")
  println(cpg.call.code("\\bexecute\\b").size)
  
  println("Testing anchored .*\\bexecute\\b.*")
  println(cpg.call.code(".*\\bexecute\\b.*").size)
}
