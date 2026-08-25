import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

@main def main(cpg_path: String) = {
  importCpg(cpg_path)
  
  val methodCount = cpg.method.size
  val fileCount = cpg.file.nameNot("<unknown>").size
  val sampleMethods = cpg.method.name.filterNot(_.contains("<")).take(10).l.mkString(", ")
  
  println(s"METADATA_START")
  println(s"Methods: $methodCount")
  println(s"Files: $fileCount")
  println(s"Sample Methods: $sampleMethods")
  println(s"METADATA_END")
}
