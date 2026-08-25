import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

@main def main(cpg_path: String) = {
  importCpg(cpg_path)
  
  val call = cpg.call.headOption
  println(s"Call file: ${call.map(_.file.name.headOption)}")
  
  val param = cpg.parameter.headOption
  println(s"Param file: ${param.map(_.file.name.headOption)}")
}
