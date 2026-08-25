import io.shiftleft.semanticcpg.language._
@main def main() = {
  importCpg("C:/Users/thane/OneDrive/Desktop/project/test/VulnerableApp/vuln_cpg.bin")
  
  val singleBackslashRegex = ".*\bRequestParam\b.*" 
  
  println("--- PARAM CODE WITH SINGLE BACKSLASH ---")
  println(cpg.parameter.code(singleBackslashRegex).size)
}