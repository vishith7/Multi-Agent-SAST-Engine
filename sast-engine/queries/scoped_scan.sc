import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._
import scala.util.matching.Regex

@main def main(category: String, sources: String, sinks: String, sanitizers: String, cpg_path: String, changed_lines: String, scope: String = "", maxDepth: String = "30") = {
  println(s"[DEBUG] maxDepth resolved to: ${maxDepth.toInt}")
  importCpg(cpg_path)
  
  val sourceRegexes = if (sources.isEmpty) List() else sources.split(",").map(_.r.unanchored).toList
  val sinkEntries = if (sinks.isEmpty) List() else sinks.split(",").map(_.split(":::")).map(a => (a(0).r.unanchored, if (a.length > 1) a(1) else "UNKNOWN")).toList
  val sanitizerRegexes = if (sanitizers.isEmpty) List() else sanitizers.split(",").map(_.r.unanchored).toList
  val scopeList = if (scope.isEmpty) List() else scope.split(",").toList
  
  val changedLinesSet = if (changed_lines.isEmpty) Set[Int]() else changed_lines.split(",").map(_.toInt).toSet

  val callSources = cpg.call.filter(c => sourceRegexes.exists(_.matches(c.code))).argument.l
  val paramSources = cpg.parameter.filter(p => sourceRegexes.exists(_.matches(p.name))).l
  val paramAnnotationSources = cpg.parameter.where(_.annotation.filter(a => sourceRegexes.exists(_.matches(a.name)))).l
  
  val sourceNodes = callSources ++ paramSources ++ paramAnnotationSources
  
  val sinkNodes = cpg.call.filter(c => sinkEntries.exists(entry => entry._1.matches(c.code))).l

  val sinkCandidatesMatched = sinkNodes.size
  val flows = sinkNodes.reachableByFlows(sourceNodes)
  
  var findingsReturned = 0
  
  flows.l.foreach { flow =>
    if (flow.elements.size <= maxDepth.toInt) {
      val pathNodeCodes = flow.elements.isCall.code.l
      val isSanitized = sanitizerRegexes.exists { regex =>
        pathNodeCodes.exists(code => regex.matches(code))
      }
      
      if (!isSanitized) {
        val intersectsChanged = changedLinesSet.isEmpty || flow.elements.exists { e =>
          val line = e match {
            case expr: io.shiftleft.codepropertygraph.generated.nodes.Expression => expr.lineNumber.getOrElse(-1)
            case param: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => param.lineNumber.getOrElse(-1)
            case _ => -1
          }
          changedLinesSet.contains(line)
        }

        if (intersectsChanged) {
          val src = flow.elements.headOption.get
          val snk = flow.elements.lastOption.get
          
          val snkNode = snk.asInstanceOf[io.shiftleft.codepropertygraph.generated.nodes.Call]
          
          val srcId = src.id
          val snkId = snkNode.id
          
          val srcCodeRaw = src match {
            case expr: io.shiftleft.codepropertygraph.generated.nodes.Expression => expr.code
            case param: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => param.code
            case _ => "unknown"
          }
          val srcCode = srcCodeRaw.replace("\"", "'").replace("\n", " ").replace("\\", "\\\\")
          
          val srcFileRaw = src match {
            case expr: io.shiftleft.codepropertygraph.generated.nodes.Expression => expr.location.filename
            case param: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => param.location.filename
            case _ => "unknown"
          }
          val srcFile = srcFileRaw.replace("\\", "\\\\")
          
          val srcLine = src match {
            case expr: io.shiftleft.codepropertygraph.generated.nodes.Expression => expr.lineNumber.getOrElse(-1)
            case param: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => param.lineNumber.getOrElse(-1)
            case _ => -1
          }
          
          val sinkFunc = snkNode.name
          val sinkFile = snkNode.location.filename.replace("\\", "\\\\")
          val sinkLine = snkNode.lineNumber.getOrElse(-1)
          
          val inScope = if (scopeList.nonEmpty) scopeList.contains(sinkFunc) else true
          
          if (inScope) {
            findingsReturned += 1
            val pathObjs = flow.elements.map { e =>
              val codeRaw = e.code.replace("\"", "'").replace("\n", " ").replace("\\", "\\\\")
              val fileRaw = e match {
                case expr: io.shiftleft.codepropertygraph.generated.nodes.Expression => expr.location.filename
                case param: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => param.location.filename
                case _ => "unknown"
              }
              val file = fileRaw.replace("\\", "\\\\")
              val line = e match {
                case expr: io.shiftleft.codepropertygraph.generated.nodes.Expression => expr.lineNumber.getOrElse(-1)
                case param: io.shiftleft.codepropertygraph.generated.nodes.MethodParameterIn => param.lineNumber.getOrElse(-1)
                case _ => -1
              }
              s"""{"code": "${codeRaw}", "file": "${file}", "line": ${line}}"""
            }
            val pathStr = pathObjs.mkString("[", ", ", "]")
            
            val subtype = sinkEntries.find(entry => entry._1.matches(snkNode.code)).map(_._2).getOrElse("UNKNOWN")

            println(s"""JSON_START:{"category": "${category}", "subtype": "${subtype}", "source": {"id": ${srcId}, "code": "${srcCode}", "file": "${srcFile}", "line": ${srcLine}}, "sink": {"id": ${snkId}, "function": "${sinkFunc}", "file": "${sinkFile}", "line": ${sinkLine}}, "path": ${pathStr}}:JSON_END""")
          }
        }
      }
    }
  }
  
  println(s"""TELEMETRY_START:{"rule_id": "${category}", "source_nodes_matched": ${sourceNodes.size}, "sink_candidates_matched": ${sinkCandidatesMatched}, "findings_returned": ${findingsReturned}}:TELEMETRY_END""")
}