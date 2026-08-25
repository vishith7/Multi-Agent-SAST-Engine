import io.joern.dataflowengineoss.language._
import io.shiftleft.semanticcpg.language._

@main def main(category: String, sources: String, sinks: String, sanitizers: String, cpg_path: String, scope: String = "", maxDepth: String = "30") = {
  println(s"[DEBUG] maxDepth resolved to: ${maxDepth.toInt}")
  importCpg(cpg_path)
  
  val sourceRegexes = if (sources.isEmpty) List() else sources.split(",").toList
  println("DEBUG: sourceRegexes: " + sourceRegexes)
  sourceRegexes.foreach { r =>
    println(s"DEBUG: element='$r' length=${r.length} chars=${r.map(_.toInt).toList}")
  }
  
  val sinkEntries = if (sinks.isEmpty) List() else sinks.split(",").map(_.split(":::")).map(a => (a(0), if (a.length > 1) a(1) else "UNKNOWN")).toList
  val sinkRegexes = sinkEntries.map(_._1)
  
  val sanitizerRegexes = if (sanitizers.isEmpty) List() else sanitizers.split(",").toList
  val scopeList = if (scope.isEmpty) List() else scope.split(",").toList

  // In Spring/Java, sources are often annotated parameters instead of direct function calls.
  val callSources = cpg.call.code(sourceRegexes: _*).argument.l
  println("DEBUG: callSources MATCHES count: " + cpg.call.code(sourceRegexes: _*).size)
  println("DEBUG: callSources MATCHES: " + cpg.call.code(sourceRegexes: _*).code.l)
  println("DEBUG: callSources variable size: " + callSources.size)
  
  val paramSources = cpg.parameter.name(sourceRegexes: _*).l
  println("DEBUG: paramSources size: " + paramSources.size)
  
  val paramAnnotationSources = cpg.parameter.where(_.annotation.name(sourceRegexes: _*)).l
  println("DEBUG: paramAnnotationSources size: " + paramAnnotationSources.size)
  
  val sourceNodes = callSources ++ paramSources ++ paramAnnotationSources
  
  val sinkNodes = cpg.call.code(sinkRegexes: _*).filter { call =>
    // Structural check to catch parameterized vs raw call shape
    if (category == "injection" && call.code.contains("execute")) {
      call.argument.size == 1 // Raw injection usually has 1 argument (the query string)
    } else {
      true
    }
  }.l

  val sinkCandidatesMatched = sinkNodes.size
  val flows = sinkNodes.reachableByFlows(sourceNodes)
  
  var findingsReturned = 0
  
  flows.l.foreach { flow =>
    // Cap traversal depth
    if (flow.elements.size <= maxDepth.toInt) {
      val pathNodeCodes = flow.elements.isCall.code.l
      val isSanitized = sanitizerRegexes.exists { regex =>
        pathNodeCodes.exists(code => code.matches(regex))
      }
      
      if (!isSanitized) {
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
          
          val subtype = sinkEntries.find(entry => snkNode.code.matches(entry._1)).map(_._2).getOrElse("UNKNOWN")

          println(s"""JSON_START:{"category": "${category}", "subtype": "${subtype}", "source": {"id": ${srcId}, "code": "${srcCode}", "file": "${srcFile}", "line": ${srcLine}}, "sink": {"id": ${snkId}, "function": "${sinkFunc}", "file": "${sinkFile}", "line": ${sinkLine}}, "path": ${pathStr}}:JSON_END""")
        }
      }
    }
  }
  
  println(s"""TELEMETRY_START:{"rule_id": "${category}", "source_nodes_matched": ${sourceNodes.size}, "sink_candidates_matched": ${sinkCandidatesMatched}, "findings_returned": ${findingsReturned}}:TELEMETRY_END""")
}
