#include-once
#include "..\..\CVEUtils.au3"

Func _cvePlot2dSetMinX($obj, $value)
    ; CVAPI(void) cvePlot2dSetMinX(cv::plot::Plot2d* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetMinX", "ptr", $obj, "double", $value), "cvePlot2dSetMinX", @error)
EndFunc   ;==>_cvePlot2dSetMinX

Func _cvePlot2dSetMinY($obj, $value)
    ; CVAPI(void) cvePlot2dSetMinY(cv::plot::Plot2d* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetMinY", "ptr", $obj, "double", $value), "cvePlot2dSetMinY", @error)
EndFunc   ;==>_cvePlot2dSetMinY

Func _cvePlot2dSetMaxX($obj, $value)
    ; CVAPI(void) cvePlot2dSetMaxX(cv::plot::Plot2d* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetMaxX", "ptr", $obj, "double", $value), "cvePlot2dSetMaxX", @error)
EndFunc   ;==>_cvePlot2dSetMaxX

Func _cvePlot2dSetMaxY($obj, $value)
    ; CVAPI(void) cvePlot2dSetMaxY(cv::plot::Plot2d* obj, double value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetMaxY", "ptr", $obj, "double", $value), "cvePlot2dSetMaxY", @error)
EndFunc   ;==>_cvePlot2dSetMaxY

Func _cvePlot2dSetPlotLineWidth($obj, $value)
    ; CVAPI(void) cvePlot2dSetPlotLineWidth(cv::plot::Plot2d* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotLineWidth", "ptr", $obj, "int", $value), "cvePlot2dSetPlotLineWidth", @error)
EndFunc   ;==>_cvePlot2dSetPlotLineWidth

Func _cvePlot2dSetGridLinesNumber($obj, $value)
    ; CVAPI(void) cvePlot2dSetGridLinesNumber(cv::plot::Plot2d* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetGridLinesNumber", "ptr", $obj, "int", $value), "cvePlot2dSetGridLinesNumber", @error)
EndFunc   ;==>_cvePlot2dSetGridLinesNumber

Func _cvePlot2dSetPointIdxToPrint($obj, $value)
    ; CVAPI(void) cvePlot2dSetPointIdxToPrint(cv::plot::Plot2d* obj, int value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPointIdxToPrint", "ptr", $obj, "int", $value), "cvePlot2dSetPointIdxToPrint", @error)
EndFunc   ;==>_cvePlot2dSetPointIdxToPrint

Func _cvePlot2dSetInvertOrientation($obj, $value)
    ; CVAPI(void) cvePlot2dSetInvertOrientation(cv::plot::Plot2d* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetInvertOrientation", "ptr", $obj, "boolean", $value), "cvePlot2dSetInvertOrientation", @error)
EndFunc   ;==>_cvePlot2dSetInvertOrientation

Func _cvePlot2dSetShowText($obj, $value)
    ; CVAPI(void) cvePlot2dSetShowText(cv::plot::Plot2d* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetShowText", "ptr", $obj, "boolean", $value), "cvePlot2dSetShowText", @error)
EndFunc   ;==>_cvePlot2dSetShowText

Func _cvePlot2dSetShowGrid($obj, $value)
    ; CVAPI(void) cvePlot2dSetShowGrid(cv::plot::Plot2d* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetShowGrid", "ptr", $obj, "boolean", $value), "cvePlot2dSetShowGrid", @error)
EndFunc   ;==>_cvePlot2dSetShowGrid

Func _cvePlot2dSetNeedPlotLine($obj, $value)
    ; CVAPI(void) cvePlot2dSetNeedPlotLine(cv::plot::Plot2d* obj, bool value);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetNeedPlotLine", "ptr", $obj, "boolean", $value), "cvePlot2dSetNeedPlotLine", @error)
EndFunc   ;==>_cvePlot2dSetNeedPlotLine