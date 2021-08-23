#include-once
#include "..\..\CVEUtils.au3"

Func _cveInferBboxCreate($deltaBbox, $classScores, $confScores)
    ; CVAPI(cv::dnn_objdetect::InferBbox*) cveInferBboxCreate(cv::Mat* deltaBbox, cv::Mat* classScores, cv::Mat* confScores);

    Local $sDeltaBboxDllType
    If IsDllStruct($deltaBbox) Then
        $sDeltaBboxDllType = "struct*"
    Else
        $sDeltaBboxDllType = "ptr"
    EndIf

    Local $sClassScoresDllType
    If IsDllStruct($classScores) Then
        $sClassScoresDllType = "struct*"
    Else
        $sClassScoresDllType = "ptr"
    EndIf

    Local $sConfScoresDllType
    If IsDllStruct($confScores) Then
        $sConfScoresDllType = "struct*"
    Else
        $sConfScoresDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInferBboxCreate", $sDeltaBboxDllType, $deltaBbox, $sClassScoresDllType, $classScores, $sConfScoresDllType, $confScores), "cveInferBboxCreate", @error)
EndFunc   ;==>_cveInferBboxCreate

Func _cveInferBboxFilter($inferBbox, $thresh)
    ; CVAPI(void) cveInferBboxFilter(cv::dnn_objdetect::InferBbox* inferBbox, double thresh);

    Local $sInferBboxDllType
    If IsDllStruct($inferBbox) Then
        $sInferBboxDllType = "struct*"
    Else
        $sInferBboxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInferBboxFilter", $sInferBboxDllType, $inferBbox, "double", $thresh), "cveInferBboxFilter", @error)
EndFunc   ;==>_cveInferBboxFilter

Func _cveInferBboxRelease($inferBbox)
    ; CVAPI(void) cveInferBboxRelease(cv::dnn_objdetect::InferBbox** inferBbox);

    Local $sInferBboxDllType
    If IsDllStruct($inferBbox) Then
        $sInferBboxDllType = "struct*"
    ElseIf $inferBbox == Null Then
        $sInferBboxDllType = "ptr"
    Else
        $sInferBboxDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInferBboxRelease", $sInferBboxDllType, $inferBbox), "cveInferBboxRelease", @error)
EndFunc   ;==>_cveInferBboxRelease