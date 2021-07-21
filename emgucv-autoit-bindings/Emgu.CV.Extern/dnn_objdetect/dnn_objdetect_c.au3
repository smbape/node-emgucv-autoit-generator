#include-once
#include "..\..\CVEUtils.au3"

Func _cveInferBboxCreate($deltaBbox, $classScores, $confScores)
    ; CVAPI(cv::dnn_objdetect::InferBbox*) cveInferBboxCreate(cv::Mat* deltaBbox, cv::Mat* classScores, cv::Mat* confScores);

    Local $bDeltaBboxDllType
    If VarGetType($deltaBbox) == "DLLStruct" Then
        $bDeltaBboxDllType = "struct*"
    Else
        $bDeltaBboxDllType = "ptr"
    EndIf

    Local $bClassScoresDllType
    If VarGetType($classScores) == "DLLStruct" Then
        $bClassScoresDllType = "struct*"
    Else
        $bClassScoresDllType = "ptr"
    EndIf

    Local $bConfScoresDllType
    If VarGetType($confScores) == "DLLStruct" Then
        $bConfScoresDllType = "struct*"
    Else
        $bConfScoresDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInferBboxCreate", $bDeltaBboxDllType, $deltaBbox, $bClassScoresDllType, $classScores, $bConfScoresDllType, $confScores), "cveInferBboxCreate", @error)
EndFunc   ;==>_cveInferBboxCreate

Func _cveInferBboxFilter($inferBbox, $thresh)
    ; CVAPI(void) cveInferBboxFilter(cv::dnn_objdetect::InferBbox* inferBbox, double thresh);

    Local $bInferBboxDllType
    If VarGetType($inferBbox) == "DLLStruct" Then
        $bInferBboxDllType = "struct*"
    Else
        $bInferBboxDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInferBboxFilter", $bInferBboxDllType, $inferBbox, "double", $thresh), "cveInferBboxFilter", @error)
EndFunc   ;==>_cveInferBboxFilter

Func _cveInferBboxRelease($inferBbox)
    ; CVAPI(void) cveInferBboxRelease(cv::dnn_objdetect::InferBbox** inferBbox);

    Local $bInferBboxDllType
    If VarGetType($inferBbox) == "DLLStruct" Then
        $bInferBboxDllType = "struct*"
    Else
        $bInferBboxDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInferBboxRelease", $bInferBboxDllType, $inferBbox), "cveInferBboxRelease", @error)
EndFunc   ;==>_cveInferBboxRelease