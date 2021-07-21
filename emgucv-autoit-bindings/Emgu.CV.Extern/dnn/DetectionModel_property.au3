#include-once
#include "..\..\CVEUtils.au3"

Func _cveDetectionModelGetNmsAcrossClasses($obj)
    ; CVAPI(bool) cveDetectionModelGetNmsAcrossClasses(cv::dnn::DetectionModel* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDetectionModelGetNmsAcrossClasses", $bObjDllType, $obj), "cveDetectionModelGetNmsAcrossClasses", @error)
EndFunc   ;==>_cveDetectionModelGetNmsAcrossClasses

Func _cveDetectionModelSetNmsAcrossClasses($obj, $value)
    ; CVAPI(void) cveDetectionModelSetNmsAcrossClasses(cv::dnn::DetectionModel* obj, bool value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectionModelSetNmsAcrossClasses", $bObjDllType, $obj, "boolean", $value), "cveDetectionModelSetNmsAcrossClasses", @error)
EndFunc   ;==>_cveDetectionModelSetNmsAcrossClasses