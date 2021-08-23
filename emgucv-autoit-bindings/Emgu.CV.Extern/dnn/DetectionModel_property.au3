#include-once
#include "..\..\CVEUtils.au3"

Func _cveDetectionModelGetNmsAcrossClasses($obj)
    ; CVAPI(bool) cveDetectionModelGetNmsAcrossClasses(cv::dnn::DetectionModel* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveDetectionModelGetNmsAcrossClasses", $sObjDllType, $obj), "cveDetectionModelGetNmsAcrossClasses", @error)
EndFunc   ;==>_cveDetectionModelGetNmsAcrossClasses

Func _cveDetectionModelSetNmsAcrossClasses($obj, $value)
    ; CVAPI(void) cveDetectionModelSetNmsAcrossClasses(cv::dnn::DetectionModel* obj, bool value);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDetectionModelSetNmsAcrossClasses", $sObjDllType, $obj, "boolean", $value), "cveDetectionModelSetNmsAcrossClasses", @error)
EndFunc   ;==>_cveDetectionModelSetNmsAcrossClasses