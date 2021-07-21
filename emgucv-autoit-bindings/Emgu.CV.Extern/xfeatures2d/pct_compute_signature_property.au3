#include-once
#include "..\..\CVEUtils.au3"

Func _cvePCTSignaturesGetGrayscaleBits($obj)
    ; CVAPI(int) cvePCTSignaturesGetGrayscaleBits(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePCTSignaturesGetGrayscaleBits", $bObjDllType, $obj), "cvePCTSignaturesGetGrayscaleBits", @error)
EndFunc   ;==>_cvePCTSignaturesGetGrayscaleBits

Func _cvePCTSignaturesSetGrayscaleBits($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetGrayscaleBits(cv::xfeatures2d::PCTSignatures* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetGrayscaleBits", $bObjDllType, $obj, "int", $value), "cvePCTSignaturesSetGrayscaleBits", @error)
EndFunc   ;==>_cvePCTSignaturesSetGrayscaleBits

Func _cvePCTSignaturesGetWindowRadius($obj)
    ; CVAPI(int) cvePCTSignaturesGetWindowRadius(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePCTSignaturesGetWindowRadius", $bObjDllType, $obj), "cvePCTSignaturesGetWindowRadius", @error)
EndFunc   ;==>_cvePCTSignaturesGetWindowRadius

Func _cvePCTSignaturesSetWindowRadius($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetWindowRadius(cv::xfeatures2d::PCTSignatures* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetWindowRadius", $bObjDllType, $obj, "int", $value), "cvePCTSignaturesSetWindowRadius", @error)
EndFunc   ;==>_cvePCTSignaturesSetWindowRadius

Func _cvePCTSignaturesGetWeightX($obj)
    ; CVAPI(float) cvePCTSignaturesGetWeightX(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetWeightX", $bObjDllType, $obj), "cvePCTSignaturesGetWeightX", @error)
EndFunc   ;==>_cvePCTSignaturesGetWeightX

Func _cvePCTSignaturesSetWeightX($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetWeightX(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetWeightX", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetWeightX", @error)
EndFunc   ;==>_cvePCTSignaturesSetWeightX

Func _cvePCTSignaturesGetWeightY($obj)
    ; CVAPI(float) cvePCTSignaturesGetWeightY(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetWeightY", $bObjDllType, $obj), "cvePCTSignaturesGetWeightY", @error)
EndFunc   ;==>_cvePCTSignaturesGetWeightY

Func _cvePCTSignaturesSetWeightY($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetWeightY(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetWeightY", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetWeightY", @error)
EndFunc   ;==>_cvePCTSignaturesSetWeightY

Func _cvePCTSignaturesGetWeightL($obj)
    ; CVAPI(float) cvePCTSignaturesGetWeightL(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetWeightL", $bObjDllType, $obj), "cvePCTSignaturesGetWeightL", @error)
EndFunc   ;==>_cvePCTSignaturesGetWeightL

Func _cvePCTSignaturesSetWeightL($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetWeightL(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetWeightL", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetWeightL", @error)
EndFunc   ;==>_cvePCTSignaturesSetWeightL

Func _cvePCTSignaturesGetWeightA($obj)
    ; CVAPI(float) cvePCTSignaturesGetWeightA(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetWeightA", $bObjDllType, $obj), "cvePCTSignaturesGetWeightA", @error)
EndFunc   ;==>_cvePCTSignaturesGetWeightA

Func _cvePCTSignaturesSetWeightA($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetWeightA(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetWeightA", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetWeightA", @error)
EndFunc   ;==>_cvePCTSignaturesSetWeightA

Func _cvePCTSignaturesGetWeightB($obj)
    ; CVAPI(float) cvePCTSignaturesGetWeightB(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetWeightB", $bObjDllType, $obj), "cvePCTSignaturesGetWeightB", @error)
EndFunc   ;==>_cvePCTSignaturesGetWeightB

Func _cvePCTSignaturesSetWeightB($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetWeightB(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetWeightB", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetWeightB", @error)
EndFunc   ;==>_cvePCTSignaturesSetWeightB

Func _cvePCTSignaturesGetWeightEntropy($obj)
    ; CVAPI(float) cvePCTSignaturesGetWeightEntropy(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetWeightEntropy", $bObjDllType, $obj), "cvePCTSignaturesGetWeightEntropy", @error)
EndFunc   ;==>_cvePCTSignaturesGetWeightEntropy

Func _cvePCTSignaturesSetWeightEntropy($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetWeightEntropy(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetWeightEntropy", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetWeightEntropy", @error)
EndFunc   ;==>_cvePCTSignaturesSetWeightEntropy

Func _cvePCTSignaturesGetIterationCount($obj)
    ; CVAPI(int) cvePCTSignaturesGetIterationCount(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePCTSignaturesGetIterationCount", $bObjDllType, $obj), "cvePCTSignaturesGetIterationCount", @error)
EndFunc   ;==>_cvePCTSignaturesGetIterationCount

Func _cvePCTSignaturesSetIterationCount($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetIterationCount(cv::xfeatures2d::PCTSignatures* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetIterationCount", $bObjDllType, $obj, "int", $value), "cvePCTSignaturesSetIterationCount", @error)
EndFunc   ;==>_cvePCTSignaturesSetIterationCount

Func _cvePCTSignaturesGetMaxClustersCount($obj)
    ; CVAPI(int) cvePCTSignaturesGetMaxClustersCount(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePCTSignaturesGetMaxClustersCount", $bObjDllType, $obj), "cvePCTSignaturesGetMaxClustersCount", @error)
EndFunc   ;==>_cvePCTSignaturesGetMaxClustersCount

Func _cvePCTSignaturesSetMaxClustersCount($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetMaxClustersCount(cv::xfeatures2d::PCTSignatures* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetMaxClustersCount", $bObjDllType, $obj, "int", $value), "cvePCTSignaturesSetMaxClustersCount", @error)
EndFunc   ;==>_cvePCTSignaturesSetMaxClustersCount

Func _cvePCTSignaturesGetClusterMinSize($obj)
    ; CVAPI(int) cvePCTSignaturesGetClusterMinSize(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePCTSignaturesGetClusterMinSize", $bObjDllType, $obj), "cvePCTSignaturesGetClusterMinSize", @error)
EndFunc   ;==>_cvePCTSignaturesGetClusterMinSize

Func _cvePCTSignaturesSetClusterMinSize($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetClusterMinSize(cv::xfeatures2d::PCTSignatures* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetClusterMinSize", $bObjDllType, $obj, "int", $value), "cvePCTSignaturesSetClusterMinSize", @error)
EndFunc   ;==>_cvePCTSignaturesSetClusterMinSize

Func _cvePCTSignaturesGetJoiningDistance($obj)
    ; CVAPI(float) cvePCTSignaturesGetJoiningDistance(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetJoiningDistance", $bObjDllType, $obj), "cvePCTSignaturesGetJoiningDistance", @error)
EndFunc   ;==>_cvePCTSignaturesGetJoiningDistance

Func _cvePCTSignaturesSetJoiningDistance($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetJoiningDistance(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetJoiningDistance", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetJoiningDistance", @error)
EndFunc   ;==>_cvePCTSignaturesSetJoiningDistance

Func _cvePCTSignaturesGetDropThreshold($obj)
    ; CVAPI(float) cvePCTSignaturesGetDropThreshold(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "float:cdecl", "cvePCTSignaturesGetDropThreshold", $bObjDllType, $obj), "cvePCTSignaturesGetDropThreshold", @error)
EndFunc   ;==>_cvePCTSignaturesGetDropThreshold

Func _cvePCTSignaturesSetDropThreshold($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetDropThreshold(cv::xfeatures2d::PCTSignatures* obj, float value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetDropThreshold", $bObjDllType, $obj, "float", $value), "cvePCTSignaturesSetDropThreshold", @error)
EndFunc   ;==>_cvePCTSignaturesSetDropThreshold

Func _cvePCTSignaturesGetDistanceFunction($obj)
    ; CVAPI(int) cvePCTSignaturesGetDistanceFunction(cv::xfeatures2d::PCTSignatures* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePCTSignaturesGetDistanceFunction", $bObjDllType, $obj), "cvePCTSignaturesGetDistanceFunction", @error)
EndFunc   ;==>_cvePCTSignaturesGetDistanceFunction

Func _cvePCTSignaturesSetDistanceFunction($obj, $value)
    ; CVAPI(void) cvePCTSignaturesSetDistanceFunction(cv::xfeatures2d::PCTSignatures* obj, int value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePCTSignaturesSetDistanceFunction", $bObjDllType, $obj, "int", $value), "cvePCTSignaturesSetDistanceFunction", @error)
EndFunc   ;==>_cvePCTSignaturesSetDistanceFunction