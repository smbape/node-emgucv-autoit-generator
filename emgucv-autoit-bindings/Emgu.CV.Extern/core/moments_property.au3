#include-once
#include "..\..\CVEUtils.au3"

Func _cveMomentsGetM00($obj)
    ; CVAPI(double) cveMomentsGetM00(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM00", $bObjDllType, $obj), "cveMomentsGetM00", @error)
EndFunc   ;==>_cveMomentsGetM00

Func _cveMomentsSetM00($obj, $value)
    ; CVAPI(void) cveMomentsSetM00(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM00", $bObjDllType, $obj, "double", $value), "cveMomentsSetM00", @error)
EndFunc   ;==>_cveMomentsSetM00

Func _cveMomentsGetM10($obj)
    ; CVAPI(double) cveMomentsGetM10(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM10", $bObjDllType, $obj), "cveMomentsGetM10", @error)
EndFunc   ;==>_cveMomentsGetM10

Func _cveMomentsSetM10($obj, $value)
    ; CVAPI(void) cveMomentsSetM10(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM10", $bObjDllType, $obj, "double", $value), "cveMomentsSetM10", @error)
EndFunc   ;==>_cveMomentsSetM10

Func _cveMomentsGetM01($obj)
    ; CVAPI(double) cveMomentsGetM01(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM01", $bObjDllType, $obj), "cveMomentsGetM01", @error)
EndFunc   ;==>_cveMomentsGetM01

Func _cveMomentsSetM01($obj, $value)
    ; CVAPI(void) cveMomentsSetM01(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM01", $bObjDllType, $obj, "double", $value), "cveMomentsSetM01", @error)
EndFunc   ;==>_cveMomentsSetM01

Func _cveMomentsGetM20($obj)
    ; CVAPI(double) cveMomentsGetM20(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM20", $bObjDllType, $obj), "cveMomentsGetM20", @error)
EndFunc   ;==>_cveMomentsGetM20

Func _cveMomentsSetM20($obj, $value)
    ; CVAPI(void) cveMomentsSetM20(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM20", $bObjDllType, $obj, "double", $value), "cveMomentsSetM20", @error)
EndFunc   ;==>_cveMomentsSetM20

Func _cveMomentsGetM11($obj)
    ; CVAPI(double) cveMomentsGetM11(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM11", $bObjDllType, $obj), "cveMomentsGetM11", @error)
EndFunc   ;==>_cveMomentsGetM11

Func _cveMomentsSetM11($obj, $value)
    ; CVAPI(void) cveMomentsSetM11(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM11", $bObjDllType, $obj, "double", $value), "cveMomentsSetM11", @error)
EndFunc   ;==>_cveMomentsSetM11

Func _cveMomentsGetM02($obj)
    ; CVAPI(double) cveMomentsGetM02(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM02", $bObjDllType, $obj), "cveMomentsGetM02", @error)
EndFunc   ;==>_cveMomentsGetM02

Func _cveMomentsSetM02($obj, $value)
    ; CVAPI(void) cveMomentsSetM02(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM02", $bObjDllType, $obj, "double", $value), "cveMomentsSetM02", @error)
EndFunc   ;==>_cveMomentsSetM02

Func _cveMomentsGetM30($obj)
    ; CVAPI(double) cveMomentsGetM30(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM30", $bObjDllType, $obj), "cveMomentsGetM30", @error)
EndFunc   ;==>_cveMomentsGetM30

Func _cveMomentsSetM30($obj, $value)
    ; CVAPI(void) cveMomentsSetM30(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM30", $bObjDllType, $obj, "double", $value), "cveMomentsSetM30", @error)
EndFunc   ;==>_cveMomentsSetM30

Func _cveMomentsGetM21($obj)
    ; CVAPI(double) cveMomentsGetM21(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM21", $bObjDllType, $obj), "cveMomentsGetM21", @error)
EndFunc   ;==>_cveMomentsGetM21

Func _cveMomentsSetM21($obj, $value)
    ; CVAPI(void) cveMomentsSetM21(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM21", $bObjDllType, $obj, "double", $value), "cveMomentsSetM21", @error)
EndFunc   ;==>_cveMomentsSetM21

Func _cveMomentsGetM12($obj)
    ; CVAPI(double) cveMomentsGetM12(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM12", $bObjDllType, $obj), "cveMomentsGetM12", @error)
EndFunc   ;==>_cveMomentsGetM12

Func _cveMomentsSetM12($obj, $value)
    ; CVAPI(void) cveMomentsSetM12(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM12", $bObjDllType, $obj, "double", $value), "cveMomentsSetM12", @error)
EndFunc   ;==>_cveMomentsSetM12

Func _cveMomentsGetM03($obj)
    ; CVAPI(double) cveMomentsGetM03(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetM03", $bObjDllType, $obj), "cveMomentsGetM03", @error)
EndFunc   ;==>_cveMomentsGetM03

Func _cveMomentsSetM03($obj, $value)
    ; CVAPI(void) cveMomentsSetM03(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetM03", $bObjDllType, $obj, "double", $value), "cveMomentsSetM03", @error)
EndFunc   ;==>_cveMomentsSetM03

Func _cveMomentsGetMu20($obj)
    ; CVAPI(double) cveMomentsGetMu20(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetMu20", $bObjDllType, $obj), "cveMomentsGetMu20", @error)
EndFunc   ;==>_cveMomentsGetMu20

Func _cveMomentsSetMu20($obj, $value)
    ; CVAPI(void) cveMomentsSetMu20(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetMu20", $bObjDllType, $obj, "double", $value), "cveMomentsSetMu20", @error)
EndFunc   ;==>_cveMomentsSetMu20

Func _cveMomentsGetMu11($obj)
    ; CVAPI(double) cveMomentsGetMu11(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetMu11", $bObjDllType, $obj), "cveMomentsGetMu11", @error)
EndFunc   ;==>_cveMomentsGetMu11

Func _cveMomentsSetMu11($obj, $value)
    ; CVAPI(void) cveMomentsSetMu11(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetMu11", $bObjDllType, $obj, "double", $value), "cveMomentsSetMu11", @error)
EndFunc   ;==>_cveMomentsSetMu11

Func _cveMomentsGetMu02($obj)
    ; CVAPI(double) cveMomentsGetMu02(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetMu02", $bObjDllType, $obj), "cveMomentsGetMu02", @error)
EndFunc   ;==>_cveMomentsGetMu02

Func _cveMomentsSetMu02($obj, $value)
    ; CVAPI(void) cveMomentsSetMu02(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetMu02", $bObjDllType, $obj, "double", $value), "cveMomentsSetMu02", @error)
EndFunc   ;==>_cveMomentsSetMu02

Func _cveMomentsGetMu30($obj)
    ; CVAPI(double) cveMomentsGetMu30(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetMu30", $bObjDllType, $obj), "cveMomentsGetMu30", @error)
EndFunc   ;==>_cveMomentsGetMu30

Func _cveMomentsSetMu30($obj, $value)
    ; CVAPI(void) cveMomentsSetMu30(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetMu30", $bObjDllType, $obj, "double", $value), "cveMomentsSetMu30", @error)
EndFunc   ;==>_cveMomentsSetMu30

Func _cveMomentsGetMu21($obj)
    ; CVAPI(double) cveMomentsGetMu21(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetMu21", $bObjDllType, $obj), "cveMomentsGetMu21", @error)
EndFunc   ;==>_cveMomentsGetMu21

Func _cveMomentsSetMu21($obj, $value)
    ; CVAPI(void) cveMomentsSetMu21(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetMu21", $bObjDllType, $obj, "double", $value), "cveMomentsSetMu21", @error)
EndFunc   ;==>_cveMomentsSetMu21

Func _cveMomentsGetMu12($obj)
    ; CVAPI(double) cveMomentsGetMu12(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetMu12", $bObjDllType, $obj), "cveMomentsGetMu12", @error)
EndFunc   ;==>_cveMomentsGetMu12

Func _cveMomentsSetMu12($obj, $value)
    ; CVAPI(void) cveMomentsSetMu12(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetMu12", $bObjDllType, $obj, "double", $value), "cveMomentsSetMu12", @error)
EndFunc   ;==>_cveMomentsSetMu12

Func _cveMomentsGetMu03($obj)
    ; CVAPI(double) cveMomentsGetMu03(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetMu03", $bObjDllType, $obj), "cveMomentsGetMu03", @error)
EndFunc   ;==>_cveMomentsGetMu03

Func _cveMomentsSetMu03($obj, $value)
    ; CVAPI(void) cveMomentsSetMu03(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetMu03", $bObjDllType, $obj, "double", $value), "cveMomentsSetMu03", @error)
EndFunc   ;==>_cveMomentsSetMu03

Func _cveMomentsGetNu20($obj)
    ; CVAPI(double) cveMomentsGetNu20(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetNu20", $bObjDllType, $obj), "cveMomentsGetNu20", @error)
EndFunc   ;==>_cveMomentsGetNu20

Func _cveMomentsSetNu20($obj, $value)
    ; CVAPI(void) cveMomentsSetNu20(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetNu20", $bObjDllType, $obj, "double", $value), "cveMomentsSetNu20", @error)
EndFunc   ;==>_cveMomentsSetNu20

Func _cveMomentsGetNu11($obj)
    ; CVAPI(double) cveMomentsGetNu11(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetNu11", $bObjDllType, $obj), "cveMomentsGetNu11", @error)
EndFunc   ;==>_cveMomentsGetNu11

Func _cveMomentsSetNu11($obj, $value)
    ; CVAPI(void) cveMomentsSetNu11(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetNu11", $bObjDllType, $obj, "double", $value), "cveMomentsSetNu11", @error)
EndFunc   ;==>_cveMomentsSetNu11

Func _cveMomentsGetNu02($obj)
    ; CVAPI(double) cveMomentsGetNu02(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetNu02", $bObjDllType, $obj), "cveMomentsGetNu02", @error)
EndFunc   ;==>_cveMomentsGetNu02

Func _cveMomentsSetNu02($obj, $value)
    ; CVAPI(void) cveMomentsSetNu02(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetNu02", $bObjDllType, $obj, "double", $value), "cveMomentsSetNu02", @error)
EndFunc   ;==>_cveMomentsSetNu02

Func _cveMomentsGetNu30($obj)
    ; CVAPI(double) cveMomentsGetNu30(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetNu30", $bObjDllType, $obj), "cveMomentsGetNu30", @error)
EndFunc   ;==>_cveMomentsGetNu30

Func _cveMomentsSetNu30($obj, $value)
    ; CVAPI(void) cveMomentsSetNu30(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetNu30", $bObjDllType, $obj, "double", $value), "cveMomentsSetNu30", @error)
EndFunc   ;==>_cveMomentsSetNu30

Func _cveMomentsGetNu21($obj)
    ; CVAPI(double) cveMomentsGetNu21(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetNu21", $bObjDllType, $obj), "cveMomentsGetNu21", @error)
EndFunc   ;==>_cveMomentsGetNu21

Func _cveMomentsSetNu21($obj, $value)
    ; CVAPI(void) cveMomentsSetNu21(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetNu21", $bObjDllType, $obj, "double", $value), "cveMomentsSetNu21", @error)
EndFunc   ;==>_cveMomentsSetNu21

Func _cveMomentsGetNu12($obj)
    ; CVAPI(double) cveMomentsGetNu12(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetNu12", $bObjDllType, $obj), "cveMomentsGetNu12", @error)
EndFunc   ;==>_cveMomentsGetNu12

Func _cveMomentsSetNu12($obj, $value)
    ; CVAPI(void) cveMomentsSetNu12(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetNu12", $bObjDllType, $obj, "double", $value), "cveMomentsSetNu12", @error)
EndFunc   ;==>_cveMomentsSetNu12

Func _cveMomentsGetNu03($obj)
    ; CVAPI(double) cveMomentsGetNu03(cv::Moments* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveMomentsGetNu03", $bObjDllType, $obj), "cveMomentsGetNu03", @error)
EndFunc   ;==>_cveMomentsGetNu03

Func _cveMomentsSetNu03($obj, $value)
    ; CVAPI(void) cveMomentsSetNu03(cv::Moments* obj, double value);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMomentsSetNu03", $bObjDllType, $obj, "double", $value), "cveMomentsSetNu03", @error)
EndFunc   ;==>_cveMomentsSetNu03