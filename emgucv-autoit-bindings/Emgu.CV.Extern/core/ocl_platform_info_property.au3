#include-once
#include "..\..\CVEUtils.au3"

Func _cvePlatformInfoName($obj, $str)
    ; CVAPI(void) cvePlatformInfoName(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoName", $bObjDllType, $obj, $bStrDllType, $str), "cvePlatformInfoName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoName

Func _cvePlatformInfoVersion($obj, $str)
    ; CVAPI(void) cvePlatformInfoVersion(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoVersion", $bObjDllType, $obj, $bStrDllType, $str), "cvePlatformInfoVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoVersion

Func _cvePlatformInfoVendor($obj, $str)
    ; CVAPI(void) cvePlatformInfoVendor(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf

    Local $bStrIsString = VarGetType($str) == "String"
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $bStrDllType
    If VarGetType($str) == "DLLStruct" Then
        $bStrDllType = "struct*"
    Else
        $bStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoVendor", $bObjDllType, $obj, $bStrDllType, $str), "cvePlatformInfoVendor", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoVendor

Func _cvePlatformInfoDeviceNumber($obj)
    ; CVAPI(int) cvePlatformInfoDeviceNumber(cv::ocl::PlatformInfo* obj);

    Local $bObjDllType
    If VarGetType($obj) == "DLLStruct" Then
        $bObjDllType = "struct*"
    Else
        $bObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePlatformInfoDeviceNumber", $bObjDllType, $obj), "cvePlatformInfoDeviceNumber", @error)
EndFunc   ;==>_cvePlatformInfoDeviceNumber