#include-once
#include "..\..\CVEUtils.au3"

Func _cvePlatformInfoName($obj, $str)
    ; CVAPI(void) cvePlatformInfoName(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bStrIsString = IsString($str)
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoName", $sObjDllType, $obj, $sStrDllType, $str), "cvePlatformInfoName", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoName

Func _cvePlatformInfoVersion($obj, $str)
    ; CVAPI(void) cvePlatformInfoVersion(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bStrIsString = IsString($str)
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoVersion", $sObjDllType, $obj, $sStrDllType, $str), "cvePlatformInfoVersion", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoVersion

Func _cvePlatformInfoVendor($obj, $str)
    ; CVAPI(void) cvePlatformInfoVendor(cv::ocl::PlatformInfo* obj, cv::String* str);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf

    Local $bStrIsString = IsString($str)
    If $bStrIsString Then
        $str = _cveStringCreateFromStr($str)
    EndIf

    Local $sStrDllType
    If IsDllStruct($str) Then
        $sStrDllType = "struct*"
    Else
        $sStrDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlatformInfoVendor", $sObjDllType, $obj, $sStrDllType, $str), "cvePlatformInfoVendor", @error)

    If $bStrIsString Then
        _cveStringRelease($str)
    EndIf
EndFunc   ;==>_cvePlatformInfoVendor

Func _cvePlatformInfoDeviceNumber($obj)
    ; CVAPI(int) cvePlatformInfoDeviceNumber(cv::ocl::PlatformInfo* obj);

    Local $sObjDllType
    If IsDllStruct($obj) Then
        $sObjDllType = "struct*"
    Else
        $sObjDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePlatformInfoDeviceNumber", $sObjDllType, $obj), "cvePlatformInfoDeviceNumber", @error)
EndFunc   ;==>_cvePlatformInfoDeviceNumber