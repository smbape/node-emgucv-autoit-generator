#include-once
#include "..\CVEUtils.au3"

Func _DataLoggerCreate($logLevel, $loggerId)
    ; CVAPI(emgu::DataLogger*) DataLoggerCreate(int logLevel, int loggerId);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "DataLoggerCreate", "int", $logLevel, "int", $loggerId), "DataLoggerCreate", @error)
EndFunc   ;==>_DataLoggerCreate

Func _DataLoggerRelease($logger)
    ; CVAPI(void) DataLoggerRelease(emgu::DataLogger** logger);

    Local $sLoggerDllType
    If IsDllStruct($logger) Then
        $sLoggerDllType = "struct*"
    ElseIf $logger == Null Then
        $sLoggerDllType = "ptr"
    Else
        $sLoggerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerRelease", $sLoggerDllType, $logger), "DataLoggerRelease", @error)
EndFunc   ;==>_DataLoggerRelease

Func _DataLoggerRegisterCallback($logger, $messageCallback)
    ; CVAPI(void) DataLoggerRegisterCallback(emgu::DataLogger* logger, emgu::DataCallback messageCallback);

    Local $sLoggerDllType
    If IsDllStruct($logger) Then
        $sLoggerDllType = "struct*"
    Else
        $sLoggerDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerRegisterCallback", $sLoggerDllType, $logger, "ptr", $messageCallback), "DataLoggerRegisterCallback", @error)
EndFunc   ;==>_DataLoggerRegisterCallback

Func _DataLoggerLog($logger, $data, $logLevel)
    ; CVAPI(void) DataLoggerLog(emgu::DataLogger* logger, void* data, int logLevel);

    Local $sLoggerDllType
    If IsDllStruct($logger) Then
        $sLoggerDllType = "struct*"
    Else
        $sLoggerDllType = "ptr"
    EndIf

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerLog", $sLoggerDllType, $logger, $sDataDllType, $data, "int", $logLevel), "DataLoggerLog", @error)
EndFunc   ;==>_DataLoggerLog