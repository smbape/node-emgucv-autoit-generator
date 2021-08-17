#include-once
#include "..\CVEUtils.au3"

Func _DataLoggerCreate($logLevel, $loggerId)
    ; CVAPI(emgu::DataLogger*) DataLoggerCreate(int logLevel, int loggerId);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "DataLoggerCreate", "int", $logLevel, "int", $loggerId), "DataLoggerCreate", @error)
EndFunc   ;==>_DataLoggerCreate

Func _DataLoggerRelease($logger)
    ; CVAPI(void) DataLoggerRelease(emgu::DataLogger** logger);

    Local $bLoggerDllType
    If VarGetType($logger) == "DLLStruct" Then
        $bLoggerDllType = "struct*"
    Else
        $bLoggerDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerRelease", $bLoggerDllType, $logger), "DataLoggerRelease", @error)
EndFunc   ;==>_DataLoggerRelease

Func _DataLoggerRegisterCallback($logger, $messageCallback)
    ; CVAPI(void) DataLoggerRegisterCallback(emgu::DataLogger* logger, emgu::DataCallback messageCallback);

    Local $bLoggerDllType
    If VarGetType($logger) == "DLLStruct" Then
        $bLoggerDllType = "struct*"
    Else
        $bLoggerDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerRegisterCallback", $bLoggerDllType, $logger, "ptr", $messageCallback), "DataLoggerRegisterCallback", @error)
EndFunc   ;==>_DataLoggerRegisterCallback

Func _DataLoggerLog($logger, $data, $logLevel)
    ; CVAPI(void) DataLoggerLog(emgu::DataLogger* logger, void* data, int logLevel);

    Local $bLoggerDllType
    If VarGetType($logger) == "DLLStruct" Then
        $bLoggerDllType = "struct*"
    Else
        $bLoggerDllType = "ptr"
    EndIf

    Local $bDataDllType
    If VarGetType($data) == "DLLStruct" Then
        $bDataDllType = "struct*"
    Else
        $bDataDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerLog", $bLoggerDllType, $logger, $bDataDllType, $data, "int", $logLevel), "DataLoggerLog", @error)
EndFunc   ;==>_DataLoggerLog