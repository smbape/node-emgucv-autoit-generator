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
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerRegisterCallback", "ptr", $logger, "emgu::DataCallback", $messageCallback), "DataLoggerRegisterCallback", @error)
EndFunc   ;==>_DataLoggerRegisterCallback

Func _DataLoggerLog($logger, $data, $logLevel)
    ; CVAPI(void) DataLoggerLog(emgu::DataLogger* logger, void* data, int logLevel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerLog", "ptr", $logger, "struct*", $data, "int", $logLevel), "DataLoggerLog", @error)
EndFunc   ;==>_DataLoggerLog