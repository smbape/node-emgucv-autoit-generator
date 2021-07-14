#include-once
#include <..\CVEUtils.au3>

Func _DataLoggerCreate($logLevel, $loggerId)
    ; CVAPI(emgu::DataLogger*) DataLoggerCreate(int logLevel, int loggerId);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "DataLoggerCreate", "int", $logLevel, "int", $loggerId), "DataLoggerCreate", @error)
EndFunc   ;==>_DataLoggerCreate

Func _DataLoggerRelease(ByRef $logger)
    ; CVAPI(void) DataLoggerRelease(emgu::DataLogger** logger);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerRelease", "ptr*", $logger), "DataLoggerRelease", @error)
EndFunc   ;==>_DataLoggerRelease

Func _DataLoggerRegisterCallback(ByRef $logger, $messageCallback)
    ; CVAPI(void) DataLoggerRegisterCallback(emgu::DataLogger* logger, emgu::DataCallback messageCallback);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerRegisterCallback", "ptr", $logger, "emgu::DataCallback", $messageCallback), "DataLoggerRegisterCallback", @error)
EndFunc   ;==>_DataLoggerRegisterCallback

Func _DataLoggerLog(ByRef $logger, ByRef $data, $logLevel)
    ; CVAPI(void) DataLoggerLog(emgu::DataLogger* logger, void* data, int logLevel);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "DataLoggerLog", "ptr", $logger, "struct*", $data, "int", $logLevel), "DataLoggerLog", @error)
EndFunc   ;==>_DataLoggerLog