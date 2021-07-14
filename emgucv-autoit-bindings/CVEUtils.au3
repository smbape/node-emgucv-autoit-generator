#include-once
#include <CVEConstants.au3>
#include <CVEtypes_c.au3>

Global $_h_cvextern_dll
Global $_cve_debug = 0

Func _DebugMsg($msg)
	If BitAND($_cve_debug, 1) Then
		ConsoleWrite($msg & @CRLF)
	Endif
	If BitAND($_cve_debug, 2) Then
		DllCall("kernel32.dll", "none", "OutputDebugString", "str", $msg)
	Endif
EndFunc

Func _LoadDLL($dll)
	_DebugMsg('Loading ' & $dll)
	Local $result = DllOpen($dll)
	If $result == -1 Then
		ConsoleWriteError('Error while loading ' & $dll & @CRLF)
	EndIf
	Return $result
EndFunc   ;==>_LoadDLL

Func _OpenCV_DLLOpen($s_cvextern_dll = "cvextern.dll")
	$_h_cvextern_dll = _LoadDLL($s_cvextern_dll)
EndFunc   ;==>_OpenCV_DLLOpen

Func _Opencv_DLLClose()
	DllClose($_h_cvextern_dll)
EndFunc   ;==>_Opencv_DLLClose

Func CVEDllCallResult($_aResult, $sFunction, $error = @error)
	_DebugMsg("called " & $sFunction)
	If $error Then
		_PrintDLLError($error, $sFunction)
		Return -1
	EndIf

	Return $_aResult[0]
EndFunc   ;==>CVEDllCallResult

Func _PrintDLLError($error, $sFunction = "function")
	Local $sMsg = ""

	Switch $error
		Case 1
			$sMsg = $sFunction & ': unable to use the DLL file'
		Case 2
			$sMsg = $sFunction & ': unknown "return type'
		Case 3
			$sMsg = '"' & $sFunction & '" not found in the DLL file'
		Case 4
			$sMsg = $sFunction & ': bad number of parameters'
		Case 5
			$sMsg = $sFunction & ': bad number of parameters'
		Case Else
			$sMsg = $sFunction & ': bad parameter'
	EndSwitch

	ConsoleWriteError('Error - ' & $sMsg & @CRLF)
EndFunc   ;==>_PrintDLLError
