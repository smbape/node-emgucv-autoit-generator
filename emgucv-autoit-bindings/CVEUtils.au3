#include-once
#include "cv_enums.au3"
#include "cv_constants.au3"
#include "CVEtypes_c.au3"

Global $_cve_debug = 0
Global $_h_cvextern_dll

Local $_mat_none = Null
Local $_io_arr_none = Null

Local $aOpenHooks[8]
Local $aCloseHooks[8]
Local $iOpenHook = 0
Local $iCloseHook = 0

Func _cveRegisterOpenHook($sCallback)
	If $iOpenHook == UBound($aOpenHooks) Then
		ReDim $aOpenHooks[$iOpenHook * 2]
	EndIf
	$aOpenHooks[$iOpenHook] = $sCallback
	$iOpenHook += 1
EndFunc   ;==>_cveRegisterOpenHook

Func _cveRegisterCloseHook($sCallback)
	If $iCloseHook == UBound($aCloseHooks) Then
		ReDim $aCloseHooks[$iCloseHook * 2]
	EndIf
	$aCloseHooks[$iCloseHook] = $sCallback
	$iCloseHook += 1
EndFunc   ;==>_cveRegisterCloseHook

Func _cveDebugMsg($msg)
	If BitAND($_cve_debug, 1) Then
		ConsoleWrite($msg & @CRLF)
	EndIf
	If BitAND($_cve_debug, 2) Then
		DllCall("kernel32.dll", "none", "OutputDebugString", "str", $msg)
	EndIf
EndFunc   ;==>_cveDebugMsg

Func _OpenCV_LoadDLL($dll)
	_cveDebugMsg('Loading ' & $dll)
	Local $result = DllOpen($dll)
	If $result == -1 Then
		ConsoleWriteError('Error while loading ' & $dll & @CRLF)
	EndIf
	Return $result
EndFunc   ;==>_OpenCV_LoadDLL

Func _OpenCV_DLLOpen($s_cvextern_dll = "cvextern.dll")
	$_h_cvextern_dll = _OpenCV_LoadDLL($s_cvextern_dll)
	$_mat_none = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveMatCreate"), "cveMatCreate", @error)
	$_io_arr_none = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveInputOutputArrayFromMat", "ptr", $_mat_none), "cveInputOutputArrayFromMat", @error)
	For $i = 0 To $iOpenHook - 1
		Call($aOpenHooks[$i])
	Next
EndFunc   ;==>_OpenCV_DLLOpen

Func _Opencv_DLLClose()
	For $i = $iCloseHook - 1 To 0 Step -1
		Call($aCloseHooks[$i])
	Next
	CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInputOutputArrayRelease", "ptr*", $_io_arr_none), "cveInputOutputArrayRelease", @error)
	CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveMatRelease", "ptr*", $_mat_none), "cveMatRelease", @error)
	$_mat_none = Null
	DllClose($_h_cvextern_dll)
EndFunc   ;==>_Opencv_DLLClose

Func _cveNoArray()
	Return $_io_arr_none
EndFunc   ;==>_cveNoArray

Func _cveNoArrayMat()
	Return $_mat_none
EndFunc   ;==>_cveNoArrayMat

Func _cveMorphologyDefaultBorderValue()
	Return _cvScalar($CV_DBL_MAX)
EndFunc   ;==>_cveMorphologyDefaultBorderValue

Func CVEDllCallResult($_aResult, $sFunction, $error = @error)
	_cveDebugMsg("called " & $sFunction)
	If $error Then
		_cvePrintDLLError($error, $sFunction)
		Return -1
	EndIf

	Return $_aResult[0]
EndFunc   ;==>CVEDllCallResult

Func _cvePrintDLLError($error, $sFunction = "function")
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
EndFunc   ;==>_cvePrintDLLError
