#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <ButtonConstants.au3>
#include <ComboConstants.au3>
#include <EditConstants.au3>
#include <File.au3>
#include <FileConstants.au3>
#include <GDIPlus.au3>
#include <GuiComboBox.au3>
#include <GUIConstantsEx.au3>
#include <GuiSlider.au3>
#include <Math.au3>
#include <Misc.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"
#include "..\..\..\autoit-addon\addon.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/da/d97/tutorial_threshold_inRange.html
;~     https://github.com/opencv/opencv/tree/master/samples/cpp/tutorial_code/ImgProc/Threshold_inRange.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _OpenCV_FindFile("samples\data")

Local Const $max_value_H = 360 / 2 ;
Local Const $max_value = 255 ;

Local $low_H = 50 ;
Local $low_S = 0 ;
Local $low_V = 60 ;
Local $high_H = 140 ;
Local $high_S = $max_value ;
Local $high_V = 150 ;

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Thresholding Operations using inRange", 1066, 745, 192, 73)

Local $LabelCamera = GUICtrlCreateLabel("Camera", 24, 24, 58, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $ComboCamera = GUICtrlCreateCombo("", 136, 24, 120, 25, BitOR($CBS_DROPDOWNLIST, $CBS_AUTOHSCROLL))

Local $LabelLowH = GUICtrlCreateLabel("Low H: 180", 24, 64, 78, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderLowH = GUICtrlCreateSlider(128, 64, 400, 45)
GUICtrlSetLimit(-1, $max_value_H - 1, 0)

Local $LabelHighH = GUICtrlCreateLabel("High H: 180", 544, 64, 83, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderHighH = GUICtrlCreateSlider(648, 64, 400, 45)
GUICtrlSetLimit(-1, $max_value_H, 1)

Local $LabelLowS = GUICtrlCreateLabel("Low S: 255", 24, 104, 77, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderLowS = GUICtrlCreateSlider(128, 104, 400, 45)
GUICtrlSetLimit(-1, $max_value - 1, 0)

Local $LabelHighS = GUICtrlCreateLabel("High S: 255", 544, 104, 82, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderHighS = GUICtrlCreateSlider(648, 104, 400, 45)
GUICtrlSetLimit(-1, $max_value, 1)

Local $LabelLowV = GUICtrlCreateLabel("Low V: 255", 24, 144, 77, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderLowV = GUICtrlCreateSlider(128, 144, 400, 45)
GUICtrlSetLimit(-1, $max_value - 1, 0)

Local $LabelHighV = GUICtrlCreateLabel("High V: 255", 544, 144, 82, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderHighV = GUICtrlCreateSlider(648, 144, 400, 45)
GUICtrlSetLimit(-1, $max_value, 1)

Local $LabelVideoCapture = GUICtrlCreateLabel("Video Capture", 231, 196, 103, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupVideoCapture = GUICtrlCreateGroup("", 20, 219, 510, 516)
Local $PicVideoCapture = GUICtrlCreatePic("", 25, 230, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelObjectDetection = GUICtrlCreateLabel("Object Detection", 735, 196, 119, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupObjectDetection = GUICtrlCreateGroup("", 532, 219, 510, 516)
Local $PicObjectDetection = GUICtrlCreatePic("", 537, 230, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUICtrlSetData($SliderLowH, $low_H)
GUICtrlSetData($SliderLowS, $low_S)
GUICtrlSetData($SliderLowV, $low_V)
GUICtrlSetData($SliderHighH, $high_H)
GUICtrlSetData($SliderHighS, $high_S)
GUICtrlSetData($SliderHighV, $high_V)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GUICtrlSlider_SetTicFreq($SliderLowH, 1)
_GUICtrlSlider_SetTicFreq($SliderHighH, 1)
_GUICtrlSlider_SetTicFreq($SliderLowS, 1)
_GUICtrlSlider_SetTicFreq($SliderHighS, 1)
_GUICtrlSlider_SetTicFreq($SliderLowV, 1)
_GUICtrlSlider_SetTicFreq($SliderHighV, 1)

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL())
Local $bHasAddon = _Addon_DLLOpen(_Addon_FindDLL())

Local $tPtr = DllStructCreate("ptr value")
Local $sCameraList = ""

Local $iCamId = 0
Local $cap = Null

Local $frame
Local $frame_flipped
Local $frame_HSV
Local $frame_threshold

Local $iNewLowH, $iOldLowH, $iNewHighH, $iOldHighH
Local $iNewLowS, $iOldLowS, $iNewSighS, $iOldHighS
Local $iNewLowV, $iOldLowV, $iNewVighV, $iOldHighV

Local $hUser32DLL = DllOpen("user32.dll")

Local $nMsg

While 1
	$nMsg = GUIGetMsg()

	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Exit
		Case $ComboCamera
			Clean()
			Main()
	EndSwitch

	UpdateCameraList()

	If $cap == Null Then
		Main()
		Sleep(1000) ; Sleep to reduce CPU usage
		ContinueLoop
	EndIf

	$iNewLowH = GUICtrlRead($SliderLowH)
	If $iOldLowH <> $iNewLowH Then
		on_low_H_thresh_trackbar()
		$iOldLowH = $iNewLowH
	EndIf

	$iNewHighH = GUICtrlRead($SliderHighH)
	If $iOldHighH <> $iNewHighH Then
		on_high_H_thresh_trackbar()
		$iOldHighH = $iNewHighH
	EndIf

	$iNewLowS = GUICtrlRead($SliderLowS)
	If $iOldLowS <> $iNewLowS Then
		on_low_S_thresh_trackbar()
		$iOldLowS = $iNewLowS
	EndIf

	$iNewSighS = GUICtrlRead($SliderHighS)
	If $iOldHighS <> $iNewSighS Then
		on_high_S_thresh_trackbar()
		$iOldHighS = $iNewSighS
	EndIf

	$iNewLowV = GUICtrlRead($SliderLowV)
	If $iOldLowV <> $iNewLowV Then
		on_low_V_thresh_trackbar()
		$iOldLowV = $iNewLowV
	EndIf

	$iNewVighV = GUICtrlRead($SliderHighV)
	If $iOldHighV <> $iNewVighV Then
		on_high_V_thresh_trackbar()
		$iOldHighV = $iNewVighV
	EndIf

	UpdateFrame()

	If _IsPressed(Hex(Asc("Q")), $hUser32DLL) Then
		ExitLoop
	EndIf

	Sleep(30) ; Sleep to reduce CPU usage
WEnd

Clean()

DllClose($hUser32DLL)

If $bHasAddon Then _Addon_DLLClose()
_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func on_low_H_thresh_trackbar()
	$low_H = GUICtrlRead($SliderLowH)
	GUICtrlSetData($LabelLowH, "Low H: " & $low_H)

	$high_H = _Max($high_H, $low_H + 1)
	GUICtrlSetData($SliderHighH, $high_H)
EndFunc   ;==>on_low_H_thresh_trackbar

Func on_high_H_thresh_trackbar()
	$high_H = GUICtrlRead($SliderHighH)
	GUICtrlSetData($LabelHighH, "High H: " & $high_H)

	$low_H = _Min($high_H - 1, $low_H)
	GUICtrlSetData($SliderLowH, $low_H)
EndFunc   ;==>on_high_H_thresh_trackbar

Func on_low_S_thresh_trackbar()
	$low_S = GUICtrlRead($SliderLowS)
	GUICtrlSetData($LabelLowS, "Low S: " & $low_S)

	$high_S = _Max($high_S, $low_S + 1)
	GUICtrlSetData($SliderHighS, $high_S)
EndFunc   ;==>on_low_S_thresh_trackbar

Func on_high_S_thresh_trackbar()
	$high_S = GUICtrlRead($SliderHighS)
	GUICtrlSetData($LabelHighS, "High S: " & $high_S)

	$low_S = _Min($high_S - 1, $low_S)
	GUICtrlSetData($SliderLowS, $low_S)
EndFunc   ;==>on_high_S_thresh_trackbar

Func on_low_V_thresh_trackbar()
	$low_V = GUICtrlRead($SliderLowV)
	GUICtrlSetData($LabelLowV, "Low V: " & $low_V)

	$high_V = _Max($high_V, $low_V + 1)
	GUICtrlSetData($SliderHighV, $high_V)
EndFunc   ;==>on_low_V_thresh_trackbar

Func on_high_V_thresh_trackbar()
	$high_V = GUICtrlRead($SliderHighV)
	GUICtrlSetData($LabelHighV, "High V: " & $high_V)

	$low_V = _Min($high_V - 1, $low_V)
	GUICtrlSetData($SliderLowV, $low_V)
EndFunc   ;==>on_high_V_thresh_trackbar

Func Main()
	UpdateCameraList()
	on_low_H_thresh_trackbar()
	on_high_H_thresh_trackbar()
	on_low_S_thresh_trackbar()
	on_high_S_thresh_trackbar()
	on_low_V_thresh_trackbar()
	on_high_V_thresh_trackbar()

	Local $iCamId = _Max(0, _GUICtrlComboBox_GetCurSel($ComboCamera))
	$cap = _cveVideoCaptureCreateFromDevice($iCamId, $CV_CAP_ANY, 0)
	If Not _cveVideoCaptureIsOpened($cap) Then
		ConsoleWriteError("!>Error: cannot open the camera." & @CRLF)
		_cveVideoCaptureRelease($cap)
		$cap = Null
		Return
	EndIf

	$frame = _cveMatCreate()
	$frame_flipped = _cveMatCreate()
	$frame_HSV = _cveMatCreate()
	$frame_threshold = _cveMatCreate()
EndFunc   ;==>Main

Func Clean()
	If $cap == Null Then Return
	_cveMatRelease($frame_threshold)
	_cveMatRelease($frame_HSV)
	_cveMatRelease($frame_flipped)
	_cveMatRelease($frame)

	_cveVideoCaptureRelease($cap)
	$cap = Null
EndFunc   ;==>Clean

Func UpdateFrame()
	If $cap == Null Then Return

	_cveVideoCaptureReadMat($cap, $frame)
	If _cveInputArrayIsEmptyMat($frame) Then
		ConsoleWriteError("!>Error: cannot read the camera." & @CRLF)
		Return
	EndIf

	;; Flip the image horizontally to give the mirror impression
	_cveFlipMat($frame, $frame_flipped, 1)

	;; Convert from BGR to HSV colorspace
	_cveCvtColorMat($frame_flipped, $frame_HSV, $CV_COLOR_BGR2HSV) ;

	;; Detect the object based on HSV Range Values
	Local $lowHSVScalar = _cvScalar($low_H, $low_S, $low_V)
	Local $highHSVScalar = _cvScalar($high_H, $high_S, $high_V)
	_cveInRangeTyped("Mat", $frame_HSV, "Scalar", $lowHSVScalar, "Scalar", $highHSVScalar, "Mat", $frame_threshold) ;

	;;! [while]

	;;! [show]
	;; Show the frames
	_cveImshowControlPic($frame_flipped, $FormGUI, $PicVideoCapture)
	_cveImshowControlPic($frame_threshold, $FormGUI, $PicObjectDetection)
	;;! [show]
EndFunc   ;==>UpdateFrame

Func UpdateCameraList()
	If Not $bHasAddon Then Return

	Local $videoDevices = _VectorOfDeviceInfoCreate()
	_addonEnumerateVideoDevices($videoDevices)

	Local $tDevice, $tStr
	Local $sCamera = GUICtrlRead($ComboCamera)
	Local $sOldCameraList = $sCameraList
	$sCameraList = ""
	Local $longestString = ""

	For $i = _VectorOfDeviceInfoGetSize($videoDevices) - 1 To 0 Step -1
		_VectorOfDeviceInfoGetItemPtr($videoDevices, $i, $tPtr)
		$tDevice = DllStructCreate($tagAddonDeviceInfo, $tPtr.value)

		$tStr = DllStructCreate("wchar value[" & $tDevice.FriendlyNameLen & "]", $tDevice.FriendlyName)
		$sCameraList &= "|" & $tStr.value

		If StringLen($longestString) < StringLen($tStr.value) Then
			$longestString = $tStr.value
		EndIf
	Next

	_VectorOfDeviceInfoRelease($videoDevices)

	If StringLen($sCameraList) <> 0 Then
		$sCameraList = StringRight($sCameraList, StringLen($sCameraList) - 1)
	EndIf

	If StringCompare($sOldCameraList, $sCameraList, $STR_CASESENSE) == 0 Then Return

	_GUICtrlComboBox_ResetContent($ComboCamera)
	GUICtrlSetData($ComboCamera, $sCameraList)

	Local $avSize_Info = _StringSize($longestString)
	Local $aPos = ControlGetPos($FormGUI, "", $ComboCamera)
	GUICtrlSetPos($ComboCamera, $aPos[0], $aPos[1], _Max(145, $avSize_Info[2] + 20))

	If _GUICtrlComboBox_SelectString($ComboCamera, $sCamera) == -1 Then
		_GUICtrlComboBox_SetCurSel($ComboCamera, 0)
	EndIf
EndFunc   ;==>UpdateCameraList

; #FUNCTION# =======================================================================================
;
; Name...........: _StringSize
; Description ...: Returns size of rectangle required to display string - width can be chosen
; Syntax ........: _StringSize($sText[, $iSize[, $iWeight[, $iAttrib[, $sName[, $iWidth]]]]])
; Parameters ....: $sText   - String to display
;                 $iSize   - Font size in points - default AutoIt GUI default
;                 $iWeight - Font weight (400 = normal) - default AutoIt GUI default
;                 $iAttrib - Font attribute (0-Normal, 2-Italic, 4-Underline, 8 Strike - default AutoIt
;                 $sName   - Font name - default AutoIt GUI default
;                 $iWidth  - [optional] Width of rectangle - default is unwrapped width of string
; Requirement(s) : v3.2.12.1 or higher
; Return values .: Success - Returns array with details of rectangle required for text:
;                 |$array[0] = String formatted with @CRLF at required wrap points
;                 |$array[1] = Height of single line in selected font
;                 |$array[2] = Width of rectangle required to hold formatted string
;                 |$array[3] = Height of rectangle required to hold formatted string
;                 Failure - Returns 0 and sets @error:
;                 |1 - Incorrect parameter type (@extended = parameter index)
;                 |2 - Failure to create GUI to test label size
;                 |3 - Failure of _WinAPI_SelectObject
;                 |4 - Font too large for chosen width - longest word will not fit
; Author ........: Melba23
; Modified ......:
; Remarks .......:
; Related .......:
; Link ..........:
; Example .......: Yes
;===================================================================================================
Func _StringSize($sText, $iSize = Default, $iWeight = Default, $iAttrib = Default, $sName = Default, $iWidth = 0)
	Local $hWnd, $hFont, $hDC, $oFont, $tSize, $hGUI, $hText_Label, $sTest_Line
	Local $iLine_Count, $iLine_Width, $iWrap_Count, $iLast_Word
	Local $asLines[1], $avSize_Info[4], $aiPos[4]
	If Not IsString($sText) Then Return SetError(1, 1, 0)
	If Not IsNumber($iSize) And $iSize <> Default Then Return SetError(1, 2, 0)
	If Not IsInt($iWeight) And $iWeight <> Default Then Return SetError(1, 3, 0)
	If Not IsInt($iAttrib) And $iAttrib <> Default Then Return SetError(1, 4, 0)
	If Not IsString($sName) And $sName <> Default Then Return SetError(1, 5, 0)
	If Not IsNumber($iWidth) Then Return SetError(1, 6, 0)
	$hGUI = GUICreate("", 1200, 500, 10, 10)
	If $hGUI = 0 Then Return SetError(2, 0, 0)
	GUISetFont($iSize, $iWeight, $iAttrib, $sName)
	$avSize_Info[0] = $sText
	If StringInStr($sText, @CRLF) = 0 Then StringRegExpReplace($sText, "[x0a|x0d]", @CRLF)
	$asLines = StringSplit($sText, @CRLF, 1)
	$hText_Label = GUICtrlCreateLabel($sText, 10, 10)
	$aiPos = ControlGetPos($hGUI, "", $hText_Label)
	GUICtrlDelete($hText_Label)
	$avSize_Info[1] = ($aiPos[3] - 8) / $asLines[0]
	$avSize_Info[2] = $aiPos[2]
	$avSize_Info[3] = $aiPos[3] - 4
	If $aiPos[2] > $iWidth And $iWidth > 0 Then
		$avSize_Info[0] = ""
		$avSize_Info[2] = $iWidth
		$iLine_Count = 0
		For $j = 1 To $asLines[0]
			$hText_Label = GUICtrlCreateLabel($asLines[$j], 10, 10)
			$aiPos = ControlGetPos($hGUI, "", $hText_Label)
			GUICtrlDelete($hText_Label)
			If $aiPos[2] < $iWidth Then
				$iLine_Count += 1
				$avSize_Info[0] &= $asLines[$j] & @CRLF
			Else
				$hText_Label = GUICtrlCreateLabel("", 0, 0)
				$hWnd = ControlGetHandle($hGUI, "", $hText_Label)
				$hFont = _SendMessage($hWnd, $WM_GETFONT)
				$hDC = _WinAPI_GetDC($hWnd)
				$oFont = _WinAPI_SelectObject($hDC, $hFont)
				If $oFont = 0 Then Return SetError(3, 0, 0)
				$iWrap_Count = 0
				While 1
					$iLine_Width = 0
					$iLast_Word = 0
					For $i = 1 To StringLen($asLines[$j])
						If StringMid($asLines[$j], $i, 1) = " " Then $iLast_Word = $i - 1
						$sTest_Line = StringMid($asLines[$j], 1, $i)
						GUICtrlSetData($hText_Label, $sTest_Line)
						$tSize = _WinAPI_GetTextExtentPoint32($hDC, $sTest_Line)
						$iLine_Width = DllStructGetData($tSize, "X")
						If $iLine_Width >= $iWidth - Int($iSize / 2) Then ExitLoop
					Next
					If $i > StringLen($asLines[$j]) Then
						$iWrap_Count += 1
						$avSize_Info[0] &= $sTest_Line & @CRLF
						ExitLoop
					Else
						$iWrap_Count += 1
						If $iLast_Word = 0 Then
							GUIDelete($hGUI)
							Return SetError(4, 0, 0)
						EndIf
						$avSize_Info[0] &= StringLeft($sTest_Line, $iLast_Word) & @CRLF
						$asLines[$j] = StringTrimLeft($asLines[$j], $iLast_Word)
						$asLines[$j] = StringStripWS($asLines[$j], 1)
					EndIf
				WEnd
				$iLine_Count += $iWrap_Count
				_WinAPI_ReleaseDC($hWnd, $hDC)
				GUICtrlDelete($hText_Label)
			EndIf
		Next
		$avSize_Info[3] = ($iLine_Count * $avSize_Info[1]) + 4
	EndIf
	GUIDelete($hGUI)
	Return $avSize_Info
EndFunc   ;==>_StringSize
