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
#include <Math.au3>
#include <Misc.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"
#include "..\..\..\autoit-addon\addon.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/de/da9/tutorial_template_matching.html
;~     https://github.com/opencv/opencv/blob/4.5.3/samples/cpp/tutorial_code/Histograms_Matching/MatchTemplate_Demo.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _OpenCV_FindFile("samples\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Changing the contrast and brightness of an image!", 1262, 672, 185, 122)

Local $InputFile = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\vtest.avi", 366, 16, 449, 21)
GUICtrlSetState(-1, $GUI_DISABLE)
Local $BtnFile = GUICtrlCreateButton("Video File", 825, 14, 75, 25)

Local $CheckboxUseCamera = GUICtrlCreateCheckbox("", 368, 56, 17, 17)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $LabelCamera = GUICtrlCreateLabel("Camera", 390, 56, 67, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $ComboCamera = GUICtrlCreateCombo("", 464, 56, 351, 25, BitOR($CBS_DROPDOWNLIST, $CBS_AUTOHSCROLL))

Local $GroupMethod = GUICtrlCreateGroup("Method", 368, 96, 137, 89)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $RadioKNN = GUICtrlCreateRadio("KNN", 392, 120, 73, 17)
GUICtrlSetFont(-1, 8, 400, 0, "MS Sans Serif")
Local $RadioMOG2 = GUICtrlCreateRadio("MOG2", 392, 152, 73, 17)
GUICtrlSetFont(-1, 8, 400, 0, "MS Sans Serif")
GUICtrlSetState(-1, $GUI_CHECKED)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $GroupCPUMode = GUICtrlCreateGroup("CPU mode", 528, 96, 137, 89)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $RadioOpenCL = GUICtrlCreateRadio("OpenCL", 552, 120, 73, 17)
Local $RadioCPU = GUICtrlCreateRadio("CPU", 552, 152, 73, 17)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $BtnStart = GUICtrlCreateButton("Start", 824, 104, 75, 25)
Local $BtnStop = GUICtrlCreateButton("Stop", 824, 144, 75, 25)

Local $LabelImage = GUICtrlCreateLabel("Image", 192, 216, 47, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupImage = GUICtrlCreateGroup("", 16, 240, 400, 400)
Local $PicImage = GUICtrlCreatePic("", 21, 251, 390, 384)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelForegroundMask = GUICtrlCreateLabel("Foreground mask", 567, 216, 125, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupForegroundMask = GUICtrlCreateGroup("", 430, 238, 400, 400)
Local $PicForegroundMask = GUICtrlCreatePic("", 435, 249, 390, 384)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelForegroundImage = GUICtrlCreateLabel("Foreground image", 975, 216, 131, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupForegroundImage = GUICtrlCreateGroup("", 840, 238, 400, 400)
Local $PicForegroundImage = GUICtrlCreatePic("", 845, 249, 390, 384)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL())
Local $bHasAddon = _Addon_DLLOpen(_Addon_FindDLL())

If _cveUseOpenCL() Then
	GUICtrlSetState($RadioOpenCL, $GUI_CHECKED)
Else
	GUICtrlSetState($RadioCPU, $GUI_CHECKED)
EndIf

Local $tPtr = DllStructCreate("ptr value")
Local $sCameraList = ""

Local Const $M_MOG2 = 2
Local Const $M_KNN = 3

Local $sInputFile = ""
Local $useCamera = False
Local $method
Local $cap = Null
Local $running = True
Local $bInitialized = False

Local $frame, $i_arr_frame
Local $fgmask, $i_arr_fgmask, $o_arr_fgmask
Local $fgimg, $i_arr_fgimg, $o_arr_fgimg

Local $tKNNSharedPtr
Local $knn

Local $tMOG2SharedPtr
Local $mog2

Local $mode

Local $hUser32DLL = DllOpen("user32.dll")

Local $nMsg

While 1
	$nMsg = GUIGetMsg()

	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Exit
		Case $BtnFile
			_handleBtnFileClick()
		Case $CheckboxUseCamera
			Reset()
		Case $RadioKNN
			Reset()
		Case $RadioMOG2
			Reset()
		Case $RadioOpenCL
			UpdateState()
		Case $RadioCPU
			UpdateState()
		Case $ComboCamera
			Reset()
		Case $BtnStart
			$running = True
		Case $BtnStop
			$running = False
	EndSwitch

	UpdateCameraList()

	If $running Then
		If $cap == Null Then
			Main()
			Sleep(1000) ; Sleep to reduce CPU usage
			ContinueLoop
		EndIf

		UpdateFrame()
	EndIf

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

Func _handleBtnFileClick()
	$sInputFile = ControlGetText($FormGUI, "", $InputFile)
	$sInputFile = FileOpenDialog("Select a video", $OPENCV_SAMPLES_DATA_PATH, "Video files (*.avi;*.mp4)", $FD_FILEMUSTEXIST, $sInputFile)
	If @error Then
		$sInputFile = ""
		Return
	EndIf

	ControlSetText($FormGUI, "", $InputFile, $sInputFile)
	Reset()
EndFunc   ;==>_handleBtnFileClick

Func Reset()
	Clean()
	Main()
EndFunc   ;==>Reset

Func Main()
	UpdateState()

	If $useCamera Then
		Local $iCamId = _Max(0, _GUICtrlComboBox_GetCurSel($ComboCamera))
		$cap = _cveVideoCaptureCreateFromDevice($iCamId, $CV_CAP_ANY, 0)
	Else
		$sInputFile = ControlGetText($FormGUI, "", $InputFile)
		$cap = _cveVideoCaptureCreateFromFile($sInputFile, $CV_CAP_ANY, 0)
	EndIf

	If Not _cveVideoCaptureIsOpened($cap) Then
		ConsoleWriteError("!>Error: cannot open camera or video file" & @CRLF)
		_cveVideoCaptureRelease($cap)
		$cap = Null
		Return
	EndIf

	$frame = _cveMatCreate()
	$i_arr_frame = _cveInputArrayFromMat($frame)
EndFunc   ;==>Main

Func Clean()
	If $cap == Null Then Return

	If $bInitialized Then
		_cveOutputArrayRelease($o_arr_fgmask)
		_cveInputArrayRelease($i_arr_fgmask)
		_cveMatRelease($fgmask)

		_cveOutputArrayRelease($o_arr_fgimg)
		_cveInputArrayRelease($i_arr_fgimg)
		_cveMatRelease($fgimg)

		_cveBackgroundSubtractorMOG2Release($mog2, $tMOG2SharedPtr)
		_cveBackgroundSubtractorKNNRelease($knn, $tKNNSharedPtr)

		$bInitialized = False
	EndIf

	_cveInputArrayRelease($i_arr_frame)
	_cveMatRelease($frame)

	_cveVideoCaptureRelease($cap)
	$cap = Null
EndFunc   ;==>Clean

Func UpdateState()
	$useCamera = _IsChecked($CheckboxUseCamera)

	If $useCamera Then
		GUICtrlSetState($BtnFile, $GUI_DISABLE)
		GUICtrlSetState($ComboCamera, $GUI_ENABLE)
	Else
		GUICtrlSetState($BtnFile, $GUI_ENABLE)
		GUICtrlSetState($ComboCamera, $GUI_DISABLE)
	EndIf

	If _IsChecked($RadioKNN) Then
		$method = $M_KNN
	Else
		$method = $M_MOG2
	EndIf

	Local $useOpenCL = _IsChecked($RadioOpenCL)
	If _cveUseOpenCL() <> $useOpenCL Then
		_cveSetUseOpenCL($useOpenCL)

		If $useOpenCL Then
			$mode = "OpenCL enabled"
		Else
			$mode = "CPU"
		EndIf
		ConsoleWrite("Switched to " & $mode & " mode" & @CRLF)
	EndIf
EndFunc   ;==>UpdateState

Func InitState()
	If $bInitialized Then Return

	Local $tKNNBgSubtractorPtr = DllStructCreate("ptr value")
	Local $tKNNAlgorithmPtr = DllStructCreate("ptr value")
	$tKNNSharedPtr = DllStructCreate("ptr value")
	_cveBackgroundSubtractorKNNCreate(500, 400, True, $tKNNBgSubtractorPtr, $tKNNAlgorithmPtr, $tKNNSharedPtr)
	$knn = $tKNNBgSubtractorPtr.value

	Local $tMOG2BgSubtractorPtr = DllStructCreate("ptr value")
	Local $tMOG2AlgorithmPtr = DllStructCreate("ptr value")
	$tMOG2SharedPtr = DllStructCreate("ptr value")
	_cveBackgroundSubtractorMOG2Create(500, 16, True, $tMOG2BgSubtractorPtr, $tMOG2AlgorithmPtr, $tMOG2SharedPtr)
	$mog2 = $tMOG2BgSubtractorPtr.value

	Local $tMatImg = DllStructCreate($tagCvMat, $frame)
	$fgimg = _cveMatCreate()
	$i_arr_fgimg = _cveInputArrayFromMat($fgimg)
	$o_arr_fgimg = _cveOutputArrayFromMat($fgimg)
	_cveMatCreateData($fgimg, $tMatImg.rows, $tMatImg.cols, CV_MAT_TYPE($tMatImg.flags))

	$fgmask = _cveMatCreate()
	$i_arr_fgmask = _cveInputArrayFromMat($fgmask)
	$o_arr_fgmask = _cveOutputArrayFromMat($fgmask)

	$bInitialized = True
EndFunc   ;==>InitState

Func UpdateFrame()
	If $cap == Null Then Return

	_cveVideoCaptureReadMat($cap, $frame)
	If _cveInputArrayIsEmptyMat($frame) Then
		If $useCamera Or Not $bInitialized Then
			ConsoleWriteError("!>Error: cannot read camera or video file." & @CRLF)
		Else
			Clean()
		EndIf
		Return
	EndIf

	InitState()

	Switch $method
		Case $M_KNN
			_cveBackgroundSubtractorUpdate($knn, $i_arr_frame, $o_arr_fgmask, -1)
		Case $M_MOG2
			_cveBackgroundSubtractorUpdate($mog2, $i_arr_frame, $o_arr_fgmask, -1)
	EndSwitch

	Local $scalar = _cveScalarCreate(_cvScalarAll(0))
	Local $i_arr_scalar = _cveInputArrayFromScalar($scalar)
	_cveMatSetTo($fgimg, $i_arr_scalar, _cveNoArray())
	_cveInputArrayRelease($i_arr_scalar)
	_cveScalarRelease($scalar)

	_cveMatCopyTo($frame, $o_arr_fgimg, $i_arr_fgmask)

	_cveImshowControlPic($frame, $FormGUI, $PicImage)
	_cveImshowControlPic($fgmask, $FormGUI, $PicForegroundMask)
	_cveImshowControlPic($fgimg, $FormGUI, $PicForegroundImage)
EndFunc   ;==>UpdateFrame

Func UpdateCameraList()
	If Not $bHasAddon Then Return

	Local $videoDevices = _VectorOfDeviceInfoCreate()
	_addonEnumerateVideoDevices($videoDevices)

	Local $tDevice, $tStr
	Local $sCamera = GUICtrlRead($ComboCamera)
	Local $sLongestString = ""
	Local $sOldCameraList = $sCameraList
	$sCameraList = ""

	For $i = _VectorOfDeviceInfoGetSize($videoDevices) - 1 To 0 Step -1
		_VectorOfDeviceInfoGetItemPtr($videoDevices, $i, $tPtr)
		$tDevice = DllStructCreate($tagAddonDeviceInfo, $tPtr.value)

		$tStr = DllStructCreate("wchar value[" & $tDevice.FriendlyNameLen & "]", $tDevice.FriendlyName)
		$sCameraList &= "|" & $tStr.value

		If StringLen($sLongestString) < StringLen($tStr.value) Then
			$sLongestString = $tStr.value
		EndIf
	Next

	_VectorOfDeviceInfoRelease($videoDevices)

	If StringLen($sCameraList) <> 0 Then
		$sCameraList = StringRight($sCameraList, StringLen($sCameraList) - 1)
	EndIf

	If StringCompare($sOldCameraList, $sCameraList, $STR_CASESENSE) == 0 Then Return

	_GUICtrlComboBox_ResetContent($ComboCamera)
	GUICtrlSetData($ComboCamera, $sCameraList)

	Local $avSize_Info = _StringSize($sLongestString)
	Local $aPos = ControlGetPos($FormGUI, "", $ComboCamera)
	GUICtrlSetPos($ComboCamera, $aPos[0], $aPos[1], _Max(145, $avSize_Info[2] + 20))

	If _GUICtrlComboBox_SelectString($ComboCamera, $sCamera) == -1 Then
		_GUICtrlComboBox_SetCurSel($ComboCamera, 0)
	EndIf
EndFunc   ;==>UpdateCameraList

Func _IsChecked($idControlID)
	Return BitAND(GUICtrlRead($idControlID), $GUI_CHECKED) = $GUI_CHECKED
EndFunc   ;==>_IsChecked

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
