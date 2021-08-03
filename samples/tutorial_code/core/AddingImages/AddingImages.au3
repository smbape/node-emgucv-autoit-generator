#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)
Opt("GUIOnEventMode", 1)

#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <File.au3>
#include <GDIPlus.au3>
#include <GUIConstantsEx.au3>
#include <GuiSlider.au3>
#include <SliderConstants.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/d5/dc4/tutorial_adding_images.html
;~     https://github.com/opencv/opencv/blob/master/samples/cpp/tutorial_code/core/AddingImages/AddingImages.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Adding (blending) two images using OpenCV", 999, 500, 192, 124)

Local $InputSrc1 = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\LinuxLogo.jpg", 230, 16, 449, 21)
Local $BtnSrc1 = GUICtrlCreateButton("Input 1", 689, 14, 75, 25)

Local $InputSrc2 = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\WindowsLogo.jpg", 230, 52, 449, 21)
Local $BtnSrc2 = GUICtrlCreateButton("Input 2", 689, 50, 75, 25)

Local $LabelAlpha = GUICtrlCreateLabel("Alpha: 0.5", 230, 84, 104, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderAlpha = GUICtrlCreateSlider(342, 80, 422, 45)
GUICtrlSetData(-1, 50)

Local $BtnExec = GUICtrlCreateButton("Execute", 832, 48, 75, 25)

Local $LabelSrc1 = GUICtrlCreateLabel("Input 1", 144, 128, 49, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSrc1 = GUICtrlCreateGroup("", 20, 150, 310, 316)
Local $PicSrc1 = GUICtrlCreatePic("", 25, 161, 300, 300)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelSrc2 = GUICtrlCreateLabel("Input 2", 468, 128, 49, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSrc2 = GUICtrlCreateGroup("", 344, 150, 310, 316)
Local $PicSrc2 = GUICtrlCreatePic("", 349, 161, 300, 300)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelResult = GUICtrlCreateLabel("Linear Blend", 792, 128, 91, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupResult = GUICtrlCreateGroup("", 668, 150, 310, 316)
Local $PicResult = GUICtrlCreatePic("", 673, 161, 300, 300)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetOnEvent($GUI_EVENT_CLOSE, "_cleanExit")
GUICtrlSetOnEvent($BtnSrc1, "_handleBtnSrc1Click")
GUICtrlSetOnEvent($BtnSrc2, "_handleBtnSrc2Click")
GUICtrlSetOnEvent($BtnExec, "_handleExecuteClick")
GUICtrlSetOnEvent($SliderAlpha, "AddWeighted")

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GUICtrlSlider_SetTicFreq($SliderAlpha, 1)

_GDIPlus_Startup()
_OpenCV_DLLOpen(@ScriptDir & "\..\..\..\..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sSrc1 = "", $sSrc2 = ""
Local $src1, $src2
Local $warned = False

Main()

Local $current_alpha = GUICtrlRead($SliderAlpha)
Local $last_alpha = $current_alpha

While 1
	$current_alpha = GUICtrlRead($SliderAlpha)
	If $last_alpha <> $current_alpha Then
		AddWeighted()
		$last_alpha = $current_alpha
	EndIf
	Sleep(50) ; Sleep to reduce CPU usage
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func _handleBtnSrc1Click()
	$sSrc1 = ControlGetText($FormGUI, "", $InputSrc1)
	$sSrc1 = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sSrc1)
	If @error Then
		$sSrc1 = ""
	Else
		ControlSetText($FormGUI, "", $InputSrc1, $sSrc1)
	EndIf
EndFunc   ;==>_handleBtnSrc1Click

Func _handleBtnSrc2Click()
	$sSrc2 = ControlGetText($FormGUI, "", $InputSrc2)
	$sSrc2 = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sSrc2)
	If @error Then
		$sSrc2 = ""
	Else
		ControlSetText($FormGUI, "", $InputSrc2, $sSrc2)
	EndIf
EndFunc   ;==>_handleBtnSrc2Click

Func _handleExecuteClick()
	Clean()
	Main()
EndFunc   ;==>_handleExecuteClick

Func Main()
	;;! [Load three images with different environment settings]
	$sSrc1 = ControlGetText($FormGUI, "", $InputSrc1)
	$src1 = _cveImreadAndCheck($sSrc1, $CV_IMREAD_COLOR)
	If @error Then
		$sSrc1 = ""
		Return
	EndIf

	$sSrc2 = ControlGetText($FormGUI, "", $InputSrc2)
	$src2 = _cveImreadAndCheck($sSrc2, $CV_IMREAD_COLOR)
	If @error Then
		_cveMatRelease($src1)
		$sSrc1 = ""
		$sSrc2 = ""
		Return
	EndIf
	;;! [Load three images with different environment settings]

	;;! [Display]
	_cveImshowControlPic($src1, $FormGUI, $PicSrc1, $tBackgroundColor)
	_cveImshowControlPic($src2, $FormGUI, $PicSrc2, $tBackgroundColor)
	;;! [Display]

	$warned = False
	AddWeighted()
EndFunc   ;==>Main

Func Clean()
	If $sSrc1 == "" Then Return

	_cveMatRelease($src1)
	_cveMatRelease($src2)

	$sSrc1 = ""
	$sSrc2 = ""
EndFunc   ;==>Clean

Func AddWeighted()
	Local $alpha = GUICtrlRead($SliderAlpha) / 100
	GUICtrlSetData($LabelAlpha, "Alpha: " & StringFormat("%.2f", $alpha))

	If $sSrc1 == "" Then Return

	Local $tSrc1Size = _cvSize()
	_cveMatGetSize($src1, $tSrc1Size)

	Local $tSrc2Size = _cvSize()
	_cveMatGetSize($src2, $tSrc2Size)

	If $tSrc1Size.width <> $tSrc2Size.width Or $tSrc1Size.height <> $tSrc2Size.height Then
		If Not $warned Then
			ConsoleWriteError("!>Error: 'Input 1' and 'Input 2' should be of the same size" & @CRLF)
			$warned = True
		EndIf
		Return
	EndIf

	Local $dst = _cveMatCreate()

	;;![blend_images]
	Local $beta = (1.0 - $alpha) ;
	_cveAddWeightedMat($src1, $alpha, $src2, $beta, 0.0, $dst) ;
	;;![blend_images]

	;;![display]
	; _cveImshowMat( "Linear Blend", $dst );
	; _cveWaitKey(0);
	_cveImshowControlPic($dst, $FormGUI, $PicResult, $tBackgroundColor)
	;;![display]

	_cveMatRelease($dst)
EndFunc   ;==>AddWeighted

Func _cleanExit()
	If @GUI_WinHandle <> $FormGUI Then
		Return
	EndIf

	Clean()
	Exit
EndFunc   ;==>_cleanExit
