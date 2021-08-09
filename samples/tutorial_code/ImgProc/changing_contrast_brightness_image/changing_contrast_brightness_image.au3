#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)
Opt("GUIOnEventMode", 1)

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
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/d3/dc1/tutorial_basic_linear_transform.html
;~     https://github.com/opencv/opencv/blob/4.5.3/samples/cpp/tutorial_code/ImgProc/changing_contrast_brightness_image/changing_contrast_brightness_image.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _OpenCV_FindFile("samples\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Changing the contrast and brightness of an image!", 1261, 671, 185, 122)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\lena.jpg", 366, 16, 449, 21)
Local $BtnSource = GUICtrlCreateButton("Source", 825, 14, 75, 25)

Local $LabelAlpha = GUICtrlCreateLabel("Alpha gain (contrast) : ", 366, 56, 195, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderAlpha = GUICtrlCreateSlider(560, 56, 340, 45)
GUICtrlSetLimit(-1, 500, 0)
GUICtrlSetData(-1, 100)

Local $LabelBeta = GUICtrlCreateLabel("Beta bias (brightness) : ", 366, 112, 197, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderBeta = GUICtrlCreateSlider(560, 104, 340, 45)
GUICtrlSetLimit(-1, 200, 0)
GUICtrlSetData(-1, 100)

Local $LabelGamma = GUICtrlCreateLabel("Gamma correction : ", 366, 160, 178, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderGamma = GUICtrlCreateSlider(560, 152, 340, 45)
GUICtrlSetLimit(-1, 200, 0)
GUICtrlSetData(-1, 100)

Local $LabelSource = GUICtrlCreateLabel("Source Image", 170, 216, 100, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSource = GUICtrlCreateGroup("", 16, 240, 400, 400)
Local $PicSource = GUICtrlCreatePic("", 21, 251, 390, 384)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelLinearTransform = GUICtrlCreateLabel("Brightness and contrast adjustments", 504, 216, 253, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupLinearTransform = GUICtrlCreateGroup("", 430, 238, 400, 400)
Local $PicLinearTransform = GUICtrlCreatePic("", 435, 249, 390, 384)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelGammaCorrection = GUICtrlCreateLabel("Gamma correction", 975, 216, 130, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupGammaCorrection = GUICtrlCreateGroup("", 840, 238, 400, 400)
Local $PicGammaCorrection = GUICtrlCreatePic("", 845, 249, 390, 384)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetOnEvent($GUI_EVENT_CLOSE, "_cleanExit")
GUICtrlSetOnEvent($BtnSource, "_handleBtnSourceClick")

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GUICtrlSlider_SetTicFreq($SliderAlpha, 1)
_GUICtrlSlider_SetTicFreq($SliderBeta, 1)
_GUICtrlSlider_SetTicFreq($SliderGamma, 1)

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL())

Local $sInputSource, $img

Main()

Local $iCurrentAlpha = GUICtrlRead($SliderAlpha)
Local $iLastAlpha = $iCurrentAlpha

Local $iCurrentBeta = GUICtrlRead($SliderBeta)
Local $iLastBeta = $iCurrentBeta

Local $iCurrentGamma = GUICtrlRead($SliderGamma)
Local $iLastGamma = $iCurrentGamma

While 1
	$iCurrentAlpha = GUICtrlRead($SliderAlpha)
	$iCurrentBeta = GUICtrlRead($SliderBeta)
	If $iLastAlpha <> $iCurrentAlpha Or $iLastBeta <> $iCurrentBeta Then
		basicLinearTransform()
		$iLastAlpha = $iCurrentAlpha
		$iLastBeta = $iCurrentBeta
	EndIf

	$iCurrentGamma = GUICtrlRead($SliderGamma)
	If $iLastGamma <> $iCurrentGamma Then
		gammaCorrection()
		$iLastGamma = $iCurrentGamma
	EndIf

	Sleep(50) ; Sleep to reduce CPU usage
WEnd

Clean()

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func _handleBtnSourceClick()
	$sInputSource = ControlGetText($FormGUI, "", $InputSource)
	$sInputSource = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sInputSource)
	If @error Then
		$sInputSource = ""
		Return
	EndIf

	ControlSetText($FormGUI, "", $InputSource, $sInputSource)
	Clean()
	Main()
EndFunc   ;==>_handleBtnSourceClick

Func Main()
	$sInputSource = ControlGetText($FormGUI, "", $InputSource)
	If $sInputSource == "" Then Return

	;;! [Read the image]
	$img = _cveImreadAndCheck($sInputSource)
	If @error Then
		$sInputSource = ""
		Return
	EndIf
	;;! [Read the image]

	;;! [Show the image]
	_cveImshowControlPic($img, $FormGUI, $PicSource)
	;;! [Show the image]

	basicLinearTransform()
	gammaCorrection()
EndFunc   ;==>Main

Func basicLinearTransform()
	If $sInputSource == "" Then Return

	Local $alpha = GUICtrlRead($SliderAlpha) / 100
	GUICtrlSetData($LabelAlpha, "Alpha gain (contrast) : " & StringFormat("%.2f", $alpha))

	Local $beta = GUICtrlRead($SliderBeta) - 100
	GUICtrlSetData($LabelBeta, "Beta bias (brightness) : " & $beta)

	Local $res = _cveMatCreate() ;
	_cveMatConvertToMat($img, $res, -1, $alpha, $beta)

	_cveImshowControlPic($res, $FormGUI, $PicLinearTransform)

	_cveMatRelease($res)
EndFunc   ;==>basicLinearTransform

Func gammaCorrection()
	If $sInputSource == "" Then Return

	Local $gamma = GUICtrlRead($SliderGamma) / 100
	GUICtrlSetData($LabelGamma, "Gamma correction : " & StringFormat("%.2f", $gamma))

	;;! [changing-contrast-brightness-gamma-correction]
	Local $lookUpTable = _cveMatCreate()
	_cveMatCreateData($lookUpTable, 1, 256, $CV_8U)
	Local $ptr = _cveMatGetDataPointer2($lookUpTable, 0)
	Local $p = DllStructCreate("byte value[256]", $ptr)

	For $i = 0 To 255
		; For elements that are an array this specifies the 1-based index to set.
		$p.value(($i + 1)) = _Max(0, _Min(255, (($i / 255) ^ $gamma) * 255))
	Next

	Local $res = _cveMatCreate()
	_cveMatCopyToMat($img, $res, _cveNoArrayMat())
	_cveLUTMat($img, $lookUpTable, $res) ;
	;;! [changing-contrast-brightness-gamma-correction]

	_cveImshowControlPic($res, $FormGUI, $PicGammaCorrection)

	_cveMatRelease($res)
	_cveMatRelease($lookUpTable)
EndFunc   ;==>gammaCorrection

Func Clean()
	If $sInputSource == "" Then Return

	_cveMatRelease($img)

	$sInputSource = ""
EndFunc   ;==>Clean

Func _cleanExit()
	If @GUI_WinHandle <> $FormGUI Then
		Return
	EndIf

	Clean()
	Exit
EndFunc   ;==>_cleanExit
