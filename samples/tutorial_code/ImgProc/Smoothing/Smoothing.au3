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
#include <GUIConstantsEx.au3>
#include <Math.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/dc/dd3/tutorial_gausian_median_blur_bilateral_filter.html
;~     https://github.com/opencv/opencv/blob/4.5.3/samples/cpp/tutorial_code/ImgProc/Smoothing/Smoothing.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Smoothing Images", 1067, 641, 192, 124)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\lena.jpg", 264, 24, 449, 21)
GUICtrlSetState(-1, $GUI_DISABLE)
Local $BtnSource = GUICtrlCreateButton("Open", 723, 22, 75, 25)

Local $LabelMethod = GUICtrlCreateLabel("Method:", 504, 61, 59, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $ComboMethod = GUICtrlCreateCombo("", 568, 61, 145, 25, BitOR($GUI_SS_DEFAULT_COMBO, $CBS_SIMPLE))
GUICtrlSetData(-1, "Homogeneous Blur|Gaussian Blur|Median Blur|Bilateral Blur")

Local $BtnReplay = GUICtrlCreateButton("Replay", 723, 59, 75, 25)

Local $LabelSource = GUICtrlCreateLabel("Source Image", 231, 92, 100, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSource = GUICtrlCreateGroup("", 20, 115, 510, 516)
Local $PicSource = GUICtrlCreatePic("", 25, 126, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelResult = GUICtrlCreateLabel("Smoothing Demo", 735, 92, 120, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupResult = GUICtrlCreateGroup("", 532, 115, 510, 516)
Local $PicResult = GUICtrlCreatePic("", 537, 126, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL())

Local $tBlueColor = _cvScalar(255, 0, 0)
Local $tGreenColor = _cvScalar(0, 255, 0)
Local $tRedColor = _cvScalar(0, 0, 255)
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sImage = ""
Local $nMsg

Local $src

Local $DELAY_BLUR = 100 ;
Local $MAX_KERNEL_LENGTH = 31 ;

Local $aMethods[4] = ["Homogeneous Blur", "Gaussian Blur", "Median Blur", "Bilateral Blur"]
_GUICtrlComboBox_SetCurSel($ComboMethod, 0)

Main()

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Clean()
			Exit
		Case $BtnSource
			Clean()
			$sImage = ControlGetText($FormGUI, "", $InputSource)
			$sImage = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sImage)
			If Not @error Then
				ControlSetText($FormGUI, "", $InputSource, $sImage)
				Main()
			EndIf
		Case $BtnReplay
			Smooth()
		Case $ComboMethod
			Smooth()
	EndSwitch
WEnd

Clean()

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func Main()
	$sImage = ControlGetText($FormGUI, "", $InputSource)
	If $sImage == "" Then Return

	;;! [Load image]
	$src = _cveImreadAndCheck($sImage, $CV_IMREAD_COLOR)
	If @error Then
		$sImage = ""
		Return
	EndIf
	;;! [Load image]

	;;! [Display]
	; _cveImshowMat("Source image", $src );
	_cveImshowControlPic($src, $FormGUI, $PicSource, $tBackgroundColor)
	;;! [Display]

	Smooth()
EndFunc   ;==>Main

Func Smooth()
	If $sImage == "" Then Return

	Local $smooth_method = $aMethods[_GUICtrlComboBox_GetCurSel($ComboMethod)]
	Local $dst = _cveMatCreate()

	Switch $smooth_method
		Case "Homogeneous Blur"
			;;![blur]
			For $i = 1 To $MAX_KERNEL_LENGTH - 1 Step 2
				_cveBlurMat($src, $dst, _cvSize($i, $i), _cvPoint(-1, -1))   ;
				_cveImshowControlPic($dst, $FormGUI, $PicResult, $tBackgroundColor)
				Sleep($DELAY_BLUR)
			Next
			;;![blur]
		Case "Gaussian Blur"
			;;![gaussianblur]
			For $i = 1 To $MAX_KERNEL_LENGTH - 1 Step 2
				_cveGaussianBlurMat($src, $dst, _cvSize($i, $i), 0, 0)    ;
				_cveImshowControlPic($dst, $FormGUI, $PicResult, $tBackgroundColor)
				Sleep($DELAY_BLUR)
			Next
			;;![gaussianblur]
		Case "Median Blur"
			;;![medianblur]
			For $i = 1 To $MAX_KERNEL_LENGTH - 1 Step 2
				_cveMedianBlurMat($src, $dst, $i)  ;
				_cveImshowControlPic($dst, $FormGUI, $PicResult, $tBackgroundColor)
				Sleep($DELAY_BLUR)
			Next
			;;![medianblur]
		Case "Bilateral Blur"
			;;![bilateralfilter]
			For $i = 1 To $MAX_KERNEL_LENGTH - 1 Step 2
				_cveBilateralFilterMat($src, $dst, $i, $i * 2, $i / 2)
				_cveImshowControlPic($dst, $FormGUI, $PicResult, $tBackgroundColor)
				Sleep($DELAY_BLUR)
			Next
			;;![bilateralfilter]
	EndSwitch

	_cveMatRelease($dst)
EndFunc   ;==>Smooth

Func Clean()
	If $sImage == "" Then Return
	_cveMatRelease($src)
	$sImage = ""
EndFunc   ;==>Clean
