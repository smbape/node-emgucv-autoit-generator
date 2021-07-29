#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)
Opt("GUIOnEventMode", 1)

#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <File.au3>
#include <FileConstants.au3>
#include <GDIPlus.au3>
#include <GUIConstantsEx.au3>
#include <GuiSlider.au3>
#include <Math.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"
#include "..\..\Table.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.2/da/d7f/tutorial_back_projection.html
;~     https://github.com/opencv/opencv/blob/master/samples/cpp/tutorial_code/Histograms_Matching/calcBackProject_Demo1.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Back Projection", 1263, 601, 187, 122)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\lena.jpg", 364, 16, 449, 21)
GUICtrlSetState(-1, $GUI_DISABLE)
Local $BtnSource = GUICtrlCreateButton("Open", 823, 14, 75, 25)

Local $LabelBins = GUICtrlCreateLabel("* Hue  bins: 25", 364, 72, 110, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderBins = GUICtrlCreateSlider(491, 72, 394, 45)
GUICtrlSetLimit(-1, 180, 2)
GUICtrlSetData(-1, 25)

Local $LabelSource = GUICtrlCreateLabel("Source image", 144, 128, 49, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSource = GUICtrlCreateGroup("", 10, 150, 410, 416)
Local $PicSource = GUICtrlCreatePic("", 15, 161, 400, 400)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelBackProj = GUICtrlCreateLabel("BackProj", 468, 128, 67, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupBackProj = GUICtrlCreateGroup("", 426, 150, 410, 416)
Local $PicBackProj = GUICtrlCreatePic("", 431, 161, 400, 400)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelHistogram = GUICtrlCreateLabel("Histogram", 792, 128, 75, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupHistogram = GUICtrlCreateGroup("", 842, 150, 410, 416)
Local $PicHistogram = GUICtrlCreatePic("", 847, 161, 400, 400)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetOnEvent($GUI_EVENT_CLOSE, "_cleanExit")
GUICtrlSetOnEvent($BtnSource, "_handleBtnSourceClick")
GUICtrlSetOnEvent($SliderBins, "Hist_and_Backproj")

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GUICtrlSlider_SetTicFreq($SliderBins, 1)

_GDIPlus_Startup()
_OpenCV_DLLOpen(@ScriptDir & "\..\..\..\libemgucv-windesktop-4.5.2.4673\libs\x64\cvextern.dll")

Local $tBlueColor = _cvScalar(255, 0, 0)
Local $tGreenColor = _cvScalar(0, 255, 0)
Local $tRedColor = _cvScalar(0, 0, 255)
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sInputSource = ""
Local $src, $hsv, $hue

Main()

Local $current_bins = GUICtrlRead($SliderBins)
Local $last_bins = $current_bins

While 1
	$current_bins = GUICtrlRead($SliderBins)
	If $last_bins <> $current_bins Then
		Hist_and_Backproj()
		$last_bins = $current_bins
	EndIf
	Sleep(50) ; Sleep to reduce CPU usage
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func Main()
	$sInputSource = ControlGetText($FormGUI, "", $InputSource)
	If $sInputSource == "" Then Return

	;;! [Read the image]
	$src = _cveImreadAndCheck($sInputSource, $CV_IMREAD_COLOR)
	If @error Then
		$sInputSource = ""
		Return
	EndIf
	;;! [Read the image]

	;;! [Transform it to HSV]
	$hsv = _cveMatCreate() ;
	_cveCvtColorMat($src, $hsv, $CV_COLOR_BGR2HSV)  ;
	;;! [Transform it to HSV]

	;;! [Use only the Hue value]
	$hue = _cveMatCreate()
	Local $cvSize = _cvSize()
	_cveMatGetSize($hsv, $cvSize)
	_cveMatCreateData($hue, $cvSize.height, $cvSize.width, _cveMatDepth($hsv))
	$cvSize = 0
	Local $ch = DllStructCreate("int value[2]")
	$ch.value((0)) = 0
	$ch.value((1)) = 0
	Local $ahsv[1] = [$hsv]
	Local $ahue[1] = [$hue]
	_cveMixChannelsMat($ahsv, $ahue, $ch, 1)  ;
	;;! [Use only the Hue value]

	;;! [Create Trackbar to enter the number of bins]
	Hist_and_Backproj() ;
	;;! [Create Trackbar to enter the number of bins]

	;;! [Show the image]
	_cveImshowControlPic($src, $FormGUI, $PicSource, $tBackgroundColor)
	;;! [Show the image]

EndFunc   ;==>Main

Func Clean()
	If $sInputSource == "" Then Return

	_cveMatRelease($hue)
	_cveMatRelease($hsv)
	_cveMatRelease($src)
EndFunc   ;==>Clean

Func _handleBtnSourceClick()
	$sInputSource = ControlGetText($FormGUI, "", $InputSource)
	$sInputSource = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sInputSource)
	If @error Then
		$sInputSource = ""
		Return
	EndIf

	ControlSetText($FormGUI, "", $InputSource, $sInputSource)
	Main()
EndFunc   ;==>_handleBtnSourceClick

Func Hist_and_Backproj()
	If $sInputSource == "" Then Return

	Local $bins = GUICtrlRead($SliderBins)
	GUICtrlSetData($LabelBins, "* Hue  bins: " & $bins)

	Local $ahue[1] = [$hue]
	Local $channels[0]

	;;! [initialize]
	Local $histSize[1] = [_Max($bins, 2)] ;
	Local $hue_range[2] = [0, 180]  ;
	Local $ranges[2] = [$hue_range[0], $hue_range[1]]  ;
	;;! [initialize]

	;;! [Get the Histogram and normalize it]
	Local $hist = _cveMatCreate() ;
	_cveCalcHistMat($ahue, $channels, _cveNoArrayMat(), $hist, $histSize, $ranges, False)  ;
	_cveNormalizeMat($hist, $hist, 0, 255, $CV_NORM_MINMAX, -1, _cveNoArrayMat())  ;
	;;! [Get the Histogram and normalize it]

	;;! [Get Backprojection]
	Local $backproj = _cveMatCreate() ;
	_cveCalcBackProjectMat($ahue, $channels, $hist, $backproj, $ranges, 1)  ;
	;;! [Get Backprojection]

	;;! [Draw the backproj]
	; _cveImshowMat( "BackProj", $backproj );
	_cveImshowControlPic($backproj, $FormGUI, $PicBackProj, $tBackgroundColor)
	;;! [Draw the backproj]

	;;! [Draw the histogram]
	Local $w = 400, $h = 400 ;
	Local $bin_w = Round($w / $histSize[0])  ;
	Local $histImg = _cveMatCreate()
	_cveMatZeros($h, $w, $CV_8UC3, $histImg)

	Local $cvRect = _cvRect(0, 0, $bin_w, 0)

	If False Then
		;;! [Inefficient, but easier to write, way of doing _cveMatGetAt in a loop]
		For $i = 0 To $bins - 1
			$cvRect.width = $bin_w
			$cvRect.height = Round(_cveMatGetAt("float", $hist, _cvPoint(0, $i)) * $h / 255.0)
			$cvRect.x = $i * $bin_w
			$cvRect.y = $h - $cvRect.height
			_cveRectangleMat($histImg, $cvRect, $tRedColor, $CV_FILLED)  ;
		Next
		; ;;! [Inefficient, but easier to write, way of doing _cveMatGetAt in a loop]
	Else
		;;! [Efficient, but harder to write, way of doing _cveMatGetAt in a loop]
		Local $cvSize = DllStructCreate($tagCvSize)
		_cveMatGetSize($hist, $cvSize)
		Local $data_ptr = _cveMatGetDataPointer($hist)
		Local $step = _cveMatGetStep($hist)
		Local $data_struct = DllStructCreate("float[" & $step * ($cvSize.height - 1) + $cvSize.width & "]", $data_ptr)
		$cvSize = 0

		For $i = 0 To $bins - 1
			$cvRect.width = $bin_w
			$cvRect.height = Round(DllStructGetData($data_struct, 1, $i + 1))
			$cvRect.x = $i * $bin_w
			$cvRect.y = $h - $cvRect.height
			_cveRectangleMat($histImg, $cvRect, $tRedColor, $CV_FILLED)  ;
		Next
		;;! [Efficient, but harder to write, way of doing _cveMatGetAt in a loop]
	EndIf
	$cvRect = 0

	; _cveImshowMat( "Histogram", $histImg );
	_cveImshowControlPic($histImg, $FormGUI, $PicHistogram, $tBackgroundColor)
	;;! [Draw the histogram]

	_cveMatRelease($histImg)
	_cveMatRelease($backproj)
	_cveMatRelease($hist)
EndFunc   ;==>Hist_and_Backproj

Func _cleanExit()
	If @GUI_WinHandle <> $FormGUI Then
		Return
	EndIf

	Clean()
	Exit
EndFunc   ;==>_cleanExit
