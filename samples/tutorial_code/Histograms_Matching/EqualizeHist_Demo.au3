#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <File.au3>
#include <FileConstants.au3>
#include <GDIPlus.au3>
#include <GUIConstantsEx.au3>
#include <Math.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/d4/d1b/tutorial_histogram_equalization.html
;~     https://github.com/opencv/opencv/blob/4.5.3/samples/cpp/tutorial_code/Histograms_Matching/EqualizeHist_Demo.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _OpenCV_FindFile("samples\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Histogram Equalization", 1065, 617, 192, 124)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\lena.jpg", 264, 24, 449, 21)
GUICtrlSetState(-1, $GUI_DISABLE)
Local $BtnSource = GUICtrlCreateButton("Open", 723, 22, 75, 25)

Local $LabelSource = GUICtrlCreateLabel("Source Image", 231, 60, 100, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSource = GUICtrlCreateGroup("", 20, 83, 510, 516)
Local $PicSource = GUICtrlCreatePic("", 25, 94, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelResult = GUICtrlCreateLabel("Equalized Image", 735, 60, 120, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupResult = GUICtrlCreateGroup("", 532, 83, 510, 516)
Local $PicResult = GUICtrlCreatePic("", 537, 94, 500, 500)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL())

Local $sImage = ""
Local $nMsg

Local $src, $dst

Main()

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Exit
		Case $BtnSource
			Clean()
			$sImage = ControlGetText($FormGUI, "", $InputSource)
			$sImage = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sImage)
			If @error Then
				$sImage = ""
			Else
				ControlSetText($FormGUI, "", $InputSource, $sImage)
				Main()
			EndIf
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

	;;! [Convert to grayscale]
	_cveCvtColorMat($src, $src, $CV_COLOR_BGR2GRAY)  ;
	;;! [Convert to grayscale]

	;;! [Apply Histogram Equalization]
	Local $dst = _cveMatCreate() ;
	_cveEqualizeHistMat($src, $dst)  ;
	;;! [Apply Histogram Equalization]

	;;! [Display]
	; _cveImshowMat("Source image", $src );
	; _cveImshowMat("Equalized Image", $dst );

	_cveImshowControlPic($src, $FormGUI, $PicSource)
	_cveImshowControlPic($dst, $FormGUI, $PicResult)
	;;! [Display]
EndFunc   ;==>Main

Func Clean()
	If $sImage == "" Then Return

	_cveMatRelease($dst)
	_cveMatRelease($src)
	$sImage = ""
EndFunc   ;==>Clean
