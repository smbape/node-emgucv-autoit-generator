#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <Math.au3>
#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include <GDIPlus.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"

; Source: opencv\samples\cpp\tutorial_code\Histograms_Matching\EqualizeHist_Demo.cpp

#Region ### START Koda GUI section ### Form=
Local $iPicWidth = 500
Local $iPicHeight = 500

Local $FormGUI = GUICreate("EqualizeHist Demo", 1063, 573, 192, 124)
Local $InputSource = GUICtrlCreateInput("", 264, 24, 449, 21)
GUICtrlSetState(-1, $GUI_DISABLE)
Local $ButtonSource = GUICtrlCreateButton("Open", 723, 22, 75, 25)
Local $PicSource = GUICtrlCreatePic("", 25, 56, $iPicWidth, $iPicHeight)
Local $PicResult = GUICtrlCreatePic("", 537, 56, $iPicWidth, $iPicHeight)
GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(@ScriptDir & "\..\..\..\libemgucv-windesktop-4.5.2.4673\libs\x64\cvextern.dll")

Local $tBlueColor = _cvScalar(255, 0, 0)
Local $tGreenColor = _cvScalar(0, 255, 0)
Local $tRedColor = _cvScalar(0, 0, 255)
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sImage = Null
Local $nMsg

Local $src, $dst

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			clean()
			Exit
		Case $ButtonSource
			$sImage = FileOpenDialog("Select an image", @ScriptDir & "\..\..\data", "Image files (*.bmp;*.jpg;*.jpeg)", 1)
			onImageChange()
	EndSwitch
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func onImageChange()
	;;! [Load image]
	$src = _cveImreadAndCheck($sImage, $CV_IMREAD_COLOR)
	If @error Then Return
	;;! [Load image]

    ;;! [Convert to grayscale]
    _cveCvtColorMat( $src, $src, $CV_COLOR_BGR2GRAY );
    ;;! [Convert to grayscale]

    ;;! [Apply Histogram Equalization]
    Local $dst = _cveMatCreate();
    _cveEqualizeHistMat( $src, $dst );
    ;;! [Apply Histogram Equalization]

	;;! [Display]
	; _cveImshowMat("Source image", $src );
	; _cveImshowMat("Equalized Image", $dst );
	ControlSetText($FormGUI, "", $InputSource, $sImage)

	Local $matSrcResized = _cveMatResizeAndCenter($src, $iPicWidth, $iPicHeight, $tBackgroundColor, $CV_COLOR_BGR2BGRA)
	_cveSetControlPic($PicSource, $matSrcResized)
	_cveMatRelease($matSrcResized)

	Local $matDstResized = _cveMatResizeAndCenter($dst, $iPicWidth, $iPicHeight, $tBackgroundColor, $CV_COLOR_BGR2BGRA)
	_cveSetControlPic($PicResult, $matDstResized)
	_cveMatRelease($matDstResized)
	;;! [Display]
EndFunc   ;==>onImageChange

Func clean()
	If $sImage == Null Then Return

	_cveMatRelease($dst)
	_cveMatRelease($src)
	$sImage = Null
EndFunc   ;==>clean
