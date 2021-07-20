#Region ;**** Directives created by AutoIt3Wrapper_GUI ****
#AutoIt3Wrapper_UseX64=y
#EndRegion ;**** Directives created by AutoIt3Wrapper_GUI ****

Opt("MustDeclareVars", 1)

#include <Math.au3>
#include <FileConstants.au3>
#include <ButtonConstants.au3>
#include <EditConstants.au3>
#include <GUIConstantsEx.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include <GDIPlus.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.2/d8/dbc/tutorial_histogram_calculation.html
;~     opencv\samples\cpp\tutorial_code\Histograms_Matching\calcHist_Demo.cpp

#Region ### START Koda GUI section ### Form=
Local $iPicWidth = 500
Local $iPicHeight = 500

Local $FormGUI = GUICreate("Histogram Calculation", 1063, 573, 192, 124)
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

Local $src, $brg_planes, $histImage, $b_hist, $g_hist, $r_hist

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			clean()
			Exit
		Case $ButtonSource
			clean()
			$sImage = FileOpenDialog("Select an image", @ScriptDir & "\..\..\data", "Image files (*.bmp;*.jpg;*.jpeg)", $FD_FILEMUSTEXIST, $sImage)
			If @error Then
				$sImage = ""
			Else
				ControlSetText($FormGUI, "", $InputSource, $sImage)
				onImageChange()
			EndIf
	EndSwitch
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func onImageChange()
	;;! [Load image]
	$src = _cveImreadAndCheck($sImage)
	If @error Then
		$sImage = Null
		Return
	EndIf
	;;! [Load image]

	;;! [Separate the image in 3 places ( B, G and R )]
	$brg_planes = _VectorOfMatCreate()
	Local $iArrSrc = _cveInputArrayFromMat($src)
	Local $oArrBgrPlanes = _cveOutputArrayFromVectorOfMat($brg_planes)
	_cveSplit($iArrSrc, $oArrBgrPlanes)
	_cveOutputArrayRelease($oArrBgrPlanes)
	_cveInputArrayRelease($iArrSrc)
	;;! [Separate the image in 3 places ( B, G and R )]

	;;! [Establish the number of bins]
	Local $histSize[1] = [256] ;
	;;! [Establish the number of bins]

	;;! [Set the ranges ( for B,G,R) )]
	Local $histRange[2] = [0, 256]  ; ;;the upper boundary is exclusive
	;;! [Set the ranges ( for B,G,R) )]

	;;! [Set histogram param]
	Local $accumulate = False ;
	;;! [Set histogram param]

	Local $channels[0]

	;;! [Compute the histograms]
	$b_hist = _cveMatCreate()
	$g_hist = _cveMatCreate()
	$r_hist = _cveMatCreate()

	Local $tMatPtr = DllStructCreate("ptr value")

	_VectorOfMatGetItemPtr($brg_planes, 0, $tMatPtr)
	Local $a_brg_planes_0[1] = [$tMatPtr.value]

	_VectorOfMatGetItemPtr($brg_planes, 1, $tMatPtr)
	Local $a_brg_planes_1[1] = [$tMatPtr.value]

	_VectorOfMatGetItemPtr($brg_planes, 2, $tMatPtr)
	Local $a_brg_planes_2[1] = [$tMatPtr.value]

	Local $matEmpty = _cveNoArrayMat()

	_cveCalcHistMat($a_brg_planes_0, $channels, $matEmpty, $b_hist, $histSize, $histRange, $accumulate)  ;
	_cveCalcHistMat($a_brg_planes_1, $channels, $matEmpty, $g_hist, $histSize, $histRange, $accumulate)  ;
	_cveCalcHistMat($a_brg_planes_2, $channels, $matEmpty, $r_hist, $histSize, $histRange, $accumulate)  ;
	;;! [Compute the histograms]

	;;! [Draw the histograms for B, G and R]
	Local $hist_w = 512, $hist_h = 400 ;
	Local $bin_w = Round($hist_w / $histSize[0]) ;

	$histImage = _cveMatCreate()
	_cveMatZeros($hist_h, $hist_w, $CV_8UC3, $histImage)
	;;! [Draw the histograms for B, G and R]

	;;! [Normalize the result to ( 0, histImage.rows )]
	_cveNormalizeMat($b_hist, $b_hist, 0, $hist_h, $CV_NORM_MINMAX, -1, $matEmpty) ;
	_cveNormalizeMat($g_hist, $g_hist, 0, $hist_h, $CV_NORM_MINMAX, -1, $matEmpty) ;
	_cveNormalizeMat($r_hist, $r_hist, 0, $hist_h, $CV_NORM_MINMAX, -1, $matEmpty) ;
	;;! [Normalize the result to ( 0, histImage.rows )]

	;;! [Draw for each channel]
	Local $hTimer

	$hTimer = TimerInit()
	For $i = 1 To $histSize[0] - 1
		_cveLineMat($histImage, _cvPoint($bin_w * ($i - 1), $hist_h - Round(_cveMatGetAt("float", $b_hist, _cvPoint(0, $i - 1)))), _
				_cvPoint($bin_w * $i, $hist_h - Round(_cveMatGetAt("float", $b_hist, _cvPoint(0, $i)))), _
				$tBlueColor, 2, 8, 0) ;
		_cveLineMat($histImage, _cvPoint($bin_w * ($i - 1), $hist_h - Round(_cveMatGetAt("float", $g_hist, _cvPoint(0, $i - 1)))), _
				_cvPoint($bin_w * $i, $hist_h - Round(_cveMatGetAt("float", $g_hist, _cvPoint(0, $i)))), _
				$tGreenColor, 2, 8, 0) ;
		_cveLineMat($histImage, _cvPoint($bin_w * ($i - 1), $hist_h - Round(_cveMatGetAt("float", $r_hist, _cvPoint(0, $i - 1)))), _
				_cvPoint($bin_w * $i, $hist_h - Round(_cveMatGetAt("float", $r_hist, _cvPoint(0, $i)))), _
				$tRedColor, 2, 8, 0) ;
	Next
	ConsoleWrite("Easy loop " & TimerDiff($hTimer) & @CRLF)

	$hTimer = TimerInit()
	Local $cvSize = DllStructCreate($tagCvSize)

	_cveMatGetSize($b_hist, $cvSize)
	Local $b_data_ptr = _cveMatGetDataPointer($b_hist)
	Local $b_step = _cveMatGetStep($b_hist)
	Local $b_data_struct = DllStructCreate("float value[" & $b_step * ($cvSize.height - 1) + $cvSize.width & "]", $b_data_ptr)

	_cveMatGetSize($g_hist, $cvSize)
	Local $g_data_ptr = _cveMatGetDataPointer($g_hist)
	Local $g_step = _cveMatGetStep($g_hist)
	Local $g_data_struct = DllStructCreate("float value[" & $g_step * ($cvSize.height - 1) + $cvSize.width & "]", $g_data_ptr)

	_cveMatGetSize($r_hist, $cvSize)
	Local $r_data_ptr = _cveMatGetDataPointer($r_hist)
	Local $r_step = _cveMatGetStep($r_hist)
	Local $r_data_struct = DllStructCreate("float value[" & $r_step * ($cvSize.height - 1) + $cvSize.width & "]", $r_data_ptr)

	For $i = 1 To $histSize[0] - 1
		_cveLineMat($histImage, _cvPoint($bin_w * ($i - 1), $hist_h - Round(DllStructGetData($b_data_struct, 1, $i))), _
				_cvPoint($bin_w * $i, $hist_h - Round(DllStructGetData($b_data_struct, 1, $i + 1))), _
				$tBlueColor, 2, 8, 0) ;
		_cveLineMat($histImage, _cvPoint($bin_w * ($i - 1), $hist_h - Round(DllStructGetData($g_data_struct, 1, $i))), _
				_cvPoint($bin_w * $i, $hist_h - Round(DllStructGetData($g_data_struct, 1, $i + 1))), _
				$tGreenColor, 2, 8, 0) ;
		_cveLineMat($histImage, _cvPoint($bin_w * ($i - 1), $hist_h - Round(DllStructGetData($r_data_struct, 1, $i))), _
				_cvPoint($bin_w * $i, $hist_h - Round(DllStructGetData($r_data_struct, 1, $i + 1))), _
				$tRedColor, 2, 8, 0) ;
	Next
	ConsoleWrite("Optimized loop " & TimerDiff($hTimer) & @CRLF)
	;;! [Draw for each channel]

	;;! [Display]
	; _cveImshowMat("Source image", $src );
	; _cveImshowMat("calcHist Demo", $histImage );

	Local $iCode = -1
	If _cveMatNumberOfChannels($src) == 3 Then
		$iCode = $CV_COLOR_BGR2BGRA
	EndIf
	Local $matSrcResized = _cveMatResizeAndCenter($src, $iPicWidth, $iPicHeight, $tBackgroundColor, $iCode)
	_cveSetControlPic($PicSource, $matSrcResized)
	_cveMatRelease($matSrcResized)

	Local $matHistResized = _cveMatResizeAndCenter($histImage, $iPicWidth, $iPicHeight, $tBackgroundColor, $CV_COLOR_BGR2BGRA)
	_cveSetControlPic($PicResult, $matHistResized)
	_cveMatRelease($matHistResized)
	;;! [Display]
EndFunc   ;==>onImageChange

Func clean()
	If $sImage == Null Then Return

	; _cveDestroyAllWindows()

	_cveMatRelease($histImage)

	_cveMatRelease($r_hist)
	_cveMatRelease($g_hist)
	_cveMatRelease($b_hist)

	_VectorOfMatRelease($brg_planes)

	_cveMatRelease($src)

	$sImage = Null
EndFunc   ;==>clean
