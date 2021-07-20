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
#include "..\..\Table.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.2/d8/dc8/tutorial_histogram_comparison.html
;~     opencv\samples\cpp\tutorial_code\Histograms_Matching\compareHist_Demo.cpp
;~     https://www.autoitscript.com/forum/topic/105814-table-udf/

#Region ### START Koda GUI section ### Form=
Local $iPicWidth = 300
Local $iPicHeight = 300

Local $FormGUI = GUICreate("Histogram Comparison", 996, 627, 192, 124)

Local $InputSrcBase = GUICtrlCreateInput("", 230, 16, 449, 21)
Local $ButtonSourceBase = GUICtrlCreateButton("Input 1", 689, 14, 75, 25)
Local $PicSourceBase = GUICtrlCreatePic("", 25, 120, $iPicWidth, $iPicHeight)

Local $InputSrcTest1 = GUICtrlCreateInput("", 230, 52, 449, 21)
Local $ButtonSourceTest1 = GUICtrlCreateButton("Input 2", 689, 50, 75, 25)
Local $PicSourceTest1 = GUICtrlCreatePic("", 349, 120, $iPicWidth, $iPicHeight)

Local $InputSrcTest2 = GUICtrlCreateInput("", 230, 88, 449, 21)
Local $ButtonSourceTest2 = GUICtrlCreateButton("Input 3", 689, 86, 75, 25)
Local $PicSourceTest2 = GUICtrlCreatePic("", 673, 120, $iPicWidth, $iPicHeight)

Local $BtnExec = GUICtrlCreateButton("Execute", 832, 48, 75, 25)

; Local $EditOut = GUICtrlCreateEdit("", 25, 432, 948, 145)
; GUICtrlSetState(-1, $GUI_DISABLE)

GUISetState(@SW_SHOW)

GUISetState(@SW_LOCK)
Local $Table = _GUICtrlTable_Create(25, 432, 189, 28, 5, 5, 0)
_GUICtrlTable_Set_RowHeight($Table, 1, 35)
_GUICtrlTable_Set_Justify_All($Table, 1, 1)
_GUICtrlTable_Set_TextFont_All($Table, 8.5, 800, 0, "Tahoma")
_GUICtrlTable_Set_CellColor_Row($Table, 1, 0x374F7F)
_GUICtrlTable_Set_TextColor_All($Table, 0x555555)
_GUICtrlTable_Set_TextColor_Row($Table, 1, 0xFFFFFF)
For $row = 3 To 5 Step 2
    _GUICtrlTable_Set_CellColor_Row($Table, $row, 0xDDDDDD)
Next
_GUICtrlTable_Set_Text_Row($Table, 1, "*Method*|Base - Base|Base - Half|Base - Test 1|Base - Test 2")
_GUICtrlTable_Set_Border_Table($Table, 0x555555)
GUISetState(@SW_UNLOCK)

#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(@ScriptDir & "\..\..\..\libemgucv-windesktop-4.5.2.4673\libs\x64\cvextern.dll")

Local $tBlueColor = _cvScalar(255, 0, 0)
Local $tGreenColor = _cvScalar(0, 255, 0)
Local $tRedColor = _cvScalar(0, 0, 255)
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sSrcBase = "", $sSrcTest1 = "", $sSrcTest2 = ""
Local $nMsg

Local $src_base, $src_test1, $src_test2
Local $hist_base, $hist_half_down, $hist_test1, $hist_test2
Local $hsv_base, $hsv_test1, $hsv_test2, $hsv_half_down
Local $aMethodName[4] = ["Correlation", "Chi-square", "Intersection", "Bhattacharyya"]

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			clean()
			Exit
		Case $ButtonSourceBase
			$sSrcBase = FileOpenDialog("Select an image", @ScriptDir & "\..\..\data", "Image files (*.bmp;*.jpg;*.jpeg)", $FD_FILEMUSTEXIST, $sSrcBase)
			If @error Then
				$sSrcBase = ""
			Else
				ControlSetText($FormGUI, "", $InputSrcBase, $sSrcBase)
			EndIf
		Case $ButtonSourceTest1
			$sSrcTest1 = FileOpenDialog("Select an image", @ScriptDir & "\..\..\data", "Image files (*.bmp;*.jpg;*.jpeg)", $FD_FILEMUSTEXIST, $sSrcTest1)
			If @error Then
				$sSrcTest1 = ""
			Else
				ControlSetText($FormGUI, "", $InputSrcTest1, $sSrcTest1)
			EndIf
		Case $ButtonSourceTest2
			$sSrcTest2 = FileOpenDialog("Select an image", @ScriptDir & "\..\..\data", "Image files (*.bmp;*.jpg;*.jpeg)", $FD_FILEMUSTEXIST, $sSrcTest2)
			If @error Then
				$sSrcTest2 = ""
			Else
				ControlSetText($FormGUI, "", $InputSrcTest2, $sSrcTest2)
			EndIf
		Case $BtnExec
			clean()
			onImageChange()
	EndSwitch
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func onImageChange()
	;;! [Load three images with different environment settings]
	$sSrcBase = ControlGetText($FormGUI, "", $InputSrcBase)
	$src_base = _cveImreadAndCheck($sSrcBase, $CV_IMREAD_COLOR)
	If @error Then
		$sSrcBase = ""
		Return
	EndIf

	$sSrcTest1 = ControlGetText($FormGUI, "", $InputSrcTest1)
	$src_test1 = _cveImreadAndCheck($sSrcTest1, $CV_IMREAD_COLOR)
	If @error Then
		_cveMatRelease($src_base)
		$sSrcBase = ""
		$sSrcTest1 = ""
		Return
	EndIf

	$sSrcTest2 = ControlGetText($FormGUI, "", $InputSrcTest2)
	$src_test2 = _cveImreadAndCheck($sSrcTest2, $CV_IMREAD_COLOR)
	If @error Then
		_cveMatRelease($src_base)
		_cveMatRelease($src_test1)
		$sSrcBase = ""
		$sSrcTest1 = ""
		$sSrcTest2 = ""
		Return
	EndIf
	;;! [Load three images with different environment settings]

	;;! [Display]
	Local $matSrcBaseResized = _cveMatResizeAndCenter($src_base, $iPicWidth, $iPicHeight, $tBackgroundColor, $CV_COLOR_BGR2BGRA)
	_cveSetControlPic($PicSourceBase, $matSrcBaseResized)
	_cveMatRelease($matSrcBaseResized)

	Local $matSrcTest1Resized = _cveMatResizeAndCenter($src_test1, $iPicWidth, $iPicHeight, $tBackgroundColor, $CV_COLOR_BGR2BGRA)
	_cveSetControlPic($PicSourceTest1, $matSrcTest1Resized)
	_cveMatRelease($matSrcTest1Resized)

	Local $matSrcTest2Resized = _cveMatResizeAndCenter($src_test2, $iPicWidth, $iPicHeight, $tBackgroundColor, $CV_COLOR_BGR2BGRA)
	_cveSetControlPic($PicSourceTest2, $matSrcTest2Resized)
	_cveMatRelease($matSrcTest2Resized)
	;;! [Display]

	;;! [Convert to HSV]
	$hsv_base = _cveMatCreate()
	$hsv_test1 = _cveMatCreate()
	$hsv_test2 = _cveMatCreate()

	_cveCvtColorMat($src_base, $hsv_base, $CV_COLOR_BGR2HSV)  ;
	_cveCvtColorMat($src_test1, $hsv_test1, $CV_COLOR_BGR2HSV)  ;
	_cveCvtColorMat($src_test2, $hsv_test2, $CV_COLOR_BGR2HSV)  ;
	;;! [Convert to HSV]

	;;! [Convert to HSV half]
	Local $tHsvBaseSize = _cvSize()
	_cveMatGetSize($hsv_base, $tHsvBaseSize)
	Local $iRows = $tHsvBaseSize.height
	Local $iCols = $tHsvBaseSize.width
	$tHsvBaseSize = 0
	Local $tHalfDownRect = _cvRect(0, $iCols / 2, $iRows, $iCols / 2)
	$hsv_half_down = _cveMatCreateFromRect($hsv_base, $tHalfDownRect)
	$tHalfDownRect = 0
	;;! [Convert to HSV half]

	;;! [Using 50 bins for hue and 60 for saturation]
	Local $h_bins = 50, $s_bins = 60 ;
	Local $histSize[2] = [$h_bins, $s_bins]  ;

	;; hue varies from 0 to 179, saturation from 0 to 255
	Local $h_ranges[2] = [0, 180]  ;
	Local $s_ranges[2] = [0, 256]  ;

	Local $ranges[4] = [$h_ranges[0], $h_ranges[1], $s_ranges[0], $s_ranges[1]]  ;

	;; Use the 0-th and 1-st channels
	Local $channels[2] = [0, 1]  ;
	;;! [Using 50 bins for hue and 60 for saturation]

	;;! [Calculate the histograms for the HSV images]
	$hist_base = _cveMatCreate()
	$hist_half_down = _cveMatCreate()
	$hist_test1 = _cveMatCreate()
	$hist_test2 = _cveMatCreate()

	Local $a_hsv_base[1] = [$hsv_base]
	_cveCalcHistMat($a_hsv_base, $channels, _cveNoArrayMat(), $hist_base, $histSize, $ranges, False)  ;
	_cveNormalizeMat($hist_base, $hist_base, 0, 1, $CV_NORM_MINMAX, -1, _cveNoArrayMat())  ;

	Local $a_hsv_half_down[1] = [$hsv_half_down]
	_cveCalcHistMat($a_hsv_half_down, $channels, _cveNoArrayMat(), $hist_half_down, $histSize, $ranges, False)  ;
	_cveNormalizeMat($hist_half_down, $hist_half_down, 0, 1, $CV_NORM_MINMAX, -1, _cveNoArrayMat())  ;

	Local $a_hsv_test1[1] = [$hsv_test1]
	_cveCalcHistMat($a_hsv_test1, $channels, _cveNoArrayMat(), $hist_test1, $histSize, $ranges, False)  ;
	_cveNormalizeMat($hist_test1, $hist_test1, 0, 1, $CV_NORM_MINMAX, -1, _cveNoArrayMat())  ;

	Local $a_hsv_test2[1] = [$hsv_test2]
	_cveCalcHistMat($a_hsv_test2, $channels, _cveNoArrayMat(), $hist_test2, $histSize, $ranges, False)  ;
	_cveNormalizeMat($hist_test2, $hist_test2, 0, 1, $CV_NORM_MINMAX, -1, _cveNoArrayMat())  ;
	;;! [Calculate the histograms for the HSV images]

	;;! [Apply the histogram comparison methods]
	GUISetState(@SW_LOCK)
	For $compare_method = 0 To 3 Step 1
		Local $base_base = _cveCompareHistMat($hist_base, $hist_base, $compare_method)  ;
		Local $base_half = _cveCompareHistMat($hist_base, $hist_half_down, $compare_method)  ;
		Local $base_test1 = _cveCompareHistMat($hist_base, $hist_test1, $compare_method)  ;
		Local $base_test2 = _cveCompareHistMat($hist_base, $hist_test2, $compare_method)  ;

		ConsoleWrite("Method " & $compare_method & " Perfect, Base-Half, Base-Test(1), Base-Test(2) : " _
				 & $base_base & " / " & $base_half & " / " & $base_test1 & " / " & $base_test2 & @CRLF)

		_GUICtrlTable_Set_Text_Row($Table, $compare_method + 2, "*" & $aMethodName[$compare_method] & "*|" _
				 & $base_base & "|" & $base_half & "|" & $base_test1 & "|" & $base_test2)
	Next
	GUISetState(@SW_UNLOCK)
	;;! [Apply the histogram comparison methods]

	ConsoleWrite("Done " & @CRLF) ;
EndFunc   ;==>onImageChange

Func clean()
	If $sSrcBase == "" Then Return

	_cveMatRelease($hist_base)
	_cveMatRelease($hist_half_down)
	_cveMatRelease($hist_test1)
	_cveMatRelease($hist_test2)

	_cveMatRelease($hsv_half_down)
	_cveMatRelease($hsv_base)
	_cveMatRelease($hsv_test1)
	_cveMatRelease($hsv_test2)

	_cveMatRelease($src_base)
	_cveMatRelease($src_test1)
	_cveMatRelease($src_test2)

	$sSrcBase = ""
	$sSrcTest1 = ""
	$sSrcTest2 = ""
EndFunc   ;==>clean
