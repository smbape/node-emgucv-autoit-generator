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
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/de/da9/tutorial_template_matching.html
;~     https://github.com/opencv/opencv/blob/4.5.3/samples/cpp/tutorial_code/Histograms_Matching/MatchTemplate_Demo.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Template Matching", 1267, 556, 185, 122)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\lena_tmpl.jpg", 366, 16, 449, 21)
Local $BtnSource = GUICtrlCreateButton("Source", 825, 14, 75, 25)

Local $InputTemplate = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\tmpl.png", 366, 52, 449, 21)
Local $BtnTemplate = GUICtrlCreateButton("Template", 825, 50, 75, 25)

Local $InputMask = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\mask.png", 366, 88, 449, 21)
Local $BtnMask = GUICtrlCreateButton("Mask", 825, 86, 75, 25)

Local $LabelMethod = GUICtrlCreateLabel("Method:", 604, 128, 59, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $ComboMethod = GUICtrlCreateCombo("", 670, 128, 145, 25, BitOR($GUI_SS_DEFAULT_COMBO, $CBS_SIMPLE))
GUICtrlSetData(-1, "TM SQDIFF|TM SQDIFF NORMED|TM CCORR|TM CCORR NORMED|TM CCOEFF|TM CCOEFF NORMED")

Local $BtnExec = GUICtrlCreateButton("Execute", 825, 126, 75, 25)

Local $LabelSource = GUICtrlCreateLabel("Source Image", 141, 168, 100, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSource = GUICtrlCreateGroup("", 20, 190, 342, 342)
Local $PicSource = GUICtrlCreatePic("", 25, 201, 332, 326)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelTemplate = GUICtrlCreateLabel("Template", 420, 176, 70, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupTemplate = GUICtrlCreateGroup("", 376, 190, 158, 158)
Local $PicTemplate = GUICtrlCreatePic("", 381, 201, 148, 142)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelMask = GUICtrlCreateLabel("Mask", 435, 360, 41, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupMask = GUICtrlCreateGroup("", 375, 374, 158, 158)
Local $PicMask = GUICtrlCreatePic("", 380, 385, 148, 142)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelMatchTemplate = GUICtrlCreateLabel("Match Template", 668, 168, 115, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupMatchTemplate = GUICtrlCreateGroup("", 544, 190, 342, 342)
Local $PicMatchTemplate = GUICtrlCreatePic("", 549, 201, 332, 326)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelResultImage = GUICtrlCreateLabel("Result Image", 1024, 168, 95, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupResultImage = GUICtrlCreateGroup("", 900, 190, 342, 342)
Local $PicResultImage = GUICtrlCreatePic("", 905, 201, 332, 326)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(_OpenCV_FindDLL(@ScriptDir))

Local $tBlueColor = _cvScalar(255, 0, 0)
Local $tGreenColor = _cvScalar(0, 255, 0)
Local $tRedColor = _cvScalar(0, 0, 255)
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sSource = "", $sTemplate = "", $sMask = ""
Local $img, $templ, $mask, $match_method
Local $nMsg

Local $aMethods[6] = [$CV_TM_SQDIFF, $CV_TM_SQDIFF_NORMED, $CV_TM_CCORR, $CV_TM_CCORR_NORMED, $CV_TM_CCOEFF, $CV_TM_CCOEFF_NORMED]
_GUICtrlComboBox_SetCurSel($ComboMethod, 3)

Local $image_window = "Source Image" ;
Local $result_window = "Result window" ;
Local $use_mask = False

Main()

While 1
	$nMsg = GUIGetMsg()
	Switch $nMsg
		Case $GUI_EVENT_CLOSE
			Clean()
			Exit
		Case $BtnSource
			$sSource = ControlGetText($FormGUI, "", $InputSource)
			$sSource = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sSource)
			If @error Then
				$sSource = ""
			Else
				ControlSetText($FormGUI, "", $InputSource, $sSource)
			EndIf
		Case $BtnTemplate
			$sTemplate = ControlGetText($FormGUI, "", $InputTemplate)
			$sTemplate = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sTemplate)
			If @error Then
				$sTemplate = ""
			Else
				ControlSetText($FormGUI, "", $InputTemplate, $sTemplate)
			EndIf
		Case $BtnMask
			$sMask = ControlGetText($FormGUI, "", $InputMask)
			$sMask = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sMask)
			If @error Then
				$sMask = ""
			Else
				ControlSetText($FormGUI, "", $InputMask, $sMask)
			EndIf
		Case $ComboMethod
			MatchingMethod()
		Case $BtnExec
			Clean()
			Main()
	EndSwitch
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func Main()
	;;! [load_image]
	;;/ Load image and template
	$sSource = ControlGetText($FormGUI, "", $InputSource)
	$img = _cveImreadAndCheck($sSource, $CV_IMREAD_COLOR)
	If @error Then
		$sSource = ""
		Return
	EndIf

	$sTemplate = ControlGetText($FormGUI, "", $InputTemplate)
	$templ = _cveImreadAndCheck($sTemplate, $CV_IMREAD_COLOR)
	If @error Then
		_cveMatRelease($img)
		$sSource = ""
		$sTemplate = ""
		Return
	EndIf

	$sMask = ControlGetText($FormGUI, "", $InputMask)
	If $sMask <> "" Then
		$mask = _cveImreadAndCheck($sMask, $CV_IMREAD_GRAYSCALE)
		If @error Then
			_cveMatRelease($img)
			_cveMatRelease($templ)
			$sSource = ""
			$sTemplate = ""
			$sMask = ""
			Return
		EndIf
		$use_mask = True
	Else
		$use_mask = False
		$mask = _cveNoArrayMat()
	EndIf
	;;! [load_image]

	;;! [Display]
	_cveImshowControlPic($img, $FormGUI, $PicSource, $tBackgroundColor)
	_cveImshowControlPic($templ, $FormGUI, $PicTemplate, $tBackgroundColor)

	If $use_mask Then
		_cveImshowControlPic($mask, $FormGUI, $PicMask, $tBackgroundColor)
	EndIf
	;;! [Display]

	MatchingMethod()
EndFunc   ;==>Main

Func Clean()
	If $sSource == "" Then Return

	_cveMatRelease($img)
	_cveMatRelease($templ)

	If $use_mask Then
		_cveMatRelease($mask)
	EndIf

	$sSource = ""
EndFunc   ;==>Clean

Func MatchingMethod()
	$match_method = $aMethods[_GUICtrlComboBox_GetCurSel($ComboMethod)]

	If $CV_TM_SQDIFF == $match_method Or $match_method == $CV_TM_CCORR_NORMED Then
		GUICtrlSetState($InputMask, $GUI_ENABLE)
		GUICtrlSetState($BtnMask, $GUI_ENABLE)
	Else
		GUICtrlSetState($InputMask, $GUI_DISABLE)
		GUICtrlSetState($BtnMask, $GUI_DISABLE)
	EndIf

	If $sSource == "" Then Return

	;;! [copy_source]
	;;/ Source image to display
	Local $img_display = _cveMatCreate()
	_cveMatCopyToMat($img, $img_display, _cveNoArrayMat())
	;;! [copy_source]

	;;! [create_result_matrix]
	;;/ Create the result matrix
	Local $cvSizeImg = _cvSize()
	_cveMatGetSize($img, $cvSizeImg)

	Local $cvSizeTempl = _cvSize()
	_cveMatGetSize($templ, $cvSizeTempl)

	Local $result_cols = $cvSizeImg.width - $cvSizeTempl.width + 1 ;
	Local $result_rows = $cvSizeImg.height - $cvSizeTempl.height + 1 ;

	Local $result = _cveMatCreate()
	_cveMatCreateData($result, $result_rows, $result_cols, $CV_32FC1)
	;;! [create_result_matrix]

	;;! [match_template]
	;;/ Do the Matching and Normalize
	Local $method_accepts_mask = $CV_TM_SQDIFF == $match_method Or $match_method == $CV_TM_CCORR_NORMED ;
	If $use_mask And $method_accepts_mask Then
		_cveMatchTemplateMat($img, $templ, $result, $match_method, $mask) ;
	Else
		_cveMatchTemplateMat($img, $templ, $result, $match_method) ;
	EndIf
	;;! [match_template]

	;;! [normalize]
	_cveNormalizeMat($result, $result, 0, 1, $CV_NORM_MINMAX, -1, _cveNoArrayMat())  ;
	;;! [normalize]

	;;! [best_match]
	;;/ Localizing the best match with minMaxLoc
	Local $minVal = DllStructCreate("double value;")
	Local $maxVal = DllStructCreate("double value;")
	Local $minLoc = DllStructCreate($tagCvPoint)
	Local $maxLoc = DllStructCreate($tagCvPoint)

	Local $matchLoc

	_cveMinMaxLocMat($result, $minVal, $maxVal, $minLoc, $maxLoc, _cveNoArrayMat())  ;
	;;! [best_match]

	;;! [match_loc]
	;;/ For SQDIFF and SQDIFF_NORMED, the best matches are lower values. For all the other methods, the higher the better
	If $match_method == $CV_TM_SQDIFF Or $match_method == $CV_TM_SQDIFF_NORMED Then
		$matchLoc = $minLoc
	Else
		$matchLoc = $maxLoc
	EndIf
	;;! [match_loc]

	;;! [imshow]
	;;/ Show me what you got
	Local $matchRect = _cvRect($matchLoc.x, $matchLoc.y, $cvSizeTempl.width, $cvSizeTempl.height)

	_cveRectangleMat($img_display, $matchRect, $tGreenColor, 2, 8, 0)  ;
	_cveRectangleMat($result, $matchRect, _cvScalarAll(0), 2, 8, 0)  ;

	; _cveImshowMat( $image_window, $img_display );
	; _cveImshowMat( $result_window, $result );

	_cveImshowControlPic($img_display, $FormGUI, $PicMatchTemplate, $tBackgroundColor)
	_cveImshowControlPic($result, $FormGUI, $PicResultImage, $tBackgroundColor)
	;;! [imshow]

	_cveMatRelease($result)
	_cveMatRelease($img_display)
EndFunc   ;==>MatchingMethod
