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
;~     https://github.com/opencv/opencv/blob/master/samples/cpp/tutorial_code/Histograms_Matching/MatchTemplate_Demo.cpp

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Template Matching", 1267, 556, 185, 122)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\lena_tmpl.jpg", 366, 16, 449, 21)
Local $BtnSource = GUICtrlCreateButton("Source", 825, 14, 75, 25)

Local $InputTemplate = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\tmpl.png", 366, 52, 449, 21)
Local $BtnTemplate = GUICtrlCreateButton("Template", 825, 50, 75, 25)

Local $InputMask = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\mask.png", 366, 88, 449, 21)
Local $BtnMask = GUICtrlCreateButton("Mask", 825, 86, 75, 25)

Local $CheckboxGrayScale = GUICtrlCreateCheckbox("Gray scale", 152, 64, 97, 17)
GUICtrlSetState(-1, $GUI_CHECKED)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")

Local $CheckboxCanny = GUICtrlCreateCheckbox("Canny", 152, 96, 97, 17)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")

Local $LabelThreshold = GUICtrlCreateLabel("Threshold: 0.6", 153, 128, 110, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderThreshold = GUICtrlCreateSlider(260, 128, 334, 45)
GUICtrlSetData(-1, 60)

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
_OpenCV_DLLOpen(@ScriptDir & "\..\..\..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $tBlueColor = _cvScalar(255, 0, 0)
Local $tGreenColor = _cvScalar(0, 255, 0)
Local $tRedColor = _cvScalar(0, 0, 255)
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sSource = "", $sTemplate = "", $sMask = ""
Local $img, $img_gray, $img_size, $templ, $templ_gray, $templ_size, $mask, $match_method, $scale_direction, $min_scale, $max_scale, $threshold
Local $nMsg

Local $aMethods[6] = [$CV_TM_SQDIFF, $CV_TM_SQDIFF_NORMED, $CV_TM_CCORR, $CV_TM_CCORR_NORMED, $CV_TM_CCOEFF, $CV_TM_CCOEFF_NORMED]
_GUICtrlComboBox_SetCurSel($ComboMethod, 3)

Local $image_window = "Source Image" ;
Local $result_window = "Result window" ;
Local $use_mask = False

Main()

Local $current_threshold = GUICtrlRead($SliderThreshold)
Local $last_threshold = $current_threshold

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
		Case $CheckboxGrayScale
			Clean()
			Main()
		Case $CheckboxCanny
			Clean()
			Main()
		Case $ComboMethod
			MatchingMethod()
		Case $SliderThreshold
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

	$img_size = _cvSize()
	_cveMatGetSize($img, $img_size)

	$templ_size = _cvSize()
	_cveMatGetSize($templ, $templ_size)

	; convert to gray to speed up computation
	If _IsChecked($CheckboxGrayScale) Then
		$img_gray = _cveMatCreate()
		_cveCvtColorMat($img, $img_gray, $CV_COLOR_BGR2GRAY)

		$templ_gray = _cveMatCreate()
		_cveCvtColorMat($templ, $templ_gray, $CV_COLOR_BGR2GRAY)
	Else
		$img_gray = $img
		$templ_gray = $templ
	EndIf

	; finds edges in the input image and marks them in the output map edges using the Canny algorithm
	; also a tip to speed up computation
	If _IsChecked($CheckboxGrayScale) And _IsChecked($CheckboxCanny) Then
		_cveCannyMat($templ_gray, $templ_gray, 50, 200)
	EndIf

	If $img_size.width >= $templ_size.width And $img_size.height >= $templ_size.height Then
		$scale_direction = 1
		$min_scale = 1
	Else
		$scale_direction = -1
		$min_scale = Round(_Max($templ_size.width / $img_size.width, $templ_size.height / $img_size.height))
	EndIf

	$max_scale = 2.5 * $min_scale

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
	Local $method_accepts_mask = $CV_TM_SQDIFF == $match_method Or $match_method == $CV_TM_CCORR_NORMED ;

	If $method_accepts_mask Then
		GUICtrlSetState($InputMask, $GUI_ENABLE)
		GUICtrlSetState($BtnMask, $GUI_ENABLE)
	Else
		GUICtrlSetState($InputMask, $GUI_DISABLE)
		GUICtrlSetState($BtnMask, $GUI_DISABLE)
	EndIf

	If _IsChecked($CheckboxGrayScale) Then
		GUICtrlSetState($CheckboxCanny, $GUI_ENABLE)
	Else
		GUICtrlSetState($CheckboxCanny, $GUI_DISABLE)
	EndIf

	$threshold = GUICtrlRead($SliderThreshold) / 100
	GUICtrlSetData($LabelThreshold, "Threshold: " & StringFormat("%.2f", $threshold))

	If $sSource == "" Then Return

	Local $tDsize = _cvSize()
	Local $tMatchRect = _cvRect(0, 0, $templ_size.width, $templ_size.height)
	Local $scale, $img_resized, $aMatches
	Local $fBestScore = 0
	Local $tBestMatchRect = _cvRect()

	For $i = $min_scale To $max_scale Step 0.25
		$scale = $i ^ $scale_direction

		$tDsize.width = $img_size.width / $scale
		$tDsize.height = $img_size.height / $scale
		If ($tDsize.width < $templ_size.width) Or ($tDsize.height < $templ_size.height) Then
			ExitLoop
		EndIf

		; Resize the image and draw edges
		$img_resized = _cveMatCreate()
		_cveResizeMat($img_gray, $img_resized, $tDsize)

		If _IsChecked($CheckboxGrayScale) And _IsChecked($CheckboxCanny) Then
			_cveCannyMat($img_resized, $img_resized, 50, 200)
		EndIf

		_cveMatGetSize($img_resized, $tDsize)

		;;! [match_template]
		Local $rw = $tDsize.width - $templ_size.width + 1 ;
		Local $rh = $tDsize.height - $templ_size.height + 1 ;
		Local $mat_result = _cveMatCreate()
		_cveMatCreateData($mat_result, $rh, $rw, $CV_32FC1)

		$aMatches = _cveFindTemplate($img_resized, $templ_gray, $threshold, $match_method, $mask, 1)
		Local $iMatches = UBound($aMatches)
		For $m = 0 To $iMatches - 1 Step 1
			$tMatchRect.x = $aMatches[$m][0]
			$tMatchRect.y = $aMatches[$m][1]

			If $fBestScore < $aMatches[$m][2] Then
				$fBestScore = $aMatches[$m][2]
				$tBestMatchRect.x = $aMatches[$m][0] * $scale
				$tBestMatchRect.y = $aMatches[$m][1] * $scale
				$tBestMatchRect.width = $tMatchRect.width * $scale
				$tBestMatchRect.height = $tMatchRect.height * $scale
			EndIf

			; Draw a red rectangle around the matched position
			_cveRectangleMat($img_resized, $tMatchRect, $tGreenColor, 2, $CV_LINE_8, 0)
		Next
		;;! [match_template]

		;;! [imshow]
		_cveImshowControlPic($img_resized, $FormGUI, $PicMatchTemplate, $tBackgroundColor)
		;;! [imshow]

		_cveMatRelease($img_resized)
		Sleep(100)
	Next

	;;! [imshow]
	; Draw a red rectangle around the matched position
	Local $img_display = _cveMatCreate()
	_cveMatCopyToMat($img, $img_display, _cveNoArrayMat())
	_cveRectangleMat($img_display, $tBestMatchRect, $tGreenColor, 2, $CV_LINE_8, 0)
	_cveImshowControlPic($img_display, $FormGUI, $PicResultImage, $tBackgroundColor)
	_cveMatRelease($img_display)
	;;! [imshow]
EndFunc   ;==>MatchingMethod

Func _IsChecked($idControlID)
	Return BitAND(GUICtrlRead($idControlID), $GUI_CHECKED) = $GUI_CHECKED
EndFunc   ;==>_IsChecked
