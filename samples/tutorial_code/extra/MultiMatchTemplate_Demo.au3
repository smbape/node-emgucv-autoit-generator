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
#include <Math.au3>
#include <StaticConstants.au3>
#include <WindowsConstants.au3>
#include "..\..\..\emgucv-autoit-bindings\cve_extra.au3"

;~ Sources:
;~     https://docs.opencv.org/4.5.3/d4/dc6/tutorial_py_template_matching.html

Local Const $OPENCV_SAMPLES_DATA_PATH = _PathFull(@ScriptDir & "\..\..\data")

#Region ### START Koda GUI section ### Form=
Local $FormGUI = GUICreate("Multi-template matching", 906, 607, 183, 120)

Local $InputSource = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\mario.png", 185, 16, 449, 21)
Local $BtnSource = GUICtrlCreateButton("Source", 644, 14, 75, 25)

Local $InputTemplate = GUICtrlCreateInput($OPENCV_SAMPLES_DATA_PATH & "\mario_coin.png", 185, 52, 449, 21)
Local $BtnTemplate = GUICtrlCreateButton("Template", 644, 50, 75, 25)

Local $InputMask = GUICtrlCreateInput("", 185, 88, 449, 21)
GUICtrlSetState(-1, $GUI_DISABLE)
Local $BtnMask = GUICtrlCreateButton("Mask", 644, 86, 75, 25)
GUICtrlSetState(-1, $GUI_DISABLE)

Local $LabelMethod = GUICtrlCreateLabel("Method:", 423, 128, 59, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $ComboMethod = GUICtrlCreateCombo("", 489, 128, 145, 25, BitOR($GUI_SS_DEFAULT_COMBO,$CBS_SIMPLE))
GUICtrlSetData(-1, "TM SQDIFF|TM SQDIFF NORMED|TM CCORR|TM CCORR NORMED|TM CCOEFF|TM CCOEFF NORMED")

Local $LabelThreshold = GUICtrlCreateLabel("Threshold: 0.8", 185, 180, 110, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $SliderThreshold = GUICtrlCreateSlider(300, 168, 334, 45)
GUICtrlSetData(-1, 80)

Local $BtnExec = GUICtrlCreateButton("Execute", 644, 126, 75, 25)

Local $LabelSource = GUICtrlCreateLabel("Source Image", 141, 224, 100, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupSource = GUICtrlCreateGroup("", 20, 246, 342, 342)
Local $PicSource = GUICtrlCreatePic("", 25, 257, 332, 326)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelTemplate = GUICtrlCreateLabel("Template", 420, 232, 70, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupTemplate = GUICtrlCreateGroup("", 376, 246, 158, 158)
Local $PicTemplate = GUICtrlCreatePic("", 381, 257, 148, 142)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelMask = GUICtrlCreateLabel("Mask", 435, 416, 41, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupMask = GUICtrlCreateGroup("", 375, 430, 158, 158)
Local $PicMask = GUICtrlCreatePic("", 380, 441, 148, 142)
GUICtrlCreateGroup("", -99, -99, 1, 1)

Local $LabelMatchTemplate = GUICtrlCreateLabel("Match Template", 668, 224, 115, 20)
GUICtrlSetFont(-1, 10, 800, 0, "MS Sans Serif")
Local $GroupMatchTemplate = GUICtrlCreateGroup("", 544, 246, 342, 342)
Local $PicMatchTemplate = GUICtrlCreatePic("", 549, 257, 332, 326)
GUICtrlCreateGroup("", -99, -99, 1, 1)

GUISetOnEvent($GUI_EVENT_CLOSE, "_cleanExit")
GUICtrlSetOnEvent($BtnSource, "_handleBtnSourceClick")
GUICtrlSetOnEvent($BtnTemplate, "_handleBtnTemplateClick")
GUICtrlSetOnEvent($Btnmask, "_handleBtnmaskClick")
GUICtrlSetOnEvent($BtnExec, "_handleBtnExecClick")
GUICtrlSetOnEvent($SliderThreshold, "MultiMatchTemplate")
GUICtrlSetOnEvent($ComboMethod, "MultiMatchTemplate")

GUISetState(@SW_SHOW)
#EndRegion ### END Koda GUI section ###

_GDIPlus_Startup()
_OpenCV_DLLOpen(@ScriptDir & "\..\..\..\libemgucv-windesktop-4.5.3.4721\libs\x64\cvextern.dll")

Local $tBlueColor = _cvScalar(255, 0, 0)
Local $tGreenColor = _cvScalar(0, 255, 0)
Local $tRedColor = _cvScalar(0, 0, 255)
Local $tBackgroundColor = _cvRGB(0xF0, 0xF0, 0xF0)

Local $sSource = "", $sTemplate = "", $sMask = ""
Local $img, $templ, $mask, $match_method, $threshold

Local $aMethods[6] = [$CV_TM_SQDIFF, $CV_TM_SQDIFF_NORMED, $CV_TM_CCORR, $CV_TM_CCORR_NORMED, $CV_TM_CCOEFF, $CV_TM_CCOEFF_NORMED]
_GUICtrlComboBox_SetCurSel($ComboMethod, 5)

Local $image_window = "Source Image";
Local $result_window = "Result window";
Local $use_mask = False
Local $tMatchRect = _cvRect(0, 0, 0, 0)

Main()

Local $current_threshold = GUICtrlRead($SliderThreshold)
Local $last_threshold = $current_threshold

While 1
    $current_threshold = GUICtrlRead($SliderThreshold)
    If $last_threshold <> $current_threshold Then
        MultiMatchTemplate()
        $last_threshold = $current_threshold
    EndIf
    Sleep(50) ; Sleep to reduce CPU usage
WEnd

_Opencv_DLLClose()
_GDIPlus_Shutdown()

Func _handleBtnSourceClick()
    $sSource = ControlGetText($FormGUI, "", $InputSource)
    $sSource = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sSource)
    If @error Then
        $sSource = ""
    Else
        ControlSetText($FormGUI, "", $InputSource, $sSource)
    EndIf
EndFunc

Func _handleBtnTemplateClick()
    $sTemplate = ControlGetText($FormGUI, "", $InputTemplate)
    $sTemplate = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sTemplate)
    If @error Then
        $sTemplate = ""
    Else
        ControlSetText($FormGUI, "", $InputTemplate, $sTemplate)
    EndIf
EndFunc

Func _handleBtnMaskClick()
    $sMask = ControlGetText($FormGUI, "", $InputMask)
    $sMask = FileOpenDialog("Select an image", $OPENCV_SAMPLES_DATA_PATH, "Image files (*.bmp;*.jpg;*.jpeg;*.png;*.gif)", $FD_FILEMUSTEXIST, $sMask)
    If @error Then
        $sMask = ""
    Else
        ControlSetText($FormGUI, "", $InputMask, $sMask)
    EndIf
EndFunc

Func _handleBtnExecClick()
    Clean()
    Main()
EndFunc

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

    ;;! [prepare_match_rect]
    Local $cvSize = _cvSize()
    _cveMatGetSize($templ, $cvSize)
    $tMatchRect.width = $cvSize.width
    $tMatchRect.height = $cvSize.height
    ;;! [prepare_match_rect]

    ;;! [Display]
    _cveImshowControlPic($img, $FormGUI, $PicSource, $tBackgroundColor)
    _cveImshowControlPic($templ, $FormGUI, $PicTemplate, $tBackgroundColor)

    If $use_mask Then
        _cveImshowControlPic($mask, $FormGUI, $PicMask, $tBackgroundColor)
    EndIf
    ;;! [Display]

    MultiMatchTemplate()
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

Func MultiMatchTemplate()
    $match_method = $aMethods[_GUICtrlComboBox_GetCurSel($ComboMethod)]

    If $CV_TM_SQDIFF == $match_method Or $match_method == $CV_TM_CCORR_NORMED Then
        GUICtrlSetState($InputMask, $GUI_ENABLE)
        GUICtrlSetState($BtnMask, $GUI_ENABLE)
    Else
        GUICtrlSetState($InputMask, $GUI_DISABLE)
        GUICtrlSetState($BtnMask, $GUI_DISABLE)
    EndIf

    $threshold = GUICtrlRead($SliderThreshold) / 100
    GUICtrlSetData($LabelThreshold, "Threshold: " & StringFormat("%.2f", $threshold))

    If $sSource == "" Then Return

    ;;! [copy_source]
    ;;/ Source image to display
    Local $img_display = _cveMatCreate()
    _cveMatCopyToMat($img, $img_display, _cveNoArrayMat())
    ;;! [copy_source]

    ;;! [match_template]
    Local $aMatches = _cveFindTemplate($img_display, $templ, $threshold, $match_method, $mask)
    Local $iMatches = UBound($aMatches)
    For $i = 0 To $iMatches - 1
        $tMatchRect.x = $aMatches[$i][0]
        $tMatchRect.y = $aMatches[$i][1]

        ; Draw a red rectangle around the matched position
        _cveRectangleMat($img_display, $tMatchRect, $tRedColor, 1, $CV_LINE_8, 0)
    Next
    ;;! [match_template]

    ;;! [imshow]
    _cveImshowControlPic($img_display, $FormGUI, $PicMatchTemplate, $tBackgroundColor)
    ;;! [imshow]

    _cveMatRelease($img_display)
EndFunc   ;==>MultiMatchTemplate

Func _cleanExit()
    If @GUI_WinHandle <> $FormGUI Then
        Return
    EndIf

    Clean()
    Exit
EndFunc   ;==>_cleanExit
