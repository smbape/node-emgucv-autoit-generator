#include-once
#include <Math.au3>
#include <WindowsConstants.au3>
#include <WinAPI.au3>
#include <StaticConstants.au3>
#include "cve_world.au3"

_cveRegisterOpenHook("_cveOnOpen")
_cveRegisterCloseHook("_cveOnClose")

Local $aBGRChannels[3] = [0, 1, 2]
Local $vectorDefaultBGRChannels = Null

Func _cveDefaultBGRChannels()
	Return $vectorDefaultBGRChannels
EndFunc   ;==>_cveDefaultBGRChannels

Local $aBGRHistSize[3] = [32, 32, 32]
Local $vectorDefaultBGRHistSize = Null

Func _cveDefaultBGRHistSize()
	Return $vectorDefaultBGRHistSize
EndFunc   ;==>_cveDefaultBGRHistSize

Local $aBGRRanges[6] = [0, 256, 0, 256, 0, 256]
Local $vectorDefaultBGRRanges = Null

Func _cveDefaultBGRRanges()
	Return $vectorDefaultBGRRanges
EndFunc   ;==>_cveDefaultBGRRanges

Local $aHsvChannels[2] = [0, 1]
Local $vectorDefaultHsvChannels = Null

Func _cveDefaultHsvChannels()
	Return $vectorDefaultHsvChannels
EndFunc   ;==>_cveDefaultHsvChannels

Local $aHsvHistSize[2] = [30, 32]
Local $vectorDefaultHsvHistSize = Null

Func _cveDefaultHsvHistSize()
	Return $vectorDefaultHsvHistSize
EndFunc   ;==>_cveDefaultHsvHistSize

Local $aHsvRanges[4] = [0, 180, 0, 256]
Local $vectorDefaultHsvRanges = Null

Func _cveDefaultHsvRanges()
	Return $vectorDefaultHsvRanges
EndFunc   ;==>_cveDefaultHsvRanges

Local $aGrayScaleChannels[1] = [0]
Local $vectorDefaultGrayScaleChannels = Null

Func _cveDefaultGrayScaleChannels()
	Return $vectorDefaultGrayScaleChannels
EndFunc   ;==>_cveDefaultGrayScaleChannels

Local $aGrayScaleHistSize[1] = [32]
Local $vectorDefaultGrayScaleHistSize = Null

Func _cveDefaultGrayScaleHistSize()
	Return $vectorDefaultGrayScaleHistSize
EndFunc   ;==>_cveDefaultGrayScaleHistSize

Local $aGrayScaleRanges[2] = [0, 256]
Local $vectorDefaultGrayScaleRanges = Null

Func _cveDefaultGrayScaleRanges()
	Return $vectorDefaultGrayScaleRanges
EndFunc   ;==>_cveDefaultGrayScaleRanges

Func _cveOnOpen()
	$vectorDefaultBGRChannels = _VectorOfIntCreate()
	For $i = 0 To UBound($aBGRChannels) - 1
		_VectorOfIntPush($vectorDefaultBGRChannels, $aBGRChannels[$i])
	Next

	$vectorDefaultBGRHistSize = _VectorOfIntCreate()
	For $i = 0 To UBound($aBGRHistSize) - 1
		_VectorOfIntPush($vectorDefaultBGRHistSize, $aBGRHistSize[$i])
	Next

	$vectorDefaultBGRRanges = _VectorOfFloatCreate()
	For $i = 0 To UBound($aBGRRanges) - 1
		_VectorOfFloatPush($vectorDefaultBGRRanges, $aBGRRanges[$i])
	Next

	$vectorDefaultHsvChannels = _VectorOfIntCreate()
	For $i = 0 To UBound($aHsvChannels) - 1
		_VectorOfIntPush($vectorDefaultHsvChannels, $aHsvChannels[$i])
	Next

	$vectorDefaultHsvHistSize = _VectorOfIntCreate()
	For $i = 0 To UBound($aHsvHistSize) - 1
		_VectorOfIntPush($vectorDefaultHsvHistSize, $aHsvHistSize[$i])
	Next

	$vectorDefaultHsvRanges = _VectorOfFloatCreate()
	For $i = 0 To UBound($aHsvRanges) - 1
		_VectorOfFloatPush($vectorDefaultHsvRanges, $aHsvRanges[$i])
	Next

	$vectorDefaultGrayScaleChannels = _VectorOfIntCreate()
	For $i = 0 To UBound($aGrayScaleChannels) - 1
		_VectorOfIntPush($vectorDefaultGrayScaleChannels, $aGrayScaleChannels[$i])
	Next

	$vectorDefaultGrayScaleHistSize = _VectorOfIntCreate()
	For $i = 0 To UBound($aGrayScaleHistSize) - 1
		_VectorOfIntPush($vectorDefaultGrayScaleHistSize, $aGrayScaleHistSize[$i])
	Next

	$vectorDefaultGrayScaleRanges = _VectorOfFloatCreate()
	For $i = 0 To UBound($aGrayScaleRanges) - 1
		_VectorOfFloatPush($vectorDefaultGrayScaleRanges, $aGrayScaleRanges[$i])
	Next
EndFunc   ;==>_cveOnOpen

Func _cveOnClose()
	_VectorOfIntRelease($vectorDefaultBGRChannels)
	$vectorDefaultBGRChannels = Null

	_VectorOfIntRelease($vectorDefaultBGRHistSize)
	$vectorDefaultBGRHistSize = Null

	_VectorOfFloatRelease($vectorDefaultBGRRanges)
	$vectorDefaultBGRRanges = Null

	_VectorOfIntRelease($vectorDefaultHsvChannels)
	$vectorDefaultHsvChannels = Null

	_VectorOfIntRelease($vectorDefaultHsvHistSize)
	$vectorDefaultHsvHistSize = Null

	_VectorOfFloatRelease($vectorDefaultHsvRanges)
	$vectorDefaultHsvRanges = Null

	_VectorOfIntRelease($vectorDefaultGrayScaleChannels)
	$vectorDefaultGrayScaleChannels = Null

	_VectorOfIntRelease($vectorDefaultGrayScaleHistSize)
	$vectorDefaultGrayScaleHistSize = Null

	_VectorOfFloatRelease($vectorDefaultGrayScaleRanges)
	$vectorDefaultGrayScaleRanges = Null
EndFunc   ;==>_cveOnClose

Func _cveMatGetWidth($mat)
	Local $cvSize = DllStructCreate($tagCvSize)
	_cveMatGetSize($mat, $cvSize)
	Local $width = $cvSize.width
	$cvSize = 0
	Return $width ;
EndFunc   ;==>_cveMatGetWidth

Func _cveMatGetHeight($mat)
	Local $cvSize = DllStructCreate($tagCvSize)
	_cveMatGetSize($mat, $cvSize)
	Local $height = $cvSize.height
	$cvSize = 0
	Return $height ;
EndFunc   ;==>_cveMatGetHeight

Func _cveMatGetAt($type, $mat, $tPoint)
	Local $i0 = $tPoint.y
	Local $i1 = $tPoint.x
	Local $ptrData = _cveMatGetDataPointer($mat)
	Local $step = _cveMatGetStep($mat)

	Local $tRow = DllStructCreate($type & "[" & $i1 + 1 & "]", $ptrData + $step * $i0)
	Local $value = DllStructGetData($tRow, 1, $i1 + 1)

	$tRow = 0
	Return $value
EndFunc   ;==>_cveMatGetAt

Func _cveMatSetAt($type, $mat, $tPoint, $value)
	Local $i0 = $tPoint.y
	Local $i1 = $tPoint.x
	Local $ptrData = _cveMatGetDataPointer($mat)
	Local $step = _cveMatGetStep($mat)

	Local $tRow = DllStructCreate($type & "[" & $i1 + 1 & "]", $ptrData + $step * $i0)
	DllStructSetData($tRow, 1, $value, $i1 + 1)

	$tRow = 0
EndFunc   ;==>_cveMatSetAt

Func _cveImreadAndCheck($fileName, $flags = $CV_IMREAD_UNCHANGED, $result = Null)
	Local $matImg = _cveImread($fileName, $flags, $result)
	Local $bIsEmpty = _cveInputArrayIsEmptyMat($matImg)

	If Not $bIsEmpty Then
		Return $matImg
	EndIf

	Local $tStr

	If VarGetType($fileName) <> "String" Then
		Local $tC_str = DllStructCreate("ptr value")
		Local $tSize = DllStructCreate("int value")
		_cveStringGetCStr($fileName, $tC_str, $tSize)
		Local $tStr = DllStructCreate("char value[" & $tSize.value & "]", $tC_str.value)
		$fileName = $tStr.value
	EndIf

	ConsoleWriteError("!>Error: The image " & $fileName & " could not be loaded." & @CRLF)
	$tStr = 0
	Return SetError(1, 0, $matImg)
EndFunc   ;==>_cveImreadAndCheck

Func _cveCompareMatHist($matSrc, $matDst, $matMask, $aChannels, $aHistSize, $aRanges, $iCompareMethod = $CV_HISTCMP_CORREL, $bAccumulate = False)
	Local $matEmpty = _cveNoArrayMat()

	Local $matHistSrc = _cveMatCreate()
	Local $aMatSrc[1] = [$matSrc]
	_cveCalcHistMat($aMatSrc, $aChannels, $matMask, $matHistSrc, $aHistSize, $aRanges, $bAccumulate)
	_cveNormalizeMat($matHistSrc, $matHistSrc, 0, 1, $CV_NORM_MINMAX, -1, $matEmpty)

	Local $matHistDst = _cveMatCreate()
	Local $aMatDst[1] = [$matDst]
	_cveCalcHistMat($aMatDst, $aChannels, $matMask, $matHistDst, $aHistSize, $aRanges, $bAccumulate)
	_cveNormalizeMat($matHistDst, $matHistDst, 0, 1, $CV_NORM_MINMAX, -1, $matEmpty)

	Local $dResult = _cveCompareHistMat($matHistSrc, $matHistDst, $iCompareMethod)

	_cveMatRelease($matHistDst)
	_cveMatRelease($matHistSrc)

	Return $dResult
EndFunc   ;==>_cveCompareMatHist

; #FUNCTION# ====================================================================================================================
; Name ..........: _cveFindTemplate
; Description ...: Find matches of a template in an image
; Syntax ........: _cveFindTemplate($matImg, $matTempl[, $fThreshold = 0.95[, $iCode = -1[, $iMatchMethod = $CV_TM_CCOEFF_NORMED[,
;                  $matTemplMask = _cveNoArrayMat()[, $fOverlapping = 2[, $aChannels = _cveDefaultBGRChannels()[,
;                  $aHistSize = _cveDefaultBGRHistSize()[, $aRanges = _cveDefaultBGRRanges()[, $iCompareMethod = $CV_HISTCMP_CORREL[,
;                  $iDstCn = 0[, $bAccumulate = False[, $iLimit = 100]]]]]]]]]]]])
; Parameters ....: $matImg              - image matrix.
;                  $matTempl            - template matrix.
;                  $fThreshold          - [optional] matching correlation should not be under this value. 1 means only keep perfect matches. Default is 0.95.
;                  $iMatchMethod        - [optional] parameter specifying the comparison method. Default is $CV_TM_CCOEFF_NORMED.
;                  $matTemplMask        - [optional] mask to use for matching. Default is _cveNoArrayMat().
;                  $iLimit              - [optional] an integer value. Default is 20.
;                  $iCode               - [optional] color space conversion code. Use -1 for no conversion. Default is -1.
;                  $fOverlapping        - [optional] koeffitient to control overlapping of matches.
;                                             $fOverlapping = 1     : two matches can overlap half-body of template
;                                             $fOverlapping = 2     : no overlapping,only border touching possible
;                                             $fOverlapping = > 2   : distancing matches
;                                             0 < $fOverlapping < 1 : matches can overlap more then half.
;                                             Default is 2.
;                  $aChannels           - [optional] an array of ints. List of the dims channels used to compute the histogram.. Default is _cveDefaultBGRChannels().
;                  $aHistSize           - [optional] an array of int. Array of histogram sizes in each dimension. Default is _cveDefaultBGRHistSize().
;                  $aRanges             - [optional] an array of float. Array of the dims arrays of the histogram bin boundaries in each dimension. Default is _cveDefaultBGRRanges().
;                  $iCompareMethod      - [optional] an integer value. Default is $CV_HISTCMP_CORREL.
;                  $iDstCn              - [optional] an integer value. Default is 0.
;                  $bAccumulate         - [optional] a boolean value. Default is False.
; Return values .: An array of matches [[x1, y1, s1], [x2, y2, s2], ..., [xn, yn, sn]]
; Author ........: Stéphane MBAPE
; Modified ......:
; Sources .......: https://stackoverflow.com/a/28647930
;                  https://docs.opencv.org/4.5.1/d8/ded/samples_2cpp_2tutorial_code_2Histograms_Matching_2MatchTemplate_Demo_8cpp-example.html#a16
;                  https://vovkos.github.io/doxyrest-showcase/opencv/sphinx_rtd_theme/page_tutorial_histogram_calculation.html
; ===============================================================================================================================
Func _cveFindTemplate($matImg, $matTempl, $fThreshold = 0.95, $iMatchMethod = $CV_TM_CCOEFF_NORMED, $matTemplMask = _cveNoArrayMat(), $iLimit = 20, $iCode = -1, $fOverlapping = 2, $aChannels = _cveDefaultBGRChannels(), $aHistSize = _cveDefaultBGRHistSize(), $aRanges = _cveDefaultBGRRanges(), $iCompareMethod = $CV_HISTCMP_CORREL, $iDstCn = 0, $bAccumulate = False)
	Local $matCvtImg = $matImg
	Local $matCvtTempl = $matTempl

	If $iCode >= 0 Then
		$matCvtImg = _cveMatCreate()
		_cveCvtColorMat($matImg, $matCvtImg, $iCode, $iDstCn)

		$matCvtTempl = _cveMatCreate()
		_cveCvtColorMat($matTempl, $matCvtTempl, $iCode, $iDstCn)
	EndIf

	Local $cvSize = DllStructCreate($tagCvSize)

	_cveMatGetSize($matCvtImg, $cvSize)
	Local $width = $cvSize.width
	Local $height = $cvSize.height

	_cveMatGetSize($matCvtTempl, $cvSize)
	Local $w = $cvSize.width
	Local $h = $cvSize.height

	$cvSize = 0

	Local $tMatchRect = _cvRect(0, 0, $w, $h)

	Local $rw = $width - $w + 1
	Local $rh = $height - $h + 1

	Local $matEmpty = _cveNoArrayMat()

	Local $matResult = _cveMatCreate()
	_cveMatCreateData($matResult, $rh, $rw, $CV_32FC1)

	; there are $rh rows and $rw cols in the result matrix
	; create a mask with the same number of rows and cols
	Local $matResultMask = _cveMatCreate()
	_cveMatOnes($rh, $rw, $CV_8UC1, $matResultMask)

	Local $bMethodAcceptsMask = $CV_TM_SQDIFF == $iMatchMethod Or $iMatchMethod == $CV_TM_CCORR_NORMED
	Local $bIsNormed = $iMatchMethod == $CV_TM_SQDIFF_NORMED Or $iMatchMethod == $CV_TM_CCORR_NORMED Or $iMatchMethod == $CV_TM_CCOEFF_NORMED

	Local $hTimer, $fDiff
	$hTimer = TimerInit()
	If $bMethodAcceptsMask Then
		_cveMatchTemplateMat($matCvtImg, $matCvtTempl, $matResult, $iMatchMethod, $matTemplMask)
	Else
		_cveMatchTemplateMat($matCvtImg, $matCvtTempl, $matResult, $iMatchMethod, $matEmpty)
	EndIf
	$fDiff = TimerDiff($hTimer)
	; ConsoleWrite("_cveMatchTemplateMat took " & $fDiff & "ms" & @CRLF)

	Local $tMinVal = DllStructCreate("double value;")
	Local $tMaxVal = DllStructCreate("double value;")
	Local $tMinLoc = DllStructCreate($tagCvPoint)
	Local $tMaxLoc = DllStructCreate($tagCvPoint)

	Local $tMatchLoc

	Local $fHistScore = 1
	Local $fScore = 0
	Local $fVisited
	Local $aResult[$iLimit][3]
	Local $iFound = 0

	; For SQDIFF and SQDIFF_NORMED, the best matches are lower values. For all the other methods, the higher the better
	If ($iMatchMethod == $CV_TM_SQDIFF Or $iMatchMethod == $CV_TM_SQDIFF_NORMED) Then
		$fVisited = 1.0
	Else
		$fVisited = 0.0
	EndIf

	If Not $bIsNormed Then
		_cveNormalizeMat($matResult, $matResult, 0, 1, $CV_NORM_MINMAX, -1, $matEmpty)
	EndIf

	$hTimer = TimerInit()
	While 1 ;use infinite loop since ExitLoop will get called
		If $iLimit == 0 Then
			ExitLoop
		EndIf

		$iLimit = $iLimit - 1

		_cveMinMaxLocMat($matResult, $tMinVal, $tMaxVal, $tMinLoc, $tMaxLoc, $matResultMask)

		; For SQDIFF and SQDIFF_NORMED, the best matches are lower values. For all the other methods, the higher the better
		If ($iMatchMethod == $CV_TM_SQDIFF Or $iMatchMethod == $CV_TM_SQDIFF_NORMED) Then
			$tMatchLoc = $tMinLoc
			$fScore = 1 - $tMinVal.value
		Else
			$tMatchLoc = $tMaxLoc
			$fScore = $tMaxVal.value
		EndIf

		If (Not $bIsNormed) And ($iFound == 0) Then
			$tMatchRect.x = $tMatchLoc.x
			$tMatchRect.y = $tMatchLoc.y

			Local $matCvtImgMatch = _cveMatCreateFromRect($matCvtImg, $tMatchRect)
			$fHistScore = _cveCompareMatHist($matCvtImgMatch, $matCvtTempl, $matTemplMask, $aChannels, $aHistSize, $aRanges, $iCompareMethod, $bAccumulate)
			_cveMatRelease($matCvtImgMatch)
			; ConsoleWrite("$fHistScore: " & $fHistScore & @CRLF)
		EndIf

		$fScore *= $fHistScore

		If $fScore < $fThreshold Then
			ExitLoop
		EndIf

		$aResult[$iFound][0] = $tMatchLoc.x
		$aResult[$iFound][1] = $tMatchLoc.y
		$aResult[$iFound][2] = $fScore
		$iFound = $iFound + 1

		; Mark as visited
		_cveMatSetAt("float", $matResult, $tMinLoc, $fVisited)
		_cveMatSetAt("float", $matResult, $tMaxLoc, $fVisited)

		Local $tw = Ceiling($fOverlapping * $w)
		Local $th = Ceiling($fOverlapping * $h)
		Local $x = _Max(0, $tMatchLoc.x - $tw / 2)
		Local $y = _Max(0, $tMatchLoc.y - $th / 2)

		; will template come beyond the mask?:if yes-cut off margin
		If $x + $tw > $rw Then $tw = $rw - $x
		If $y + $th > $rh Then $th = $rh - $y

		Local $tMaskedRect = _cvRect($x, $y, $tw, $th)

		Local $matMasked = _cveMatCreate()
		_cveMatZeros($th, $tw, $CV_8UC1, $matMasked)

		Local $matMaskedRect = _cveMatCreateFromRect($matResultMask, $tMaskedRect)

		; mask the locations that should not be matched again
		_cveMatCopyToMat($matMasked, $matMaskedRect, $matEmpty)

		_cveMatRelease($matMaskedRect)
		_cveMatRelease($matMasked)
		$tMaskedRect = 0
	WEnd
	$fDiff = TimerDiff($hTimer)
	; ConsoleWrite("_cveMinMaxLocMat took " & $fDiff & "ms" & @CRLF)

	$tMinVal = 0
	$tMaxVal = 0
	$tMinLoc = 0
	$tMaxLoc = 0
	$tMatchLoc = 0

	_cveMatRelease($matResultMask)
	_cveMatRelease($matResult)

	$tMatchRect = 0

	If $iCode >= 0 Then
		_cveMatRelease($matCvtTempl)
		_cveMatRelease($matCvtImg)
	EndIf

	ReDim $aResult[$iFound][3]

	Return $aResult
EndFunc   ;==>_cveFindTemplate

; #FUNCTION# ====================================================================================================================
; Name ..........: _cveGetDesktopScreenBits
; Description ...: Get the screen color bytes
; Syntax ........: _cveGetDesktopScreenBits(Byref $tRect)
; Parameters ....: $tRect               - [in] a $tagRect struct value.
; Return values .: a byte[] struct of ABRG colors of the screen. Can be used as data for an opencv matrix
; Author ........: Stéphane MBAPE
; Modified ......:
; ===============================================================================================================================
Func _cveGetDesktopScreenBits(ByRef $tRect)
	Local $iLeft = $tRect.left
	Local $iTop = $tRect.top
	Local $iWidth = $tRect.right - $tRect.left
	Local $iHeight = $tRect.bottom - $tRect.top
	Local $iChannels = 4
	Local $iSize = $iWidth * $iHeight * $iChannels

	Local $tBits = DllStructCreate('byte value[' & $iSize & ']')

	Local $hWnd = _WinAPI_GetDesktopWindow()
	Local $hDesktopDC = _WinAPI_GetDC($hWnd)
	Local $hMemoryDC = _WinAPI_CreateCompatibleDC($hDesktopDC) ;create compatible memory DC

	Local $tBIHDR = DllStructCreate($tagBITMAPINFO)
	$tBIHDR.biSize = DllStructGetSize($tBIHDR)
	$tBIHDR.biWidth = $iWidth
	$tBIHDR.biHeight = -$iHeight
	$tBIHDR.biPlanes = 1
	$tBIHDR.biBitCount = $iChannels * 8

	Local $aDIB = DllCall("gdi32.dll", "ptr", "CreateDIBSection", "hwnd", 0, "struct*", $tBIHDR, "uint", $DIB_RGB_COLORS, "ptr*", 0, "ptr", 0, "dword", 0)

	_WinAPI_SelectObject($hMemoryDC, $aDIB[0])
	_WinAPI_BitBlt($hMemoryDC, 0, 0, $iWidth, $iHeight, $hDesktopDC, $iLeft, $iTop, $SRCCOPY)

	; $aDIB[4] will be unallacoted when _WinAPI_DeleteObject will be called
	; to be able to preserve the values,
	; keep the value in our own allocated memory
	CVEDllCallResult(DllCall("msvcrt.dll", "ptr", "memcpy_s", "struct*", $tBits, "ulong_ptr", $iSize, "ptr", $aDIB[4], "ulong_ptr", $iSize), "memcpy_s", @error)

	_WinAPI_DeleteObject($aDIB[0])
	_WinAPI_DeleteDC($hMemoryDC)
	_WinAPI_ReleaseDC($hWnd, $hDesktopDC)

	$tBIHDR = 0

	Return $tBits
EndFunc   ;==>_cveGetDesktopScreenBits

; #FUNCTION# ====================================================================================================================
; Name ..........: _WinAPI_GetDesktopScreenRect
; Description ...: Get desktop screen rect, handling multi-screen desktop.
; Syntax ........: _WinAPI_GetDesktopScreenRect()
; Parameters ....: None
; Return values .: $tagRect struct value
; Author ........: Stéphane MBAPE
; Modified ......:
; ===============================================================================================================================
Func _WinAPI_GetDesktopScreenRect()
	Local $iRight, $iBottom, $aRetrun

	Local $tRect = DllStructCreate($tagRECT)
	$tRect.Left = 0
	$tRect.Top = 0
	$tRect.Right = -1
	$tRect.Bottom = -1

	Local Const $tagDISPLAY_DEVICE = "dword Size;wchar Name[32];wchar String[128];dword Flags;wchar ID[128];wchar Key[128]"
	Local $tDisplayDevice = DllStructCreate($tagDISPLAY_DEVICE)
	$tDisplayDevice.Size = DllStructGetSize($tDisplayDevice)

	Local $tDisplaySettings = DllStructCreate($tagDEVMODE_DISPLAY)
	$tDisplaySettings.Size = DllStructGetSize($tDisplaySettings)

	Local $iDevNum = 0
	While 1
		; _WinAPI_EnumDisplayDevices("", $iDevNum)
		$aRetrun = DllCall("user32.dll", "int", "EnumDisplayDevicesW", "ptr", 0, "dword", $iDevNum, "struct*", $tDisplayDevice, "dword", 1)
		If Not $aRetrun[0] Then ExitLoop
		$iDevNum += 1

		If BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_MIRRORING_DRIVER) Or Not BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) Then
			ContinueLoop
		EndIf

		If BitAND($_cve_debug, 1) Then
			ConsoleWrite($tDisplayDevice.Name & @TAB & "Attached to desktop: " & (BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_ATTACHED_TO_DESKTOP) <> 0) & @CRLF)
			ConsoleWrite($tDisplayDevice.Name & @TAB & "Primary: " & (BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_PRIMARY_DEVICE) <> 0) & @CRLF)
			ConsoleWrite($tDisplayDevice.Name & @TAB & "Mirroring driver: " & (BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_MIRRORING_DRIVER) <> 0) & @CRLF)
			ConsoleWrite($tDisplayDevice.Name & @TAB & "VGA compatible: " & (BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_VGA_COMPATIBLE) <> 0) & @CRLF)
			ConsoleWrite($tDisplayDevice.Name & @TAB & "Removable: " & (BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_REMOVABLE) <> 0) & @CRLF)
			ConsoleWrite($tDisplayDevice.Name & @TAB & "More display modes: " & (BitAND($tDisplayDevice.Flags, $DISPLAY_DEVICE_MODESPRUNED) <> 0) & @CRLF)
			ConsoleWrite(@CRLF)
		EndIf

		; _WinAPI_EnumDisplaySettings($tDisplayDevice.Name, $ENUM_CURRENT_SETTINGS)
		Local $sDevice = $tDisplayDevice.Name
		Local $sTypeOfDevice = 'wstr'
		If Not StringStripWS($sDevice, $STR_STRIPLEADING + $STR_STRIPTRAILING) Then
			$sTypeOfDevice = 'ptr'
			$sDevice = 0
		EndIf
		$aRetrun = DllCall("user32.dll", "bool", "EnumDisplaySettingsW", $sTypeOfDevice, $sDevice, "dword", $ENUM_CURRENT_SETTINGS, "struct*", $tDisplaySettings)
		If Not $aRetrun[0] Then ContinueLoop

		If $tRect.Left > $tDisplaySettings.X Then $tRect.Left = $tDisplaySettings.X
		If $tRect.Top > $tDisplaySettings.Y Then $tRect.Left = $tDisplaySettings.Y

		$iRight = $tDisplaySettings.X + $tDisplaySettings.PelsWidth
		If $tRect.Right < $iRight Then $tRect.Right = $iRight

		$iBottom = $tDisplaySettings.Y + $tDisplaySettings.PelsHeight
		If $tRect.Bottom < $iBottom Then $tRect.Bottom = $iBottom
	WEnd

	$tDisplaySettings = 0
	$tDisplayDevice = 0

	Return $tRect
EndFunc   ;==>_WinAPI_GetDesktopScreenRect

Func _cveMatResizeAndCenter($matImg, $iDstWidth, $iDstHeight, $tBackgroundColor, $iCode = -1, $bFit = True)
	Local $tDsize = _cvSize()

	_cveMatGetSize($matImg, $tDsize)
	Local $iWidth = $tDsize.width
	Local $iHeight = $tDsize.height

	Local $fRatio = $iWidth / $iHeight
	Local $iPadCols = 0
	Local $iPadRows = 0

	If $iWidth <= $iDstWidth And $iHeight <= $iDstHeight Then
		$bFit = False
		$iPadCols = Floor(($iDstHeight - $iHeight) / 2)
		$iPadRows = Floor(($iDstWidth - $iWidth) / 2)
	ElseIf $fRatio * $iDstHeight > $iDstWidth Then
		$iWidth = $iDstWidth
		$iHeight = Floor($iWidth / $fRatio)
		$iPadCols = Floor(($iDstHeight - $iHeight) / 2)
	Else
		$iHeight = $iDstHeight
		$iWidth = Floor($iHeight * $fRatio)
		$iPadRows = Floor(($iDstWidth - $iWidth) / 2)
	EndIf

	$tDsize.width = $iWidth
	$tDsize.height = $iHeight

	Local $matCvtImg
	If $iCode <> -1 Then
		$matCvtImg = _cveMatCreate()
		_cveCvtColorMat($matImg, $matCvtImg, $iCode)
	Else
		$matCvtImg = $matImg
	EndIf

	Local $matResized
	If $bFit Then
		$matResized = _cveMatCreate()
		_cveResizeMat($matCvtImg, $matResized, $tDsize)
	Else
		$matResized = $matCvtImg
	EndIf

	Local $matResult = _cveMatCreate()
	_cveMatCreateData($matResult, $iDstHeight, $iDstWidth, $CV_8UC4)
	_cveCopyMakeBorderMat($matResized, $matResult, $iPadCols, $iPadCols, $iPadRows, $iPadRows, $CV_BORDER_CONSTANT, $tBackgroundColor)

	If $matResized <> $matCvtImg Then
		_cveMatRelease($matResized)
	EndIf

	$tDsize = 0

	If $matCvtImg <> $matImg Then
		_cveMatRelease($matCvtImg)
	EndIf

	Return $matResult
EndFunc   ;==>_cveMatResizeAndCenter

Func _cveSetControlPic($controlID, $matImg)
	Local $tDsize = _cvSize()

	_cveMatGetSize($matImg, $tDsize)
	Local $iWidth = $tDsize.width
	Local $iHeight = $tDsize.height

	Local $iChannels = 4
	Local $iSize = $iWidth * $iHeight * $iChannels

	Local $tBIHDR = DllStructCreate($tagBITMAPINFO)
	$tBIHDR.biSize = DllStructGetSize($tBIHDR)
	$tBIHDR.biWidth = $iWidth
	$tBIHDR.biHeight = -$iHeight
	$tBIHDR.biPlanes = 1
	$tBIHDR.biBitCount = $iChannels * 8

	Local $aDIB = DllCall("gdi32.dll", "ptr", "CreateDIBSection", "hwnd", 0, "struct*", $tBIHDR, "uint", $DIB_RGB_COLORS, "ptr*", 0, "ptr", 0, "dword", 0)
	DllCall("msvcrt.dll", "ptr", "memcpy_s", "ptr", $aDIB[4], "ulong_ptr", $iSize, "ptr", _cveMatGetDataPointer($matImg), "ulong_ptr", $iSize)
	_WinAPI_DeleteObject(_SendMessage(GUICtrlGetHandle($controlID), $STM_SETIMAGE, 0, $aDIB[0]))

	$tDsize = 0
EndFunc   ;==>_cveSetControlPic

Func _cveImshowControlPic($matImg, $hWnd, $controlID, $tBackgroundColor, $iCode = -1, $bFit = True)
	Local $aPicPos = ControlGetPos($hWnd, "", $controlID)

	Local $tMatImg = Null
	Local $matTemp = Null

	If $iCode == -1 Then
		$tMatImg = DllStructCreate($tagCvMat, $matImg)

		Switch CV_MAT_TYPE($tMatImg.flags)
			Case $CV_8UC1
				$iCode = $CV_COLOR_GRAY2BGRA
			Case $CV_8UC3
				$iCode = $CV_COLOR_BGR2BGRA
			Case $CV_8UC4
				$iCode = -1
			Case $CV_32FC1
				; convert CV_32FC1 in range [0, 1] to CV_8UC1 in range [0, 255]
				$matTemp = _cveMatCreate()
				_cveMatConvertToMat($matImg, $matTemp, $CV_8UC1, 255.0, 0)
				$matImg = $matTemp

				; then display the CV_8UC1 image (.i.e gray) as a BGRA image
				$iCode = $CV_COLOR_GRAY2BGRA
			Case Else
				ConsoleWriteError("!>Error: The image type is not supported." & @CRLF)
				Return
		EndSwitch
	EndIf

	Local $matResized = _cveMatResizeAndCenter($matImg, $aPicPos[2], $aPicPos[3], $tBackgroundColor, $iCode, $bFit)
	_cveSetControlPic($controlID, $matResized)
	_cveMatRelease($matResized)

	If $matTemp <> Null Then
		_cveMatRelease($matTemp)
	EndIf
EndFunc   ;==>_cveImshowControlPic
