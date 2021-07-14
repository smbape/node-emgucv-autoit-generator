#include-once
#include <Math.au3>
#include "cve_world.au3"

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
		return $matImg
	EndIf

	If VarGetType($fileName) <> "String" Then
		Local $tC_str = DllStructCreate("ptr value")
		Local $tSize = DllStructCreate("int value")
		_cveStringGetCStr($fileName, $tC_str, $tSize)
		Local $tStr = DllStructCreate("char value[" & $tSize.value & "]", $tC_str.value)
		$fileName = $tStr.value
		$tStr = 0
	EndIf

	ConsoleWriteError("!> The image " & $fileName & " could not be loaded." & @CRLF)
	return SetError(1, 0, $matImg)
EndFunc

Func _cveCompareMatHist($matSrc, $matDst, $matMask, $aChannels, $aHistSize, $aRanges, $iCompareMethod = $CV_HISTCMP_CORREL, $bAccumulate = False)
	Local $matEmpty = _cveMatCreate()

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
	_cveMatRelease($matEmpty)

	Return $dResult
EndFunc   ;==>_cveCompareMatHist

Func _cveFindTemplate($matImg, $matTempl, ByRef $aChannels, ByRef $aHistSize, ByRef $aRanges, $fThreshold = 0.95, $matTemplMask = Null, $iMatchMethod = $CV_TM_CCOEFF_NORMED, $iCompareMethod = $CV_HISTCMP_CORREL, $iCode = -1, $iDstCn = 0, $bAccumulate = False, $fOverlapping = 2, $iLimit = 100)
	Local $bIsNullMask = $matTemplMask == Null

	If $bIsNullMask Then
		$matTemplMask = _cveMatCreate()
	EndIf

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

	Local $matEmpty = _cveMatCreate()

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
	Local $aResult[$iLimit][2]
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

		If $fScore * $fHistScore < $fThreshold Then
			ExitLoop
		EndIf

		$aResult[$iFound][0] = $tMatchLoc.x
		$aResult[$iFound][1] = $tMatchLoc.y
		$iFound = $iFound + 1

		; Mark as visited
		_cveMatSetAt("float", $matResult, $tMinLoc, $fVisited)
		_cveMatSetAt("float", $matResult, $tMaxLoc, $fVisited)

		; koeffitient to control neiboring:
		; k_overlapping=1.- two neiboring selections can overlap half-body of     template
		; k_overlapping=2.- no overlapping,only border touching possible
		; k_overlapping>2.- distancing
		; 0.< k_overlapping <1.-  selections can overlap more then half
		; Local $fOverlapping = 2

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
	_cveMatRelease($matEmpty)

	$tMatchRect = 0

	If $iCode >= 0 Then
		_cveMatRelease($matCvtTempl)
		_cveMatRelease($matCvtImg)
	EndIf

	If $bIsNullMask Then
		_cveMatRelease($matTemplMask)
	EndIf

	ReDim $aResult[$iFound][2]

	Return $aResult
EndFunc   ;==>_cveFindTemplate
