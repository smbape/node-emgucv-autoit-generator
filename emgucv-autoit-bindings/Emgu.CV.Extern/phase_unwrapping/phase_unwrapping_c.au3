#include-once
#include "..\..\CVEUtils.au3"

Func _cveHistogramPhaseUnwrappingCreate($width, $height, $histThresh, $nbrOfSmallBins, $nbrOfLargeBins, ByRef $sharedPtr)
    ; CVAPI(cv::phase_unwrapping::HistogramPhaseUnwrapping*) cveHistogramPhaseUnwrappingCreate(int width, int height, float histThresh, int nbrOfSmallBins, int nbrOfLargeBins, cv::Ptr<cv::phase_unwrapping::HistogramPhaseUnwrapping>** sharedPtr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHistogramPhaseUnwrappingCreate", "int", $width, "int", $height, "float", $histThresh, "int", $nbrOfSmallBins, "int", $nbrOfLargeBins, "ptr*", $sharedPtr), "cveHistogramPhaseUnwrappingCreate", @error)
EndFunc   ;==>_cveHistogramPhaseUnwrappingCreate

Func _cveHistogramPhaseUnwrappingRelease(ByRef $phase_unwrapping, ByRef $sharedPtr)
    ; CVAPI(void) cveHistogramPhaseUnwrappingRelease(cv::phase_unwrapping::HistogramPhaseUnwrapping** phase_unwrapping, cv::Ptr<cv::phase_unwrapping::HistogramPhaseUnwrapping>** sharedPtr);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramPhaseUnwrappingRelease", "ptr*", $phase_unwrapping, "ptr*", $sharedPtr), "cveHistogramPhaseUnwrappingRelease", @error)
EndFunc   ;==>_cveHistogramPhaseUnwrappingRelease

Func _cveHistogramPhaseUnwrappingGetInverseReliabilityMap(ByRef $phase_unwrapping, ByRef $reliabilityMap)
    ; CVAPI(void) cveHistogramPhaseUnwrappingGetInverseReliabilityMap(cv::phase_unwrapping::HistogramPhaseUnwrapping* phase_unwrapping, cv::_OutputArray* reliabilityMap);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramPhaseUnwrappingGetInverseReliabilityMap", "ptr", $phase_unwrapping, "ptr", $reliabilityMap), "cveHistogramPhaseUnwrappingGetInverseReliabilityMap", @error)
EndFunc   ;==>_cveHistogramPhaseUnwrappingGetInverseReliabilityMap

Func _cveHistogramPhaseUnwrappingGetInverseReliabilityMapMat(ByRef $phase_unwrapping, ByRef $matReliabilityMap)
    ; cveHistogramPhaseUnwrappingGetInverseReliabilityMap using cv::Mat instead of _*Array

    Local $oArrReliabilityMap, $vectorOfMatReliabilityMap, $iArrReliabilityMapSize
    Local $bReliabilityMapIsArray = VarGetType($matReliabilityMap) == "Array"

    If $bReliabilityMapIsArray Then
        $vectorOfMatReliabilityMap = _VectorOfMatCreate()

        $iArrReliabilityMapSize = UBound($matReliabilityMap)
        For $i = 0 To $iArrReliabilityMapSize - 1
            _VectorOfMatPush($vectorOfMatReliabilityMap, $matReliabilityMap[$i])
        Next

        $oArrReliabilityMap = _cveOutputArrayFromVectorOfMat($vectorOfMatReliabilityMap)
    Else
        $oArrReliabilityMap = _cveOutputArrayFromMat($matReliabilityMap)
    EndIf

    _cveHistogramPhaseUnwrappingGetInverseReliabilityMap($phase_unwrapping, $oArrReliabilityMap)

    If $bReliabilityMapIsArray Then
        _VectorOfMatRelease($vectorOfMatReliabilityMap)
    EndIf

    _cveOutputArrayRelease($oArrReliabilityMap)
EndFunc   ;==>_cveHistogramPhaseUnwrappingGetInverseReliabilityMapMat

Func _cveHistogramPhaseMapUnwrappingUnwrapPhaseMap(ByRef $phase_unwrapping, ByRef $wrappedPhaseMap, ByRef $unwrappedPhaseMap, ByRef $shadowMask)
    ; CVAPI(void) cveHistogramPhaseMapUnwrappingUnwrapPhaseMap(cv::phase_unwrapping::HistogramPhaseUnwrapping* phase_unwrapping, cv::_InputArray* wrappedPhaseMap, cv::_OutputArray* unwrappedPhaseMap, cv::_InputArray* shadowMask);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramPhaseMapUnwrappingUnwrapPhaseMap", "ptr", $phase_unwrapping, "ptr", $wrappedPhaseMap, "ptr", $unwrappedPhaseMap, "ptr", $shadowMask), "cveHistogramPhaseMapUnwrappingUnwrapPhaseMap", @error)
EndFunc   ;==>_cveHistogramPhaseMapUnwrappingUnwrapPhaseMap

Func _cveHistogramPhaseMapUnwrappingUnwrapPhaseMapMat(ByRef $phase_unwrapping, ByRef $matWrappedPhaseMap, ByRef $matUnwrappedPhaseMap, ByRef $matShadowMask)
    ; cveHistogramPhaseMapUnwrappingUnwrapPhaseMap using cv::Mat instead of _*Array

    Local $iArrWrappedPhaseMap, $vectorOfMatWrappedPhaseMap, $iArrWrappedPhaseMapSize
    Local $bWrappedPhaseMapIsArray = VarGetType($matWrappedPhaseMap) == "Array"

    If $bWrappedPhaseMapIsArray Then
        $vectorOfMatWrappedPhaseMap = _VectorOfMatCreate()

        $iArrWrappedPhaseMapSize = UBound($matWrappedPhaseMap)
        For $i = 0 To $iArrWrappedPhaseMapSize - 1
            _VectorOfMatPush($vectorOfMatWrappedPhaseMap, $matWrappedPhaseMap[$i])
        Next

        $iArrWrappedPhaseMap = _cveInputArrayFromVectorOfMat($vectorOfMatWrappedPhaseMap)
    Else
        $iArrWrappedPhaseMap = _cveInputArrayFromMat($matWrappedPhaseMap)
    EndIf

    Local $oArrUnwrappedPhaseMap, $vectorOfMatUnwrappedPhaseMap, $iArrUnwrappedPhaseMapSize
    Local $bUnwrappedPhaseMapIsArray = VarGetType($matUnwrappedPhaseMap) == "Array"

    If $bUnwrappedPhaseMapIsArray Then
        $vectorOfMatUnwrappedPhaseMap = _VectorOfMatCreate()

        $iArrUnwrappedPhaseMapSize = UBound($matUnwrappedPhaseMap)
        For $i = 0 To $iArrUnwrappedPhaseMapSize - 1
            _VectorOfMatPush($vectorOfMatUnwrappedPhaseMap, $matUnwrappedPhaseMap[$i])
        Next

        $oArrUnwrappedPhaseMap = _cveOutputArrayFromVectorOfMat($vectorOfMatUnwrappedPhaseMap)
    Else
        $oArrUnwrappedPhaseMap = _cveOutputArrayFromMat($matUnwrappedPhaseMap)
    EndIf

    Local $iArrShadowMask, $vectorOfMatShadowMask, $iArrShadowMaskSize
    Local $bShadowMaskIsArray = VarGetType($matShadowMask) == "Array"

    If $bShadowMaskIsArray Then
        $vectorOfMatShadowMask = _VectorOfMatCreate()

        $iArrShadowMaskSize = UBound($matShadowMask)
        For $i = 0 To $iArrShadowMaskSize - 1
            _VectorOfMatPush($vectorOfMatShadowMask, $matShadowMask[$i])
        Next

        $iArrShadowMask = _cveInputArrayFromVectorOfMat($vectorOfMatShadowMask)
    Else
        $iArrShadowMask = _cveInputArrayFromMat($matShadowMask)
    EndIf

    _cveHistogramPhaseMapUnwrappingUnwrapPhaseMap($phase_unwrapping, $iArrWrappedPhaseMap, $oArrUnwrappedPhaseMap, $iArrShadowMask)

    If $bShadowMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatShadowMask)
    EndIf

    _cveInputArrayRelease($iArrShadowMask)

    If $bUnwrappedPhaseMapIsArray Then
        _VectorOfMatRelease($vectorOfMatUnwrappedPhaseMap)
    EndIf

    _cveOutputArrayRelease($oArrUnwrappedPhaseMap)

    If $bWrappedPhaseMapIsArray Then
        _VectorOfMatRelease($vectorOfMatWrappedPhaseMap)
    EndIf

    _cveInputArrayRelease($iArrWrappedPhaseMap)
EndFunc   ;==>_cveHistogramPhaseMapUnwrappingUnwrapPhaseMapMat