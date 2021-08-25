#include-once
#include "..\..\CVEUtils.au3"

Func _cveHistogramPhaseUnwrappingCreate($width, $height, $histThresh, $nbrOfSmallBins, $nbrOfLargeBins, $sharedPtr)
    ; CVAPI(cv::phase_unwrapping::HistogramPhaseUnwrapping*) cveHistogramPhaseUnwrappingCreate(int width, int height, float histThresh, int nbrOfSmallBins, int nbrOfLargeBins, cv::Ptr<cv::phase_unwrapping::HistogramPhaseUnwrapping>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHistogramPhaseUnwrappingCreate", "int", $width, "int", $height, "float", $histThresh, "int", $nbrOfSmallBins, "int", $nbrOfLargeBins, $sSharedPtrDllType, $sharedPtr), "cveHistogramPhaseUnwrappingCreate", @error)
EndFunc   ;==>_cveHistogramPhaseUnwrappingCreate

Func _cveHistogramPhaseUnwrappingRelease($phase_unwrapping, $sharedPtr)
    ; CVAPI(void) cveHistogramPhaseUnwrappingRelease(cv::phase_unwrapping::HistogramPhaseUnwrapping** phase_unwrapping, cv::Ptr<cv::phase_unwrapping::HistogramPhaseUnwrapping>** sharedPtr);

    Local $sPhase_unwrappingDllType
    If IsDllStruct($phase_unwrapping) Then
        $sPhase_unwrappingDllType = "struct*"
    ElseIf $phase_unwrapping == Null Then
        $sPhase_unwrappingDllType = "ptr"
    Else
        $sPhase_unwrappingDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramPhaseUnwrappingRelease", $sPhase_unwrappingDllType, $phase_unwrapping, $sSharedPtrDllType, $sharedPtr), "cveHistogramPhaseUnwrappingRelease", @error)
EndFunc   ;==>_cveHistogramPhaseUnwrappingRelease

Func _cveHistogramPhaseUnwrappingGetInverseReliabilityMap($phase_unwrapping, $reliabilityMap)
    ; CVAPI(void) cveHistogramPhaseUnwrappingGetInverseReliabilityMap(cv::phase_unwrapping::HistogramPhaseUnwrapping* phase_unwrapping, cv::_OutputArray* reliabilityMap);

    Local $sPhase_unwrappingDllType
    If IsDllStruct($phase_unwrapping) Then
        $sPhase_unwrappingDllType = "struct*"
    Else
        $sPhase_unwrappingDllType = "ptr"
    EndIf

    Local $sReliabilityMapDllType
    If IsDllStruct($reliabilityMap) Then
        $sReliabilityMapDllType = "struct*"
    Else
        $sReliabilityMapDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramPhaseUnwrappingGetInverseReliabilityMap", $sPhase_unwrappingDllType, $phase_unwrapping, $sReliabilityMapDllType, $reliabilityMap), "cveHistogramPhaseUnwrappingGetInverseReliabilityMap", @error)
EndFunc   ;==>_cveHistogramPhaseUnwrappingGetInverseReliabilityMap

Func _cveHistogramPhaseUnwrappingGetInverseReliabilityMapTyped($phase_unwrapping, $typeOfReliabilityMap, $reliabilityMap)

    Local $oArrReliabilityMap, $vectorReliabilityMap, $iArrReliabilityMapSize
    Local $bReliabilityMapIsArray = IsArray($reliabilityMap)
    Local $bReliabilityMapCreate = IsDllStruct($reliabilityMap) And $typeOfReliabilityMap == "Scalar"

    If $typeOfReliabilityMap == Default Then
        $oArrReliabilityMap = $reliabilityMap
    ElseIf $bReliabilityMapIsArray Then
        $vectorReliabilityMap = Call("_VectorOf" & $typeOfReliabilityMap & "Create")

        $iArrReliabilityMapSize = UBound($reliabilityMap)
        For $i = 0 To $iArrReliabilityMapSize - 1
            Call("_VectorOf" & $typeOfReliabilityMap & "Push", $vectorReliabilityMap, $reliabilityMap[$i])
        Next

        $oArrReliabilityMap = Call("_cveOutputArrayFromVectorOf" & $typeOfReliabilityMap, $vectorReliabilityMap)
    Else
        If $bReliabilityMapCreate Then
            $reliabilityMap = Call("_cve" & $typeOfReliabilityMap & "Create", $reliabilityMap)
        EndIf
        $oArrReliabilityMap = Call("_cveOutputArrayFrom" & $typeOfReliabilityMap, $reliabilityMap)
    EndIf

    _cveHistogramPhaseUnwrappingGetInverseReliabilityMap($phase_unwrapping, $oArrReliabilityMap)

    If $bReliabilityMapIsArray Then
        Call("_VectorOf" & $typeOfReliabilityMap & "Release", $vectorReliabilityMap)
    EndIf

    If $typeOfReliabilityMap <> Default Then
        _cveOutputArrayRelease($oArrReliabilityMap)
        If $bReliabilityMapCreate Then
            Call("_cve" & $typeOfReliabilityMap & "Release", $reliabilityMap)
        EndIf
    EndIf
EndFunc   ;==>_cveHistogramPhaseUnwrappingGetInverseReliabilityMapTyped

Func _cveHistogramPhaseUnwrappingGetInverseReliabilityMapMat($phase_unwrapping, $reliabilityMap)
    ; cveHistogramPhaseUnwrappingGetInverseReliabilityMap using cv::Mat instead of _*Array
    _cveHistogramPhaseUnwrappingGetInverseReliabilityMapTyped($phase_unwrapping, "Mat", $reliabilityMap)
EndFunc   ;==>_cveHistogramPhaseUnwrappingGetInverseReliabilityMapMat

Func _cveHistogramPhaseMapUnwrappingUnwrapPhaseMap($phase_unwrapping, $wrappedPhaseMap, $unwrappedPhaseMap, $shadowMask)
    ; CVAPI(void) cveHistogramPhaseMapUnwrappingUnwrapPhaseMap(cv::phase_unwrapping::HistogramPhaseUnwrapping* phase_unwrapping, cv::_InputArray* wrappedPhaseMap, cv::_OutputArray* unwrappedPhaseMap, cv::_InputArray* shadowMask);

    Local $sPhase_unwrappingDllType
    If IsDllStruct($phase_unwrapping) Then
        $sPhase_unwrappingDllType = "struct*"
    Else
        $sPhase_unwrappingDllType = "ptr"
    EndIf

    Local $sWrappedPhaseMapDllType
    If IsDllStruct($wrappedPhaseMap) Then
        $sWrappedPhaseMapDllType = "struct*"
    Else
        $sWrappedPhaseMapDllType = "ptr"
    EndIf

    Local $sUnwrappedPhaseMapDllType
    If IsDllStruct($unwrappedPhaseMap) Then
        $sUnwrappedPhaseMapDllType = "struct*"
    Else
        $sUnwrappedPhaseMapDllType = "ptr"
    EndIf

    Local $sShadowMaskDllType
    If IsDllStruct($shadowMask) Then
        $sShadowMaskDllType = "struct*"
    Else
        $sShadowMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHistogramPhaseMapUnwrappingUnwrapPhaseMap", $sPhase_unwrappingDllType, $phase_unwrapping, $sWrappedPhaseMapDllType, $wrappedPhaseMap, $sUnwrappedPhaseMapDllType, $unwrappedPhaseMap, $sShadowMaskDllType, $shadowMask), "cveHistogramPhaseMapUnwrappingUnwrapPhaseMap", @error)
EndFunc   ;==>_cveHistogramPhaseMapUnwrappingUnwrapPhaseMap

Func _cveHistogramPhaseMapUnwrappingUnwrapPhaseMapTyped($phase_unwrapping, $typeOfWrappedPhaseMap, $wrappedPhaseMap, $typeOfUnwrappedPhaseMap, $unwrappedPhaseMap, $typeOfShadowMask, $shadowMask)

    Local $iArrWrappedPhaseMap, $vectorWrappedPhaseMap, $iArrWrappedPhaseMapSize
    Local $bWrappedPhaseMapIsArray = IsArray($wrappedPhaseMap)
    Local $bWrappedPhaseMapCreate = IsDllStruct($wrappedPhaseMap) And $typeOfWrappedPhaseMap == "Scalar"

    If $typeOfWrappedPhaseMap == Default Then
        $iArrWrappedPhaseMap = $wrappedPhaseMap
    ElseIf $bWrappedPhaseMapIsArray Then
        $vectorWrappedPhaseMap = Call("_VectorOf" & $typeOfWrappedPhaseMap & "Create")

        $iArrWrappedPhaseMapSize = UBound($wrappedPhaseMap)
        For $i = 0 To $iArrWrappedPhaseMapSize - 1
            Call("_VectorOf" & $typeOfWrappedPhaseMap & "Push", $vectorWrappedPhaseMap, $wrappedPhaseMap[$i])
        Next

        $iArrWrappedPhaseMap = Call("_cveInputArrayFromVectorOf" & $typeOfWrappedPhaseMap, $vectorWrappedPhaseMap)
    Else
        If $bWrappedPhaseMapCreate Then
            $wrappedPhaseMap = Call("_cve" & $typeOfWrappedPhaseMap & "Create", $wrappedPhaseMap)
        EndIf
        $iArrWrappedPhaseMap = Call("_cveInputArrayFrom" & $typeOfWrappedPhaseMap, $wrappedPhaseMap)
    EndIf

    Local $oArrUnwrappedPhaseMap, $vectorUnwrappedPhaseMap, $iArrUnwrappedPhaseMapSize
    Local $bUnwrappedPhaseMapIsArray = IsArray($unwrappedPhaseMap)
    Local $bUnwrappedPhaseMapCreate = IsDllStruct($unwrappedPhaseMap) And $typeOfUnwrappedPhaseMap == "Scalar"

    If $typeOfUnwrappedPhaseMap == Default Then
        $oArrUnwrappedPhaseMap = $unwrappedPhaseMap
    ElseIf $bUnwrappedPhaseMapIsArray Then
        $vectorUnwrappedPhaseMap = Call("_VectorOf" & $typeOfUnwrappedPhaseMap & "Create")

        $iArrUnwrappedPhaseMapSize = UBound($unwrappedPhaseMap)
        For $i = 0 To $iArrUnwrappedPhaseMapSize - 1
            Call("_VectorOf" & $typeOfUnwrappedPhaseMap & "Push", $vectorUnwrappedPhaseMap, $unwrappedPhaseMap[$i])
        Next

        $oArrUnwrappedPhaseMap = Call("_cveOutputArrayFromVectorOf" & $typeOfUnwrappedPhaseMap, $vectorUnwrappedPhaseMap)
    Else
        If $bUnwrappedPhaseMapCreate Then
            $unwrappedPhaseMap = Call("_cve" & $typeOfUnwrappedPhaseMap & "Create", $unwrappedPhaseMap)
        EndIf
        $oArrUnwrappedPhaseMap = Call("_cveOutputArrayFrom" & $typeOfUnwrappedPhaseMap, $unwrappedPhaseMap)
    EndIf

    Local $iArrShadowMask, $vectorShadowMask, $iArrShadowMaskSize
    Local $bShadowMaskIsArray = IsArray($shadowMask)
    Local $bShadowMaskCreate = IsDllStruct($shadowMask) And $typeOfShadowMask == "Scalar"

    If $typeOfShadowMask == Default Then
        $iArrShadowMask = $shadowMask
    ElseIf $bShadowMaskIsArray Then
        $vectorShadowMask = Call("_VectorOf" & $typeOfShadowMask & "Create")

        $iArrShadowMaskSize = UBound($shadowMask)
        For $i = 0 To $iArrShadowMaskSize - 1
            Call("_VectorOf" & $typeOfShadowMask & "Push", $vectorShadowMask, $shadowMask[$i])
        Next

        $iArrShadowMask = Call("_cveInputArrayFromVectorOf" & $typeOfShadowMask, $vectorShadowMask)
    Else
        If $bShadowMaskCreate Then
            $shadowMask = Call("_cve" & $typeOfShadowMask & "Create", $shadowMask)
        EndIf
        $iArrShadowMask = Call("_cveInputArrayFrom" & $typeOfShadowMask, $shadowMask)
    EndIf

    _cveHistogramPhaseMapUnwrappingUnwrapPhaseMap($phase_unwrapping, $iArrWrappedPhaseMap, $oArrUnwrappedPhaseMap, $iArrShadowMask)

    If $bShadowMaskIsArray Then
        Call("_VectorOf" & $typeOfShadowMask & "Release", $vectorShadowMask)
    EndIf

    If $typeOfShadowMask <> Default Then
        _cveInputArrayRelease($iArrShadowMask)
        If $bShadowMaskCreate Then
            Call("_cve" & $typeOfShadowMask & "Release", $shadowMask)
        EndIf
    EndIf

    If $bUnwrappedPhaseMapIsArray Then
        Call("_VectorOf" & $typeOfUnwrappedPhaseMap & "Release", $vectorUnwrappedPhaseMap)
    EndIf

    If $typeOfUnwrappedPhaseMap <> Default Then
        _cveOutputArrayRelease($oArrUnwrappedPhaseMap)
        If $bUnwrappedPhaseMapCreate Then
            Call("_cve" & $typeOfUnwrappedPhaseMap & "Release", $unwrappedPhaseMap)
        EndIf
    EndIf

    If $bWrappedPhaseMapIsArray Then
        Call("_VectorOf" & $typeOfWrappedPhaseMap & "Release", $vectorWrappedPhaseMap)
    EndIf

    If $typeOfWrappedPhaseMap <> Default Then
        _cveInputArrayRelease($iArrWrappedPhaseMap)
        If $bWrappedPhaseMapCreate Then
            Call("_cve" & $typeOfWrappedPhaseMap & "Release", $wrappedPhaseMap)
        EndIf
    EndIf
EndFunc   ;==>_cveHistogramPhaseMapUnwrappingUnwrapPhaseMapTyped

Func _cveHistogramPhaseMapUnwrappingUnwrapPhaseMapMat($phase_unwrapping, $wrappedPhaseMap, $unwrappedPhaseMap, $shadowMask)
    ; cveHistogramPhaseMapUnwrappingUnwrapPhaseMap using cv::Mat instead of _*Array
    _cveHistogramPhaseMapUnwrappingUnwrapPhaseMapTyped($phase_unwrapping, "Mat", $wrappedPhaseMap, "Mat", $unwrappedPhaseMap, "Mat", $shadowMask)
EndFunc   ;==>_cveHistogramPhaseMapUnwrappingUnwrapPhaseMapMat