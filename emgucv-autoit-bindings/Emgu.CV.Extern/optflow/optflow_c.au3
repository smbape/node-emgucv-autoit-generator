#include-once
#include "..\..\CVEUtils.au3"

Func _cveUpdateMotionHistory($silhouette, $mhi, $timestamp, $duration)
    ; CVAPI(void) cveUpdateMotionHistory(cv::_InputArray* silhouette, cv::_InputOutputArray* mhi, double timestamp, double duration);

    Local $sSilhouetteDllType
    If IsDllStruct($silhouette) Then
        $sSilhouetteDllType = "struct*"
    Else
        $sSilhouetteDllType = "ptr"
    EndIf

    Local $sMhiDllType
    If IsDllStruct($mhi) Then
        $sMhiDllType = "struct*"
    Else
        $sMhiDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUpdateMotionHistory", $sSilhouetteDllType, $silhouette, $sMhiDllType, $mhi, "double", $timestamp, "double", $duration), "cveUpdateMotionHistory", @error)
EndFunc   ;==>_cveUpdateMotionHistory

Func _cveUpdateMotionHistoryTyped($typeOfSilhouette, $silhouette, $typeOfMhi, $mhi, $timestamp, $duration)

    Local $iArrSilhouette, $vectorSilhouette, $iArrSilhouetteSize
    Local $bSilhouetteIsArray = IsArray($silhouette)
    Local $bSilhouetteCreate = IsDllStruct($silhouette) And $typeOfSilhouette == "Scalar"

    If $typeOfSilhouette == Default Then
        $iArrSilhouette = $silhouette
    ElseIf $bSilhouetteIsArray Then
        $vectorSilhouette = Call("_VectorOf" & $typeOfSilhouette & "Create")

        $iArrSilhouetteSize = UBound($silhouette)
        For $i = 0 To $iArrSilhouetteSize - 1
            Call("_VectorOf" & $typeOfSilhouette & "Push", $vectorSilhouette, $silhouette[$i])
        Next

        $iArrSilhouette = Call("_cveInputArrayFromVectorOf" & $typeOfSilhouette, $vectorSilhouette)
    Else
        If $bSilhouetteCreate Then
            $silhouette = Call("_cve" & $typeOfSilhouette & "Create", $silhouette)
        EndIf
        $iArrSilhouette = Call("_cveInputArrayFrom" & $typeOfSilhouette, $silhouette)
    EndIf

    Local $ioArrMhi, $vectorMhi, $iArrMhiSize
    Local $bMhiIsArray = IsArray($mhi)
    Local $bMhiCreate = IsDllStruct($mhi) And $typeOfMhi == "Scalar"

    If $typeOfMhi == Default Then
        $ioArrMhi = $mhi
    ElseIf $bMhiIsArray Then
        $vectorMhi = Call("_VectorOf" & $typeOfMhi & "Create")

        $iArrMhiSize = UBound($mhi)
        For $i = 0 To $iArrMhiSize - 1
            Call("_VectorOf" & $typeOfMhi & "Push", $vectorMhi, $mhi[$i])
        Next

        $ioArrMhi = Call("_cveInputOutputArrayFromVectorOf" & $typeOfMhi, $vectorMhi)
    Else
        If $bMhiCreate Then
            $mhi = Call("_cve" & $typeOfMhi & "Create", $mhi)
        EndIf
        $ioArrMhi = Call("_cveInputOutputArrayFrom" & $typeOfMhi, $mhi)
    EndIf

    _cveUpdateMotionHistory($iArrSilhouette, $ioArrMhi, $timestamp, $duration)

    If $bMhiIsArray Then
        Call("_VectorOf" & $typeOfMhi & "Release", $vectorMhi)
    EndIf

    If $typeOfMhi <> Default Then
        _cveInputOutputArrayRelease($ioArrMhi)
        If $bMhiCreate Then
            Call("_cve" & $typeOfMhi & "Release", $mhi)
        EndIf
    EndIf

    If $bSilhouetteIsArray Then
        Call("_VectorOf" & $typeOfSilhouette & "Release", $vectorSilhouette)
    EndIf

    If $typeOfSilhouette <> Default Then
        _cveInputArrayRelease($iArrSilhouette)
        If $bSilhouetteCreate Then
            Call("_cve" & $typeOfSilhouette & "Release", $silhouette)
        EndIf
    EndIf
EndFunc   ;==>_cveUpdateMotionHistoryTyped

Func _cveUpdateMotionHistoryMat($silhouette, $mhi, $timestamp, $duration)
    ; cveUpdateMotionHistory using cv::Mat instead of _*Array
    _cveUpdateMotionHistoryTyped("Mat", $silhouette, "Mat", $mhi, $timestamp, $duration)
EndFunc   ;==>_cveUpdateMotionHistoryMat

Func _cveCalcMotionGradient($mhi, $mask, $orientation, $delta1, $delta2, $apertureSize = 3)
    ; CVAPI(void) cveCalcMotionGradient(cv::_InputArray* mhi, cv::_OutputArray* mask, cv::_OutputArray* orientation, double delta1, double delta2, int apertureSize);

    Local $sMhiDllType
    If IsDllStruct($mhi) Then
        $sMhiDllType = "struct*"
    Else
        $sMhiDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sOrientationDllType
    If IsDllStruct($orientation) Then
        $sOrientationDllType = "struct*"
    Else
        $sOrientationDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcMotionGradient", $sMhiDllType, $mhi, $sMaskDllType, $mask, $sOrientationDllType, $orientation, "double", $delta1, "double", $delta2, "int", $apertureSize), "cveCalcMotionGradient", @error)
EndFunc   ;==>_cveCalcMotionGradient

Func _cveCalcMotionGradientTyped($typeOfMhi, $mhi, $typeOfMask, $mask, $typeOfOrientation, $orientation, $delta1, $delta2, $apertureSize = 3)

    Local $iArrMhi, $vectorMhi, $iArrMhiSize
    Local $bMhiIsArray = IsArray($mhi)
    Local $bMhiCreate = IsDllStruct($mhi) And $typeOfMhi == "Scalar"

    If $typeOfMhi == Default Then
        $iArrMhi = $mhi
    ElseIf $bMhiIsArray Then
        $vectorMhi = Call("_VectorOf" & $typeOfMhi & "Create")

        $iArrMhiSize = UBound($mhi)
        For $i = 0 To $iArrMhiSize - 1
            Call("_VectorOf" & $typeOfMhi & "Push", $vectorMhi, $mhi[$i])
        Next

        $iArrMhi = Call("_cveInputArrayFromVectorOf" & $typeOfMhi, $vectorMhi)
    Else
        If $bMhiCreate Then
            $mhi = Call("_cve" & $typeOfMhi & "Create", $mhi)
        EndIf
        $iArrMhi = Call("_cveInputArrayFrom" & $typeOfMhi, $mhi)
    EndIf

    Local $oArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $oArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $oArrMask = Call("_cveOutputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $oArrMask = Call("_cveOutputArrayFrom" & $typeOfMask, $mask)
    EndIf

    Local $oArrOrientation, $vectorOrientation, $iArrOrientationSize
    Local $bOrientationIsArray = IsArray($orientation)
    Local $bOrientationCreate = IsDllStruct($orientation) And $typeOfOrientation == "Scalar"

    If $typeOfOrientation == Default Then
        $oArrOrientation = $orientation
    ElseIf $bOrientationIsArray Then
        $vectorOrientation = Call("_VectorOf" & $typeOfOrientation & "Create")

        $iArrOrientationSize = UBound($orientation)
        For $i = 0 To $iArrOrientationSize - 1
            Call("_VectorOf" & $typeOfOrientation & "Push", $vectorOrientation, $orientation[$i])
        Next

        $oArrOrientation = Call("_cveOutputArrayFromVectorOf" & $typeOfOrientation, $vectorOrientation)
    Else
        If $bOrientationCreate Then
            $orientation = Call("_cve" & $typeOfOrientation & "Create", $orientation)
        EndIf
        $oArrOrientation = Call("_cveOutputArrayFrom" & $typeOfOrientation, $orientation)
    EndIf

    _cveCalcMotionGradient($iArrMhi, $oArrMask, $oArrOrientation, $delta1, $delta2, $apertureSize)

    If $bOrientationIsArray Then
        Call("_VectorOf" & $typeOfOrientation & "Release", $vectorOrientation)
    EndIf

    If $typeOfOrientation <> Default Then
        _cveOutputArrayRelease($oArrOrientation)
        If $bOrientationCreate Then
            Call("_cve" & $typeOfOrientation & "Release", $orientation)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveOutputArrayRelease($oArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bMhiIsArray Then
        Call("_VectorOf" & $typeOfMhi & "Release", $vectorMhi)
    EndIf

    If $typeOfMhi <> Default Then
        _cveInputArrayRelease($iArrMhi)
        If $bMhiCreate Then
            Call("_cve" & $typeOfMhi & "Release", $mhi)
        EndIf
    EndIf
EndFunc   ;==>_cveCalcMotionGradientTyped

Func _cveCalcMotionGradientMat($mhi, $mask, $orientation, $delta1, $delta2, $apertureSize = 3)
    ; cveCalcMotionGradient using cv::Mat instead of _*Array
    _cveCalcMotionGradientTyped("Mat", $mhi, "Mat", $mask, "Mat", $orientation, $delta1, $delta2, $apertureSize)
EndFunc   ;==>_cveCalcMotionGradientMat

Func _cveCalcGlobalOrientation($orientation, $mask, $mhi, $timestamp, $duration)
    ; CVAPI(void) cveCalcGlobalOrientation(cv::_InputArray* orientation, cv::_InputArray* mask, cv::_InputArray* mhi, double timestamp, double duration);

    Local $sOrientationDllType
    If IsDllStruct($orientation) Then
        $sOrientationDllType = "struct*"
    Else
        $sOrientationDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sMhiDllType
    If IsDllStruct($mhi) Then
        $sMhiDllType = "struct*"
    Else
        $sMhiDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalcGlobalOrientation", $sOrientationDllType, $orientation, $sMaskDllType, $mask, $sMhiDllType, $mhi, "double", $timestamp, "double", $duration), "cveCalcGlobalOrientation", @error)
EndFunc   ;==>_cveCalcGlobalOrientation

Func _cveCalcGlobalOrientationTyped($typeOfOrientation, $orientation, $typeOfMask, $mask, $typeOfMhi, $mhi, $timestamp, $duration)

    Local $iArrOrientation, $vectorOrientation, $iArrOrientationSize
    Local $bOrientationIsArray = IsArray($orientation)
    Local $bOrientationCreate = IsDllStruct($orientation) And $typeOfOrientation == "Scalar"

    If $typeOfOrientation == Default Then
        $iArrOrientation = $orientation
    ElseIf $bOrientationIsArray Then
        $vectorOrientation = Call("_VectorOf" & $typeOfOrientation & "Create")

        $iArrOrientationSize = UBound($orientation)
        For $i = 0 To $iArrOrientationSize - 1
            Call("_VectorOf" & $typeOfOrientation & "Push", $vectorOrientation, $orientation[$i])
        Next

        $iArrOrientation = Call("_cveInputArrayFromVectorOf" & $typeOfOrientation, $vectorOrientation)
    Else
        If $bOrientationCreate Then
            $orientation = Call("_cve" & $typeOfOrientation & "Create", $orientation)
        EndIf
        $iArrOrientation = Call("_cveInputArrayFrom" & $typeOfOrientation, $orientation)
    EndIf

    Local $iArrMask, $vectorMask, $iArrMaskSize
    Local $bMaskIsArray = IsArray($mask)
    Local $bMaskCreate = IsDllStruct($mask) And $typeOfMask == "Scalar"

    If $typeOfMask == Default Then
        $iArrMask = $mask
    ElseIf $bMaskIsArray Then
        $vectorMask = Call("_VectorOf" & $typeOfMask & "Create")

        $iArrMaskSize = UBound($mask)
        For $i = 0 To $iArrMaskSize - 1
            Call("_VectorOf" & $typeOfMask & "Push", $vectorMask, $mask[$i])
        Next

        $iArrMask = Call("_cveInputArrayFromVectorOf" & $typeOfMask, $vectorMask)
    Else
        If $bMaskCreate Then
            $mask = Call("_cve" & $typeOfMask & "Create", $mask)
        EndIf
        $iArrMask = Call("_cveInputArrayFrom" & $typeOfMask, $mask)
    EndIf

    Local $iArrMhi, $vectorMhi, $iArrMhiSize
    Local $bMhiIsArray = IsArray($mhi)
    Local $bMhiCreate = IsDllStruct($mhi) And $typeOfMhi == "Scalar"

    If $typeOfMhi == Default Then
        $iArrMhi = $mhi
    ElseIf $bMhiIsArray Then
        $vectorMhi = Call("_VectorOf" & $typeOfMhi & "Create")

        $iArrMhiSize = UBound($mhi)
        For $i = 0 To $iArrMhiSize - 1
            Call("_VectorOf" & $typeOfMhi & "Push", $vectorMhi, $mhi[$i])
        Next

        $iArrMhi = Call("_cveInputArrayFromVectorOf" & $typeOfMhi, $vectorMhi)
    Else
        If $bMhiCreate Then
            $mhi = Call("_cve" & $typeOfMhi & "Create", $mhi)
        EndIf
        $iArrMhi = Call("_cveInputArrayFrom" & $typeOfMhi, $mhi)
    EndIf

    _cveCalcGlobalOrientation($iArrOrientation, $iArrMask, $iArrMhi, $timestamp, $duration)

    If $bMhiIsArray Then
        Call("_VectorOf" & $typeOfMhi & "Release", $vectorMhi)
    EndIf

    If $typeOfMhi <> Default Then
        _cveInputArrayRelease($iArrMhi)
        If $bMhiCreate Then
            Call("_cve" & $typeOfMhi & "Release", $mhi)
        EndIf
    EndIf

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bOrientationIsArray Then
        Call("_VectorOf" & $typeOfOrientation & "Release", $vectorOrientation)
    EndIf

    If $typeOfOrientation <> Default Then
        _cveInputArrayRelease($iArrOrientation)
        If $bOrientationCreate Then
            Call("_cve" & $typeOfOrientation & "Release", $orientation)
        EndIf
    EndIf
EndFunc   ;==>_cveCalcGlobalOrientationTyped

Func _cveCalcGlobalOrientationMat($orientation, $mask, $mhi, $timestamp, $duration)
    ; cveCalcGlobalOrientation using cv::Mat instead of _*Array
    _cveCalcGlobalOrientationTyped("Mat", $orientation, "Mat", $mask, "Mat", $mhi, $timestamp, $duration)
EndFunc   ;==>_cveCalcGlobalOrientationMat

Func _cveSegmentMotion($mhi, $segmask, $boundingRects, $timestamp, $segThresh)
    ; CVAPI(void) cveSegmentMotion(cv::_InputArray* mhi, cv::_OutputArray* segmask, std::vector<cv::Rect>* boundingRects, double timestamp, double segThresh);

    Local $sMhiDllType
    If IsDllStruct($mhi) Then
        $sMhiDllType = "struct*"
    Else
        $sMhiDllType = "ptr"
    EndIf

    Local $sSegmaskDllType
    If IsDllStruct($segmask) Then
        $sSegmaskDllType = "struct*"
    Else
        $sSegmaskDllType = "ptr"
    EndIf

    Local $vecBoundingRects, $iArrBoundingRectsSize
    Local $bBoundingRectsIsArray = IsArray($boundingRects)

    If $bBoundingRectsIsArray Then
        $vecBoundingRects = _VectorOfRectCreate()

        $iArrBoundingRectsSize = UBound($boundingRects)
        For $i = 0 To $iArrBoundingRectsSize - 1
            _VectorOfRectPush($vecBoundingRects, $boundingRects[$i])
        Next
    Else
        $vecBoundingRects = $boundingRects
    EndIf

    Local $sBoundingRectsDllType
    If IsDllStruct($boundingRects) Then
        $sBoundingRectsDllType = "struct*"
    Else
        $sBoundingRectsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSegmentMotion", $sMhiDllType, $mhi, $sSegmaskDllType, $segmask, $sBoundingRectsDllType, $vecBoundingRects, "double", $timestamp, "double", $segThresh), "cveSegmentMotion", @error)

    If $bBoundingRectsIsArray Then
        _VectorOfRectRelease($vecBoundingRects)
    EndIf
EndFunc   ;==>_cveSegmentMotion

Func _cveSegmentMotionTyped($typeOfMhi, $mhi, $typeOfSegmask, $segmask, $boundingRects, $timestamp, $segThresh)

    Local $iArrMhi, $vectorMhi, $iArrMhiSize
    Local $bMhiIsArray = IsArray($mhi)
    Local $bMhiCreate = IsDllStruct($mhi) And $typeOfMhi == "Scalar"

    If $typeOfMhi == Default Then
        $iArrMhi = $mhi
    ElseIf $bMhiIsArray Then
        $vectorMhi = Call("_VectorOf" & $typeOfMhi & "Create")

        $iArrMhiSize = UBound($mhi)
        For $i = 0 To $iArrMhiSize - 1
            Call("_VectorOf" & $typeOfMhi & "Push", $vectorMhi, $mhi[$i])
        Next

        $iArrMhi = Call("_cveInputArrayFromVectorOf" & $typeOfMhi, $vectorMhi)
    Else
        If $bMhiCreate Then
            $mhi = Call("_cve" & $typeOfMhi & "Create", $mhi)
        EndIf
        $iArrMhi = Call("_cveInputArrayFrom" & $typeOfMhi, $mhi)
    EndIf

    Local $oArrSegmask, $vectorSegmask, $iArrSegmaskSize
    Local $bSegmaskIsArray = IsArray($segmask)
    Local $bSegmaskCreate = IsDllStruct($segmask) And $typeOfSegmask == "Scalar"

    If $typeOfSegmask == Default Then
        $oArrSegmask = $segmask
    ElseIf $bSegmaskIsArray Then
        $vectorSegmask = Call("_VectorOf" & $typeOfSegmask & "Create")

        $iArrSegmaskSize = UBound($segmask)
        For $i = 0 To $iArrSegmaskSize - 1
            Call("_VectorOf" & $typeOfSegmask & "Push", $vectorSegmask, $segmask[$i])
        Next

        $oArrSegmask = Call("_cveOutputArrayFromVectorOf" & $typeOfSegmask, $vectorSegmask)
    Else
        If $bSegmaskCreate Then
            $segmask = Call("_cve" & $typeOfSegmask & "Create", $segmask)
        EndIf
        $oArrSegmask = Call("_cveOutputArrayFrom" & $typeOfSegmask, $segmask)
    EndIf

    _cveSegmentMotion($iArrMhi, $oArrSegmask, $boundingRects, $timestamp, $segThresh)

    If $bSegmaskIsArray Then
        Call("_VectorOf" & $typeOfSegmask & "Release", $vectorSegmask)
    EndIf

    If $typeOfSegmask <> Default Then
        _cveOutputArrayRelease($oArrSegmask)
        If $bSegmaskCreate Then
            Call("_cve" & $typeOfSegmask & "Release", $segmask)
        EndIf
    EndIf

    If $bMhiIsArray Then
        Call("_VectorOf" & $typeOfMhi & "Release", $vectorMhi)
    EndIf

    If $typeOfMhi <> Default Then
        _cveInputArrayRelease($iArrMhi)
        If $bMhiCreate Then
            Call("_cve" & $typeOfMhi & "Release", $mhi)
        EndIf
    EndIf
EndFunc   ;==>_cveSegmentMotionTyped

Func _cveSegmentMotionMat($mhi, $segmask, $boundingRects, $timestamp, $segThresh)
    ; cveSegmentMotion using cv::Mat instead of _*Array
    _cveSegmentMotionTyped("Mat", $mhi, "Mat", $segmask, $boundingRects, $timestamp, $segThresh)
EndFunc   ;==>_cveSegmentMotionMat

Func _cveOptFlowDeepFlowCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::DenseOpticalFlow*) cveOptFlowDeepFlowCreate(cv::Algorithm** algorithm, cv::Ptr<cv::DenseOpticalFlow>** sharedPtr);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOptFlowDeepFlowCreate", $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveOptFlowDeepFlowCreate", @error)
EndFunc   ;==>_cveOptFlowDeepFlowCreate

Func _cveOptFlowPCAFlowCreate($algorithm, $sharedPtr)
    ; CVAPI(cv::DenseOpticalFlow*) cveOptFlowPCAFlowCreate(cv::Algorithm** algorithm, cv::Ptr<cv::DenseOpticalFlow>** sharedPtr);

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveOptFlowPCAFlowCreate", $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveOptFlowPCAFlowCreate", @error)
EndFunc   ;==>_cveOptFlowPCAFlowCreate

Func _cveDenseOpticalFlowCreateDualTVL1($denseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::optflow::DualTVL1OpticalFlow*) cveDenseOpticalFlowCreateDualTVL1(cv::DenseOpticalFlow** denseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::optflow::DualTVL1OpticalFlow>** sharedPtr);

    Local $sDenseOpticalFlowDllType
    If IsDllStruct($denseOpticalFlow) Then
        $sDenseOpticalFlowDllType = "struct*"
    ElseIf $denseOpticalFlow == Null Then
        $sDenseOpticalFlowDllType = "ptr"
    Else
        $sDenseOpticalFlowDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDenseOpticalFlowCreateDualTVL1", $sDenseOpticalFlowDllType, $denseOpticalFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveDenseOpticalFlowCreateDualTVL1", @error)
EndFunc   ;==>_cveDenseOpticalFlowCreateDualTVL1

Func _cveDualTVL1OpticalFlowRelease($sharedPtr)
    ; CVAPI(void) cveDualTVL1OpticalFlowRelease(cv::Ptr<cv::optflow::DualTVL1OpticalFlow>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDualTVL1OpticalFlowRelease", $sSharedPtrDllType, $sharedPtr), "cveDualTVL1OpticalFlowRelease", @error)
EndFunc   ;==>_cveDualTVL1OpticalFlowRelease

Func _cveRLOFOpticalFlowParameterCreate()
    ; CVAPI(cv::optflow::RLOFOpticalFlowParameter*) cveRLOFOpticalFlowParameterCreate();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveRLOFOpticalFlowParameterCreate"), "cveRLOFOpticalFlowParameterCreate", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterCreate

Func _cveRLOFOpticalFlowParameterRelease($p)
    ; CVAPI(void) cveRLOFOpticalFlowParameterRelease(cv::optflow::RLOFOpticalFlowParameter** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRLOFOpticalFlowParameterRelease", $sPDllType, $p), "cveRLOFOpticalFlowParameterRelease", @error)
EndFunc   ;==>_cveRLOFOpticalFlowParameterRelease

Func _cveDenseRLOFOpticalFlowCreate($rlofParameter, $forwardBackwardThreshold, $gridStep, $interpType, $epicK, $epicSigma, $epicLambda, $usePostProc, $fgsLambda, $fgsSigma, $denseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::optflow::DenseRLOFOpticalFlow*) cveDenseRLOFOpticalFlowCreate(cv::optflow::RLOFOpticalFlowParameter* rlofParameter, float forwardBackwardThreshold, CvSize* gridStep, int interpType, int epicK, float epicSigma, float epicLambda, bool usePostProc, float fgsLambda, float fgsSigma, cv::DenseOpticalFlow** denseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::optflow::DenseRLOFOpticalFlow>** sharedPtr);

    Local $sRlofParameterDllType
    If IsDllStruct($rlofParameter) Then
        $sRlofParameterDllType = "struct*"
    Else
        $sRlofParameterDllType = "ptr"
    EndIf

    Local $sGridStepDllType
    If IsDllStruct($gridStep) Then
        $sGridStepDllType = "struct*"
    Else
        $sGridStepDllType = "ptr"
    EndIf

    Local $sDenseOpticalFlowDllType
    If IsDllStruct($denseOpticalFlow) Then
        $sDenseOpticalFlowDllType = "struct*"
    ElseIf $denseOpticalFlow == Null Then
        $sDenseOpticalFlowDllType = "ptr"
    Else
        $sDenseOpticalFlowDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveDenseRLOFOpticalFlowCreate", $sRlofParameterDllType, $rlofParameter, "float", $forwardBackwardThreshold, $sGridStepDllType, $gridStep, "int", $interpType, "int", $epicK, "float", $epicSigma, "float", $epicLambda, "boolean", $usePostProc, "float", $fgsLambda, "float", $fgsSigma, $sDenseOpticalFlowDllType, $denseOpticalFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveDenseRLOFOpticalFlowCreate", @error)
EndFunc   ;==>_cveDenseRLOFOpticalFlowCreate

Func _cveDenseRLOFOpticalFlowRelease($sharedPtr)
    ; CVAPI(void) cveDenseRLOFOpticalFlowRelease(cv::Ptr<cv::optflow::DenseRLOFOpticalFlow>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDenseRLOFOpticalFlowRelease", $sSharedPtrDllType, $sharedPtr), "cveDenseRLOFOpticalFlowRelease", @error)
EndFunc   ;==>_cveDenseRLOFOpticalFlowRelease

Func _cveSparseRLOFOpticalFlowCreate($rlofParameter, $forwardBackwardThreshold, $sparseOpticalFlow, $algorithm, $sharedPtr)
    ; CVAPI(cv::optflow::SparseRLOFOpticalFlow*) cveSparseRLOFOpticalFlowCreate(cv::optflow::RLOFOpticalFlowParameter* rlofParameter, float forwardBackwardThreshold, cv::SparseOpticalFlow** sparseOpticalFlow, cv::Algorithm** algorithm, cv::Ptr<cv::optflow::SparseRLOFOpticalFlow>** sharedPtr);

    Local $sRlofParameterDllType
    If IsDllStruct($rlofParameter) Then
        $sRlofParameterDllType = "struct*"
    Else
        $sRlofParameterDllType = "ptr"
    EndIf

    Local $sSparseOpticalFlowDllType
    If IsDllStruct($sparseOpticalFlow) Then
        $sSparseOpticalFlowDllType = "struct*"
    ElseIf $sparseOpticalFlow == Null Then
        $sSparseOpticalFlowDllType = "ptr"
    Else
        $sSparseOpticalFlowDllType = "ptr*"
    EndIf

    Local $sAlgorithmDllType
    If IsDllStruct($algorithm) Then
        $sAlgorithmDllType = "struct*"
    ElseIf $algorithm == Null Then
        $sAlgorithmDllType = "ptr"
    Else
        $sAlgorithmDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSparseRLOFOpticalFlowCreate", $sRlofParameterDllType, $rlofParameter, "float", $forwardBackwardThreshold, $sSparseOpticalFlowDllType, $sparseOpticalFlow, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveSparseRLOFOpticalFlowCreate", @error)
EndFunc   ;==>_cveSparseRLOFOpticalFlowCreate

Func _cveSparseRLOFOpticalFlowRelease($sharedPtr)
    ; CVAPI(void) cveSparseRLOFOpticalFlowRelease(cv::Ptr<cv::optflow::SparseRLOFOpticalFlow>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSparseRLOFOpticalFlowRelease", $sSharedPtrDllType, $sharedPtr), "cveSparseRLOFOpticalFlowRelease", @error)
EndFunc   ;==>_cveSparseRLOFOpticalFlowRelease