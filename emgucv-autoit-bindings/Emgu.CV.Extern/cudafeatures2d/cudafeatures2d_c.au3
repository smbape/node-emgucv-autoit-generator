#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaDescriptorMatcherCreateBFMatcher($distType, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::DescriptorMatcher*) cveCudaDescriptorMatcherCreateBFMatcher(int distType, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::DescriptorMatcher>** sharedPtr);

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
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCudaDescriptorMatcherCreateBFMatcher", "int", $distType, $sAlgorithmDllType, $algorithm, $sSharedPtrDllType, $sharedPtr), "cveCudaDescriptorMatcherCreateBFMatcher", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherCreateBFMatcher

Func _cveCudaDescriptorMatcherRelease($sharedPtr)
    ; CVAPI(void) cveCudaDescriptorMatcherRelease(cv::Ptr<cv::cuda::DescriptorMatcher>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRelease", $sSharedPtrDllType, $sharedPtr), "cveCudaDescriptorMatcherRelease", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherRelease

Func _cveCudaDescriptorMatcherAdd($matcher, $trainDescs)
    ; CVAPI(void) cveCudaDescriptorMatcherAdd(cv::cuda::DescriptorMatcher* matcher, const std::vector<cv::cuda::GpuMat>* trainDescs);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $vecTrainDescs, $iArrTrainDescsSize
    Local $bTrainDescsIsArray = IsArray($trainDescs)

    If $bTrainDescsIsArray Then
        $vecTrainDescs = _VectorOfGpuMatCreate()

        $iArrTrainDescsSize = UBound($trainDescs)
        For $i = 0 To $iArrTrainDescsSize - 1
            _VectorOfGpuMatPush($vecTrainDescs, $trainDescs[$i])
        Next
    Else
        $vecTrainDescs = $trainDescs
    EndIf

    Local $sTrainDescsDllType
    If IsDllStruct($trainDescs) Then
        $sTrainDescsDllType = "struct*"
    Else
        $sTrainDescsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherAdd", $sMatcherDllType, $matcher, $sTrainDescsDllType, $vecTrainDescs), "cveCudaDescriptorMatcherAdd", @error)

    If $bTrainDescsIsArray Then
        _VectorOfGpuMatRelease($vecTrainDescs)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherAdd

Func _cveCudaDescriptorMatcherIsMaskSupported($matcher)
    ; CVAPI(bool) cveCudaDescriptorMatcherIsMaskSupported(cv::cuda::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaDescriptorMatcherIsMaskSupported", $sMatcherDllType, $matcher), "cveCudaDescriptorMatcherIsMaskSupported", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherIsMaskSupported

Func _cveCudaDescriptorMatcherClear($matcher)
    ; CVAPI(void) cveCudaDescriptorMatcherClear(cv::cuda::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherClear", $sMatcherDllType, $matcher), "cveCudaDescriptorMatcherClear", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherClear

Func _cveCudaDescriptorMatcherEmpty($matcher)
    ; CVAPI(bool) cveCudaDescriptorMatcherEmpty(cv::cuda::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaDescriptorMatcherEmpty", $sMatcherDllType, $matcher), "cveCudaDescriptorMatcherEmpty", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherEmpty

Func _cveCudaDescriptorMatcherTrain($matcher)
    ; CVAPI(void) cveCudaDescriptorMatcherTrain(cv::cuda::DescriptorMatcher* matcher);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherTrain", $sMatcherDllType, $matcher), "cveCudaDescriptorMatcherTrain", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherTrain

Func _cveCudaDescriptorMatcherMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask)
    ; CVAPI(void) cveCudaDescriptorMatcherMatch1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector<cv::DMatch>* matches, cv::_InputArray* mask);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatch1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $vecMatches, $sMaskDllType, $mask), "cveCudaDescriptorMatcherMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatch1

Func _cveCudaDescriptorMatcherMatch1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $matches, $typeOfMask, $mask)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
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

    _cveCudaDescriptorMatcherMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $iArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatch1Typed

Func _cveCudaDescriptorMatcherMatch1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask)
    ; cveCudaDescriptorMatcherMatch1 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherMatch1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, $matches, "Mat", $mask)
EndFunc   ;==>_cveCudaDescriptorMatcherMatch1Mat

Func _cveCudaDescriptorMatcherMatch2($matcher, $queryDescriptors, $matches, $masks)
    ; CVAPI(void) cveCudaDescriptorMatcherMatch2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector<cv::DMatch>* matches, std::vector<cv::cuda::GpuMat>* masks);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatch2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $vecMatches, $sMasksDllType, $vecMasks), "cveCudaDescriptorMatcherMatch2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatch2

Func _cveCudaDescriptorMatcherMatch2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $matches, $masks)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    _cveCudaDescriptorMatcherMatch2($matcher, $iArrQueryDescriptors, $matches, $masks)

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatch2Typed

Func _cveCudaDescriptorMatcherMatch2Mat($matcher, $queryDescriptors, $matches, $masks)
    ; cveCudaDescriptorMatcherMatch2 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherMatch2Typed($matcher, "Mat", $queryDescriptors, $matches, $masks)
EndFunc   ;==>_cveCudaDescriptorMatcherMatch2Mat

Func _cveCudaDescriptorMatcherMatchAsync1($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherMatchAsync1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, cv::_OutputArray* matches, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatchAsync1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $matches, $sMaskDllType, $mask, $sStreamDllType, $stream), "cveCudaDescriptorMatcherMatchAsync1", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync1

Func _cveCudaDescriptorMatcherMatchAsync1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $typeOfMatches, $matches, $typeOfMask, $mask, $stream)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
    EndIf

    Local $oArrMatches, $vectorMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)
    Local $bMatchesCreate = IsDllStruct($matches) And $typeOfMatches == "Scalar"

    If $typeOfMatches == Default Then
        $oArrMatches = $matches
    ElseIf $bMatchesIsArray Then
        $vectorMatches = Call("_VectorOf" & $typeOfMatches & "Create")

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            Call("_VectorOf" & $typeOfMatches & "Push", $vectorMatches, $matches[$i])
        Next

        $oArrMatches = Call("_cveOutputArrayFromVectorOf" & $typeOfMatches, $vectorMatches)
    Else
        If $bMatchesCreate Then
            $matches = Call("_cve" & $typeOfMatches & "Create", $matches)
        EndIf
        $oArrMatches = Call("_cveOutputArrayFrom" & $typeOfMatches, $matches)
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

    _cveCudaDescriptorMatcherMatchAsync1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $oArrMatches, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bMatchesIsArray Then
        Call("_VectorOf" & $typeOfMatches & "Release", $vectorMatches)
    EndIf

    If $typeOfMatches <> Default Then
        _cveOutputArrayRelease($oArrMatches)
        If $bMatchesCreate Then
            Call("_cve" & $typeOfMatches & "Release", $matches)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync1Typed

Func _cveCudaDescriptorMatcherMatchAsync1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask, $stream)
    ; cveCudaDescriptorMatcherMatchAsync1 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherMatchAsync1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, "Mat", $matches, "Mat", $mask, $stream)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync1Mat

Func _cveCudaDescriptorMatcherMatchAsync2($matcher, $queryDescriptors, $matches, $masks, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherMatchAsync2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_OutputArray* matches, std::vector<cv::cuda::GpuMat>* masks, cv::cuda::Stream* stream);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatchAsync2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $matches, $sMasksDllType, $vecMasks, $sStreamDllType, $stream), "cveCudaDescriptorMatcherMatchAsync2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync2

Func _cveCudaDescriptorMatcherMatchAsync2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfMatches, $matches, $masks, $stream)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $oArrMatches, $vectorMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)
    Local $bMatchesCreate = IsDllStruct($matches) And $typeOfMatches == "Scalar"

    If $typeOfMatches == Default Then
        $oArrMatches = $matches
    ElseIf $bMatchesIsArray Then
        $vectorMatches = Call("_VectorOf" & $typeOfMatches & "Create")

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            Call("_VectorOf" & $typeOfMatches & "Push", $vectorMatches, $matches[$i])
        Next

        $oArrMatches = Call("_cveOutputArrayFromVectorOf" & $typeOfMatches, $vectorMatches)
    Else
        If $bMatchesCreate Then
            $matches = Call("_cve" & $typeOfMatches & "Create", $matches)
        EndIf
        $oArrMatches = Call("_cveOutputArrayFrom" & $typeOfMatches, $matches)
    EndIf

    _cveCudaDescriptorMatcherMatchAsync2($matcher, $iArrQueryDescriptors, $oArrMatches, $masks, $stream)

    If $bMatchesIsArray Then
        Call("_VectorOf" & $typeOfMatches & "Release", $vectorMatches)
    EndIf

    If $typeOfMatches <> Default Then
        _cveOutputArrayRelease($oArrMatches)
        If $bMatchesCreate Then
            Call("_cve" & $typeOfMatches & "Release", $matches)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync2Typed

Func _cveCudaDescriptorMatcherMatchAsync2Mat($matcher, $queryDescriptors, $matches, $masks, $stream)
    ; cveCudaDescriptorMatcherMatchAsync2 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherMatchAsync2Typed($matcher, "Mat", $queryDescriptors, "Mat", $matches, $masks, $stream)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync2Mat

Func _cveCudaDescriptorMatcherMatchConvert($matcher, $gpuMatches, $matches)
    ; CVAPI(void) cveCudaDescriptorMatcherMatchConvert(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* gpuMatches, std::vector<cv::DMatch>* matches);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sGpuMatchesDllType
    If IsDllStruct($gpuMatches) Then
        $sGpuMatchesDllType = "struct*"
    Else
        $sGpuMatchesDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatchConvert", $sMatcherDllType, $matcher, $sGpuMatchesDllType, $gpuMatches, $sMatchesDllType, $vecMatches), "cveCudaDescriptorMatcherMatchConvert", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatchConvert

Func _cveCudaDescriptorMatcherMatchConvertTyped($matcher, $typeOfGpuMatches, $gpuMatches, $matches)

    Local $iArrGpuMatches, $vectorGpuMatches, $iArrGpuMatchesSize
    Local $bGpuMatchesIsArray = IsArray($gpuMatches)
    Local $bGpuMatchesCreate = IsDllStruct($gpuMatches) And $typeOfGpuMatches == "Scalar"

    If $typeOfGpuMatches == Default Then
        $iArrGpuMatches = $gpuMatches
    ElseIf $bGpuMatchesIsArray Then
        $vectorGpuMatches = Call("_VectorOf" & $typeOfGpuMatches & "Create")

        $iArrGpuMatchesSize = UBound($gpuMatches)
        For $i = 0 To $iArrGpuMatchesSize - 1
            Call("_VectorOf" & $typeOfGpuMatches & "Push", $vectorGpuMatches, $gpuMatches[$i])
        Next

        $iArrGpuMatches = Call("_cveInputArrayFromVectorOf" & $typeOfGpuMatches, $vectorGpuMatches)
    Else
        If $bGpuMatchesCreate Then
            $gpuMatches = Call("_cve" & $typeOfGpuMatches & "Create", $gpuMatches)
        EndIf
        $iArrGpuMatches = Call("_cveInputArrayFrom" & $typeOfGpuMatches, $gpuMatches)
    EndIf

    _cveCudaDescriptorMatcherMatchConvert($matcher, $iArrGpuMatches, $matches)

    If $bGpuMatchesIsArray Then
        Call("_VectorOf" & $typeOfGpuMatches & "Release", $vectorGpuMatches)
    EndIf

    If $typeOfGpuMatches <> Default Then
        _cveInputArrayRelease($iArrGpuMatches)
        If $bGpuMatchesCreate Then
            Call("_cve" & $typeOfGpuMatches & "Release", $gpuMatches)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatchConvertTyped

Func _cveCudaDescriptorMatcherMatchConvertMat($matcher, $gpuMatches, $matches)
    ; cveCudaDescriptorMatcherMatchConvert using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherMatchConvertTyped($matcher, "Mat", $gpuMatches, $matches)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchConvertMat

Func _cveCudaDescriptorMatcherKnnMatch1($matcher, $queryDescs, $trainDescs, $matches, $k, $masks, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatch1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescs, cv::_InputArray* trainDescs, std::vector<std::vector<cv::DMatch>>* matches, int k, cv::_InputArray* masks, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescsDllType
    If IsDllStruct($queryDescs) Then
        $sQueryDescsDllType = "struct*"
    Else
        $sQueryDescsDllType = "ptr"
    EndIf

    Local $sTrainDescsDllType
    If IsDllStruct($trainDescs) Then
        $sTrainDescsDllType = "struct*"
    Else
        $sTrainDescsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatch1", $sMatcherDllType, $matcher, $sQueryDescsDllType, $queryDescs, $sTrainDescsDllType, $trainDescs, $sMatchesDllType, $vecMatches, "int", $k, $sMasksDllType, $masks, "boolean", $compactResult), "cveCudaDescriptorMatcherKnnMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch1

Func _cveCudaDescriptorMatcherKnnMatch1Typed($matcher, $typeOfQueryDescs, $queryDescs, $typeOfTrainDescs, $trainDescs, $matches, $k, $typeOfMasks, $masks, $compactResult)

    Local $iArrQueryDescs, $vectorQueryDescs, $iArrQueryDescsSize
    Local $bQueryDescsIsArray = IsArray($queryDescs)
    Local $bQueryDescsCreate = IsDllStruct($queryDescs) And $typeOfQueryDescs == "Scalar"

    If $typeOfQueryDescs == Default Then
        $iArrQueryDescs = $queryDescs
    ElseIf $bQueryDescsIsArray Then
        $vectorQueryDescs = Call("_VectorOf" & $typeOfQueryDescs & "Create")

        $iArrQueryDescsSize = UBound($queryDescs)
        For $i = 0 To $iArrQueryDescsSize - 1
            Call("_VectorOf" & $typeOfQueryDescs & "Push", $vectorQueryDescs, $queryDescs[$i])
        Next

        $iArrQueryDescs = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescs, $vectorQueryDescs)
    Else
        If $bQueryDescsCreate Then
            $queryDescs = Call("_cve" & $typeOfQueryDescs & "Create", $queryDescs)
        EndIf
        $iArrQueryDescs = Call("_cveInputArrayFrom" & $typeOfQueryDescs, $queryDescs)
    EndIf

    Local $iArrTrainDescs, $vectorTrainDescs, $iArrTrainDescsSize
    Local $bTrainDescsIsArray = IsArray($trainDescs)
    Local $bTrainDescsCreate = IsDllStruct($trainDescs) And $typeOfTrainDescs == "Scalar"

    If $typeOfTrainDescs == Default Then
        $iArrTrainDescs = $trainDescs
    ElseIf $bTrainDescsIsArray Then
        $vectorTrainDescs = Call("_VectorOf" & $typeOfTrainDescs & "Create")

        $iArrTrainDescsSize = UBound($trainDescs)
        For $i = 0 To $iArrTrainDescsSize - 1
            Call("_VectorOf" & $typeOfTrainDescs & "Push", $vectorTrainDescs, $trainDescs[$i])
        Next

        $iArrTrainDescs = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescs, $vectorTrainDescs)
    Else
        If $bTrainDescsCreate Then
            $trainDescs = Call("_cve" & $typeOfTrainDescs & "Create", $trainDescs)
        EndIf
        $iArrTrainDescs = Call("_cveInputArrayFrom" & $typeOfTrainDescs, $trainDescs)
    EndIf

    Local $iArrMasks, $vectorMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)
    Local $bMasksCreate = IsDllStruct($masks) And $typeOfMasks == "Scalar"

    If $typeOfMasks == Default Then
        $iArrMasks = $masks
    ElseIf $bMasksIsArray Then
        $vectorMasks = Call("_VectorOf" & $typeOfMasks & "Create")

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            Call("_VectorOf" & $typeOfMasks & "Push", $vectorMasks, $masks[$i])
        Next

        $iArrMasks = Call("_cveInputArrayFromVectorOf" & $typeOfMasks, $vectorMasks)
    Else
        If $bMasksCreate Then
            $masks = Call("_cve" & $typeOfMasks & "Create", $masks)
        EndIf
        $iArrMasks = Call("_cveInputArrayFrom" & $typeOfMasks, $masks)
    EndIf

    _cveCudaDescriptorMatcherKnnMatch1($matcher, $iArrQueryDescs, $iArrTrainDescs, $matches, $k, $iArrMasks, $compactResult)

    If $bMasksIsArray Then
        Call("_VectorOf" & $typeOfMasks & "Release", $vectorMasks)
    EndIf

    If $typeOfMasks <> Default Then
        _cveInputArrayRelease($iArrMasks)
        If $bMasksCreate Then
            Call("_cve" & $typeOfMasks & "Release", $masks)
        EndIf
    EndIf

    If $bTrainDescsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescs & "Release", $vectorTrainDescs)
    EndIf

    If $typeOfTrainDescs <> Default Then
        _cveInputArrayRelease($iArrTrainDescs)
        If $bTrainDescsCreate Then
            Call("_cve" & $typeOfTrainDescs & "Release", $trainDescs)
        EndIf
    EndIf

    If $bQueryDescsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescs & "Release", $vectorQueryDescs)
    EndIf

    If $typeOfQueryDescs <> Default Then
        _cveInputArrayRelease($iArrQueryDescs)
        If $bQueryDescsCreate Then
            Call("_cve" & $typeOfQueryDescs & "Release", $queryDescs)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch1Typed

Func _cveCudaDescriptorMatcherKnnMatch1Mat($matcher, $queryDescs, $trainDescs, $matches, $k, $masks, $compactResult)
    ; cveCudaDescriptorMatcherKnnMatch1 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherKnnMatch1Typed($matcher, "Mat", $queryDescs, "Mat", $trainDescs, $matches, $k, "Mat", $masks, $compactResult)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch1Mat

Func _cveCudaDescriptorMatcherKnnMatch2($matcher, $queryDescriptors, $matches, $k, $masks, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatch2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector<std::vector<cv::DMatch>>* matches, int k, std::vector<cv::cuda::GpuMat>* masks, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatch2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $vecMatches, "int", $k, $sMasksDllType, $vecMasks, "boolean", $compactResult), "cveCudaDescriptorMatcherKnnMatch2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch2

Func _cveCudaDescriptorMatcherKnnMatch2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $matches, $k, $masks, $compactResult)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    _cveCudaDescriptorMatcherKnnMatch2($matcher, $iArrQueryDescriptors, $matches, $k, $masks, $compactResult)

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch2Typed

Func _cveCudaDescriptorMatcherKnnMatch2Mat($matcher, $queryDescriptors, $matches, $k, $masks, $compactResult)
    ; cveCudaDescriptorMatcherKnnMatch2 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherKnnMatch2Typed($matcher, "Mat", $queryDescriptors, $matches, $k, $masks, $compactResult)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch2Mat

Func _cveCudaDescriptorMatcherKnnMatchAsync1($matcher, $queryDescriptors, $trainDescriptors, $matches, $k, $mask, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatchAsync1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, cv::_OutputArray* matches, int k, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatchAsync1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $matches, "int", $k, $sMaskDllType, $mask, $sStreamDllType, $stream), "cveCudaDescriptorMatcherKnnMatchAsync1", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync1

Func _cveCudaDescriptorMatcherKnnMatchAsync1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $typeOfMatches, $matches, $k, $typeOfMask, $mask, $stream)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
    EndIf

    Local $oArrMatches, $vectorMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)
    Local $bMatchesCreate = IsDllStruct($matches) And $typeOfMatches == "Scalar"

    If $typeOfMatches == Default Then
        $oArrMatches = $matches
    ElseIf $bMatchesIsArray Then
        $vectorMatches = Call("_VectorOf" & $typeOfMatches & "Create")

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            Call("_VectorOf" & $typeOfMatches & "Push", $vectorMatches, $matches[$i])
        Next

        $oArrMatches = Call("_cveOutputArrayFromVectorOf" & $typeOfMatches, $vectorMatches)
    Else
        If $bMatchesCreate Then
            $matches = Call("_cve" & $typeOfMatches & "Create", $matches)
        EndIf
        $oArrMatches = Call("_cveOutputArrayFrom" & $typeOfMatches, $matches)
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

    _cveCudaDescriptorMatcherKnnMatchAsync1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $oArrMatches, $k, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bMatchesIsArray Then
        Call("_VectorOf" & $typeOfMatches & "Release", $vectorMatches)
    EndIf

    If $typeOfMatches <> Default Then
        _cveOutputArrayRelease($oArrMatches)
        If $bMatchesCreate Then
            Call("_cve" & $typeOfMatches & "Release", $matches)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync1Typed

Func _cveCudaDescriptorMatcherKnnMatchAsync1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $k, $mask, $stream)
    ; cveCudaDescriptorMatcherKnnMatchAsync1 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherKnnMatchAsync1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, "Mat", $matches, $k, "Mat", $mask, $stream)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync1Mat

Func _cveCudaDescriptorMatcherKnnMatchAsync2($matcher, $queryDescriptors, $matches, $k, $masks, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatchAsync2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_OutputArray* matches, int k, std::vector<cv::cuda::GpuMat>* masks, cv::cuda::Stream* stream);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatchAsync2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $matches, "int", $k, $sMasksDllType, $vecMasks, $sStreamDllType, $stream), "cveCudaDescriptorMatcherKnnMatchAsync2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync2

Func _cveCudaDescriptorMatcherKnnMatchAsync2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfMatches, $matches, $k, $masks, $stream)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $oArrMatches, $vectorMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)
    Local $bMatchesCreate = IsDllStruct($matches) And $typeOfMatches == "Scalar"

    If $typeOfMatches == Default Then
        $oArrMatches = $matches
    ElseIf $bMatchesIsArray Then
        $vectorMatches = Call("_VectorOf" & $typeOfMatches & "Create")

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            Call("_VectorOf" & $typeOfMatches & "Push", $vectorMatches, $matches[$i])
        Next

        $oArrMatches = Call("_cveOutputArrayFromVectorOf" & $typeOfMatches, $vectorMatches)
    Else
        If $bMatchesCreate Then
            $matches = Call("_cve" & $typeOfMatches & "Create", $matches)
        EndIf
        $oArrMatches = Call("_cveOutputArrayFrom" & $typeOfMatches, $matches)
    EndIf

    _cveCudaDescriptorMatcherKnnMatchAsync2($matcher, $iArrQueryDescriptors, $oArrMatches, $k, $masks, $stream)

    If $bMatchesIsArray Then
        Call("_VectorOf" & $typeOfMatches & "Release", $vectorMatches)
    EndIf

    If $typeOfMatches <> Default Then
        _cveOutputArrayRelease($oArrMatches)
        If $bMatchesCreate Then
            Call("_cve" & $typeOfMatches & "Release", $matches)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync2Typed

Func _cveCudaDescriptorMatcherKnnMatchAsync2Mat($matcher, $queryDescriptors, $matches, $k, $masks, $stream)
    ; cveCudaDescriptorMatcherKnnMatchAsync2 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherKnnMatchAsync2Typed($matcher, "Mat", $queryDescriptors, "Mat", $matches, $k, $masks, $stream)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync2Mat

Func _cveCudaDescriptorMatcherKnnMatchConvert($matcher, $gpuMatches, $matches, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatchConvert(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* gpuMatches, std::vector<std::vector<cv::DMatch>>* matches, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sGpuMatchesDllType
    If IsDllStruct($gpuMatches) Then
        $sGpuMatchesDllType = "struct*"
    Else
        $sGpuMatchesDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatchConvert", $sMatcherDllType, $matcher, $sGpuMatchesDllType, $gpuMatches, $sMatchesDllType, $vecMatches, "boolean", $compactResult), "cveCudaDescriptorMatcherKnnMatchConvert", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchConvert

Func _cveCudaDescriptorMatcherKnnMatchConvertTyped($matcher, $typeOfGpuMatches, $gpuMatches, $matches, $compactResult)

    Local $iArrGpuMatches, $vectorGpuMatches, $iArrGpuMatchesSize
    Local $bGpuMatchesIsArray = IsArray($gpuMatches)
    Local $bGpuMatchesCreate = IsDllStruct($gpuMatches) And $typeOfGpuMatches == "Scalar"

    If $typeOfGpuMatches == Default Then
        $iArrGpuMatches = $gpuMatches
    ElseIf $bGpuMatchesIsArray Then
        $vectorGpuMatches = Call("_VectorOf" & $typeOfGpuMatches & "Create")

        $iArrGpuMatchesSize = UBound($gpuMatches)
        For $i = 0 To $iArrGpuMatchesSize - 1
            Call("_VectorOf" & $typeOfGpuMatches & "Push", $vectorGpuMatches, $gpuMatches[$i])
        Next

        $iArrGpuMatches = Call("_cveInputArrayFromVectorOf" & $typeOfGpuMatches, $vectorGpuMatches)
    Else
        If $bGpuMatchesCreate Then
            $gpuMatches = Call("_cve" & $typeOfGpuMatches & "Create", $gpuMatches)
        EndIf
        $iArrGpuMatches = Call("_cveInputArrayFrom" & $typeOfGpuMatches, $gpuMatches)
    EndIf

    _cveCudaDescriptorMatcherKnnMatchConvert($matcher, $iArrGpuMatches, $matches, $compactResult)

    If $bGpuMatchesIsArray Then
        Call("_VectorOf" & $typeOfGpuMatches & "Release", $vectorGpuMatches)
    EndIf

    If $typeOfGpuMatches <> Default Then
        _cveInputArrayRelease($iArrGpuMatches)
        If $bGpuMatchesCreate Then
            Call("_cve" & $typeOfGpuMatches & "Release", $gpuMatches)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchConvertTyped

Func _cveCudaDescriptorMatcherKnnMatchConvertMat($matcher, $gpuMatches, $matches, $compactResult)
    ; cveCudaDescriptorMatcherKnnMatchConvert using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherKnnMatchConvertTyped($matcher, "Mat", $gpuMatches, $matches, $compactResult)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchConvertMat

Func _cveCudaDescriptorMatcherRadiusMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatch1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector<std::vector<cv::DMatch>>* matches, float maxDistance, cv::_InputArray* mask, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatch1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $vecMatches, "float", $maxDistance, $sMaskDllType, $mask, "boolean", $compactResult), "cveCudaDescriptorMatcherRadiusMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch1

Func _cveCudaDescriptorMatcherRadiusMatch1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $matches, $maxDistance, $typeOfMask, $mask, $compactResult)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
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

    _cveCudaDescriptorMatcherRadiusMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $maxDistance, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch1Typed

Func _cveCudaDescriptorMatcherRadiusMatch1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $compactResult)
    ; cveCudaDescriptorMatcherRadiusMatch1 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherRadiusMatch1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, $matches, $maxDistance, "Mat", $mask, $compactResult)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch1Mat

Func _cveCudaDescriptorMatcherRadiusMatch2($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatch2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector<std::vector<cv::DMatch>>* matches, float maxDistance, std::vector<cv::cuda::GpuMat>* masks, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatch2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $vecMatches, "float", $maxDistance, $sMasksDllType, $vecMasks, "boolean", $compactResult), "cveCudaDescriptorMatcherRadiusMatch2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch2

Func _cveCudaDescriptorMatcherRadiusMatch2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatch2($matcher, $iArrQueryDescriptors, $matches, $maxDistance, $masks, $compactResult)

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch2Typed

Func _cveCudaDescriptorMatcherRadiusMatch2Mat($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)
    ; cveCudaDescriptorMatcherRadiusMatch2 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherRadiusMatch2Typed($matcher, "Mat", $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch2Mat

Func _cveCudaDescriptorMatcherRadiusMatchAsync1($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatchAsync1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, cv::_OutputArray* matches, float maxDistance, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sTrainDescriptorsDllType
    If IsDllStruct($trainDescriptors) Then
        $sTrainDescriptorsDllType = "struct*"
    Else
        $sTrainDescriptorsDllType = "ptr"
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatchAsync1", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sTrainDescriptorsDllType, $trainDescriptors, $sMatchesDllType, $matches, "float", $maxDistance, $sMaskDllType, $mask, $sStreamDllType, $stream), "cveCudaDescriptorMatcherRadiusMatchAsync1", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync1

Func _cveCudaDescriptorMatcherRadiusMatchAsync1Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfTrainDescriptors, $trainDescriptors, $typeOfMatches, $matches, $maxDistance, $typeOfMask, $mask, $stream)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = IsArray($trainDescriptors)
    Local $bTrainDescriptorsCreate = IsDllStruct($trainDescriptors) And $typeOfTrainDescriptors == "Scalar"

    If $typeOfTrainDescriptors == Default Then
        $iArrTrainDescriptors = $trainDescriptors
    ElseIf $bTrainDescriptorsIsArray Then
        $vectorTrainDescriptors = Call("_VectorOf" & $typeOfTrainDescriptors & "Create")

        $iArrTrainDescriptorsSize = UBound($trainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            Call("_VectorOf" & $typeOfTrainDescriptors & "Push", $vectorTrainDescriptors, $trainDescriptors[$i])
        Next

        $iArrTrainDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfTrainDescriptors, $vectorTrainDescriptors)
    Else
        If $bTrainDescriptorsCreate Then
            $trainDescriptors = Call("_cve" & $typeOfTrainDescriptors & "Create", $trainDescriptors)
        EndIf
        $iArrTrainDescriptors = Call("_cveInputArrayFrom" & $typeOfTrainDescriptors, $trainDescriptors)
    EndIf

    Local $oArrMatches, $vectorMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)
    Local $bMatchesCreate = IsDllStruct($matches) And $typeOfMatches == "Scalar"

    If $typeOfMatches == Default Then
        $oArrMatches = $matches
    ElseIf $bMatchesIsArray Then
        $vectorMatches = Call("_VectorOf" & $typeOfMatches & "Create")

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            Call("_VectorOf" & $typeOfMatches & "Push", $vectorMatches, $matches[$i])
        Next

        $oArrMatches = Call("_cveOutputArrayFromVectorOf" & $typeOfMatches, $vectorMatches)
    Else
        If $bMatchesCreate Then
            $matches = Call("_cve" & $typeOfMatches & "Create", $matches)
        EndIf
        $oArrMatches = Call("_cveOutputArrayFrom" & $typeOfMatches, $matches)
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

    _cveCudaDescriptorMatcherRadiusMatchAsync1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $oArrMatches, $maxDistance, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bMatchesIsArray Then
        Call("_VectorOf" & $typeOfMatches & "Release", $vectorMatches)
    EndIf

    If $typeOfMatches <> Default Then
        _cveOutputArrayRelease($oArrMatches)
        If $bMatchesCreate Then
            Call("_cve" & $typeOfMatches & "Release", $matches)
        EndIf
    EndIf

    If $bTrainDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfTrainDescriptors & "Release", $vectorTrainDescriptors)
    EndIf

    If $typeOfTrainDescriptors <> Default Then
        _cveInputArrayRelease($iArrTrainDescriptors)
        If $bTrainDescriptorsCreate Then
            Call("_cve" & $typeOfTrainDescriptors & "Release", $trainDescriptors)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync1Typed

Func _cveCudaDescriptorMatcherRadiusMatchAsync1Mat($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $stream)
    ; cveCudaDescriptorMatcherRadiusMatchAsync1 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherRadiusMatchAsync1Typed($matcher, "Mat", $queryDescriptors, "Mat", $trainDescriptors, "Mat", $matches, $maxDistance, "Mat", $mask, $stream)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync1Mat

Func _cveCudaDescriptorMatcherRadiusMatchAsync2($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatchAsync2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_OutputArray* matches, float maxDistance, std::vector<cv::cuda::GpuMat>* masks, cv::cuda::Stream* stream);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sQueryDescriptorsDllType
    If IsDllStruct($queryDescriptors) Then
        $sQueryDescriptorsDllType = "struct*"
    Else
        $sQueryDescriptorsDllType = "ptr"
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = IsArray($masks)

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    Local $sMasksDllType
    If IsDllStruct($masks) Then
        $sMasksDllType = "struct*"
    Else
        $sMasksDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatchAsync2", $sMatcherDllType, $matcher, $sQueryDescriptorsDllType, $queryDescriptors, $sMatchesDllType, $matches, "float", $maxDistance, $sMasksDllType, $vecMasks, $sStreamDllType, $stream), "cveCudaDescriptorMatcherRadiusMatchAsync2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync2

Func _cveCudaDescriptorMatcherRadiusMatchAsync2Typed($matcher, $typeOfQueryDescriptors, $queryDescriptors, $typeOfMatches, $matches, $maxDistance, $masks, $stream)

    Local $iArrQueryDescriptors, $vectorQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = IsArray($queryDescriptors)
    Local $bQueryDescriptorsCreate = IsDllStruct($queryDescriptors) And $typeOfQueryDescriptors == "Scalar"

    If $typeOfQueryDescriptors == Default Then
        $iArrQueryDescriptors = $queryDescriptors
    ElseIf $bQueryDescriptorsIsArray Then
        $vectorQueryDescriptors = Call("_VectorOf" & $typeOfQueryDescriptors & "Create")

        $iArrQueryDescriptorsSize = UBound($queryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            Call("_VectorOf" & $typeOfQueryDescriptors & "Push", $vectorQueryDescriptors, $queryDescriptors[$i])
        Next

        $iArrQueryDescriptors = Call("_cveInputArrayFromVectorOf" & $typeOfQueryDescriptors, $vectorQueryDescriptors)
    Else
        If $bQueryDescriptorsCreate Then
            $queryDescriptors = Call("_cve" & $typeOfQueryDescriptors & "Create", $queryDescriptors)
        EndIf
        $iArrQueryDescriptors = Call("_cveInputArrayFrom" & $typeOfQueryDescriptors, $queryDescriptors)
    EndIf

    Local $oArrMatches, $vectorMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)
    Local $bMatchesCreate = IsDllStruct($matches) And $typeOfMatches == "Scalar"

    If $typeOfMatches == Default Then
        $oArrMatches = $matches
    ElseIf $bMatchesIsArray Then
        $vectorMatches = Call("_VectorOf" & $typeOfMatches & "Create")

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            Call("_VectorOf" & $typeOfMatches & "Push", $vectorMatches, $matches[$i])
        Next

        $oArrMatches = Call("_cveOutputArrayFromVectorOf" & $typeOfMatches, $vectorMatches)
    Else
        If $bMatchesCreate Then
            $matches = Call("_cve" & $typeOfMatches & "Create", $matches)
        EndIf
        $oArrMatches = Call("_cveOutputArrayFrom" & $typeOfMatches, $matches)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatchAsync2($matcher, $iArrQueryDescriptors, $oArrMatches, $maxDistance, $masks, $stream)

    If $bMatchesIsArray Then
        Call("_VectorOf" & $typeOfMatches & "Release", $vectorMatches)
    EndIf

    If $typeOfMatches <> Default Then
        _cveOutputArrayRelease($oArrMatches)
        If $bMatchesCreate Then
            Call("_cve" & $typeOfMatches & "Release", $matches)
        EndIf
    EndIf

    If $bQueryDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfQueryDescriptors & "Release", $vectorQueryDescriptors)
    EndIf

    If $typeOfQueryDescriptors <> Default Then
        _cveInputArrayRelease($iArrQueryDescriptors)
        If $bQueryDescriptorsCreate Then
            Call("_cve" & $typeOfQueryDescriptors & "Release", $queryDescriptors)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync2Typed

Func _cveCudaDescriptorMatcherRadiusMatchAsync2Mat($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $stream)
    ; cveCudaDescriptorMatcherRadiusMatchAsync2 using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherRadiusMatchAsync2Typed($matcher, "Mat", $queryDescriptors, "Mat", $matches, $maxDistance, $masks, $stream)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync2Mat

Func _cveCudaDescriptorMatcherRadiusMatchConvert($matcher, $gpu_matches, $matches, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatchConvert(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* gpu_matches, std::vector<std::vector<cv::DMatch>>* matches, bool compactResult);

    Local $sMatcherDllType
    If IsDllStruct($matcher) Then
        $sMatcherDllType = "struct*"
    Else
        $sMatcherDllType = "ptr"
    EndIf

    Local $sGpu_matchesDllType
    If IsDllStruct($gpu_matches) Then
        $sGpu_matchesDllType = "struct*"
    Else
        $sGpu_matchesDllType = "ptr"
    EndIf

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = IsArray($matches)

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $sMatchesDllType
    If IsDllStruct($matches) Then
        $sMatchesDllType = "struct*"
    Else
        $sMatchesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatchConvert", $sMatcherDllType, $matcher, $sGpu_matchesDllType, $gpu_matches, $sMatchesDllType, $vecMatches, "boolean", $compactResult), "cveCudaDescriptorMatcherRadiusMatchConvert", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchConvert

Func _cveCudaDescriptorMatcherRadiusMatchConvertTyped($matcher, $typeOfGpu_matches, $gpu_matches, $matches, $compactResult)

    Local $iArrGpu_matches, $vectorGpu_matches, $iArrGpu_matchesSize
    Local $bGpu_matchesIsArray = IsArray($gpu_matches)
    Local $bGpu_matchesCreate = IsDllStruct($gpu_matches) And $typeOfGpu_matches == "Scalar"

    If $typeOfGpu_matches == Default Then
        $iArrGpu_matches = $gpu_matches
    ElseIf $bGpu_matchesIsArray Then
        $vectorGpu_matches = Call("_VectorOf" & $typeOfGpu_matches & "Create")

        $iArrGpu_matchesSize = UBound($gpu_matches)
        For $i = 0 To $iArrGpu_matchesSize - 1
            Call("_VectorOf" & $typeOfGpu_matches & "Push", $vectorGpu_matches, $gpu_matches[$i])
        Next

        $iArrGpu_matches = Call("_cveInputArrayFromVectorOf" & $typeOfGpu_matches, $vectorGpu_matches)
    Else
        If $bGpu_matchesCreate Then
            $gpu_matches = Call("_cve" & $typeOfGpu_matches & "Create", $gpu_matches)
        EndIf
        $iArrGpu_matches = Call("_cveInputArrayFrom" & $typeOfGpu_matches, $gpu_matches)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatchConvert($matcher, $iArrGpu_matches, $matches, $compactResult)

    If $bGpu_matchesIsArray Then
        Call("_VectorOf" & $typeOfGpu_matches & "Release", $vectorGpu_matches)
    EndIf

    If $typeOfGpu_matches <> Default Then
        _cveInputArrayRelease($iArrGpu_matches)
        If $bGpu_matchesCreate Then
            Call("_cve" & $typeOfGpu_matches & "Release", $gpu_matches)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchConvertTyped

Func _cveCudaDescriptorMatcherRadiusMatchConvertMat($matcher, $gpu_matches, $matches, $compactResult)
    ; cveCudaDescriptorMatcherRadiusMatchConvert using cv::Mat instead of _*Array
    _cveCudaDescriptorMatcherRadiusMatchConvertTyped($matcher, "Mat", $gpu_matches, $matches, $compactResult)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchConvertMat

Func _cveCudaFeature2dAsyncDetectAsync($feature2d, $image, $keypoints, $mask, $stream)
    ; CVAPI(void) cveCudaFeature2dAsyncDetectAsync(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* image, cv::_OutputArray* keypoints, cv::_InputArray* mask, cv::cuda::Stream* stream);

    Local $sFeature2dDllType
    If IsDllStruct($feature2d) Then
        $sFeature2dDllType = "struct*"
    Else
        $sFeature2dDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncDetectAsync", $sFeature2dDllType, $feature2d, $sImageDllType, $image, $sKeypointsDllType, $keypoints, $sMaskDllType, $mask, $sStreamDllType, $stream), "cveCudaFeature2dAsyncDetectAsync", @error)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAsync

Func _cveCudaFeature2dAsyncDetectAsyncTyped($feature2d, $typeOfImage, $image, $typeOfKeypoints, $keypoints, $typeOfMask, $mask, $stream)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $oArrKeypoints, $vectorKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)
    Local $bKeypointsCreate = IsDllStruct($keypoints) And $typeOfKeypoints == "Scalar"

    If $typeOfKeypoints == Default Then
        $oArrKeypoints = $keypoints
    ElseIf $bKeypointsIsArray Then
        $vectorKeypoints = Call("_VectorOf" & $typeOfKeypoints & "Create")

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            Call("_VectorOf" & $typeOfKeypoints & "Push", $vectorKeypoints, $keypoints[$i])
        Next

        $oArrKeypoints = Call("_cveOutputArrayFromVectorOf" & $typeOfKeypoints, $vectorKeypoints)
    Else
        If $bKeypointsCreate Then
            $keypoints = Call("_cve" & $typeOfKeypoints & "Create", $keypoints)
        EndIf
        $oArrKeypoints = Call("_cveOutputArrayFrom" & $typeOfKeypoints, $keypoints)
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

    _cveCudaFeature2dAsyncDetectAsync($feature2d, $iArrImage, $oArrKeypoints, $iArrMask, $stream)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveInputArrayRelease($iArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bKeypointsIsArray Then
        Call("_VectorOf" & $typeOfKeypoints & "Release", $vectorKeypoints)
    EndIf

    If $typeOfKeypoints <> Default Then
        _cveOutputArrayRelease($oArrKeypoints)
        If $bKeypointsCreate Then
            Call("_cve" & $typeOfKeypoints & "Release", $keypoints)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAsyncTyped

Func _cveCudaFeature2dAsyncDetectAsyncMat($feature2d, $image, $keypoints, $mask, $stream)
    ; cveCudaFeature2dAsyncDetectAsync using cv::Mat instead of _*Array
    _cveCudaFeature2dAsyncDetectAsyncTyped($feature2d, "Mat", $image, "Mat", $keypoints, "Mat", $mask, $stream)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAsyncMat

Func _cveCudaFeature2dAsyncComputeAsync($feature2d, $image, $keypoints, $descriptors, $stream)
    ; CVAPI(void) cveCudaFeature2dAsyncComputeAsync(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* image, cv::_OutputArray* keypoints, cv::_OutputArray* descriptors, cv::cuda::Stream* stream);

    Local $sFeature2dDllType
    If IsDllStruct($feature2d) Then
        $sFeature2dDllType = "struct*"
    Else
        $sFeature2dDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sDescriptorsDllType
    If IsDllStruct($descriptors) Then
        $sDescriptorsDllType = "struct*"
    Else
        $sDescriptorsDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncComputeAsync", $sFeature2dDllType, $feature2d, $sImageDllType, $image, $sKeypointsDllType, $keypoints, $sDescriptorsDllType, $descriptors, $sStreamDllType, $stream), "cveCudaFeature2dAsyncComputeAsync", @error)
EndFunc   ;==>_cveCudaFeature2dAsyncComputeAsync

Func _cveCudaFeature2dAsyncComputeAsyncTyped($feature2d, $typeOfImage, $image, $typeOfKeypoints, $keypoints, $typeOfDescriptors, $descriptors, $stream)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $oArrKeypoints, $vectorKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)
    Local $bKeypointsCreate = IsDllStruct($keypoints) And $typeOfKeypoints == "Scalar"

    If $typeOfKeypoints == Default Then
        $oArrKeypoints = $keypoints
    ElseIf $bKeypointsIsArray Then
        $vectorKeypoints = Call("_VectorOf" & $typeOfKeypoints & "Create")

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            Call("_VectorOf" & $typeOfKeypoints & "Push", $vectorKeypoints, $keypoints[$i])
        Next

        $oArrKeypoints = Call("_cveOutputArrayFromVectorOf" & $typeOfKeypoints, $vectorKeypoints)
    Else
        If $bKeypointsCreate Then
            $keypoints = Call("_cve" & $typeOfKeypoints & "Create", $keypoints)
        EndIf
        $oArrKeypoints = Call("_cveOutputArrayFrom" & $typeOfKeypoints, $keypoints)
    EndIf

    Local $oArrDescriptors, $vectorDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = IsArray($descriptors)
    Local $bDescriptorsCreate = IsDllStruct($descriptors) And $typeOfDescriptors == "Scalar"

    If $typeOfDescriptors == Default Then
        $oArrDescriptors = $descriptors
    ElseIf $bDescriptorsIsArray Then
        $vectorDescriptors = Call("_VectorOf" & $typeOfDescriptors & "Create")

        $iArrDescriptorsSize = UBound($descriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            Call("_VectorOf" & $typeOfDescriptors & "Push", $vectorDescriptors, $descriptors[$i])
        Next

        $oArrDescriptors = Call("_cveOutputArrayFromVectorOf" & $typeOfDescriptors, $vectorDescriptors)
    Else
        If $bDescriptorsCreate Then
            $descriptors = Call("_cve" & $typeOfDescriptors & "Create", $descriptors)
        EndIf
        $oArrDescriptors = Call("_cveOutputArrayFrom" & $typeOfDescriptors, $descriptors)
    EndIf

    _cveCudaFeature2dAsyncComputeAsync($feature2d, $iArrImage, $oArrKeypoints, $oArrDescriptors, $stream)

    If $bDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfDescriptors & "Release", $vectorDescriptors)
    EndIf

    If $typeOfDescriptors <> Default Then
        _cveOutputArrayRelease($oArrDescriptors)
        If $bDescriptorsCreate Then
            Call("_cve" & $typeOfDescriptors & "Release", $descriptors)
        EndIf
    EndIf

    If $bKeypointsIsArray Then
        Call("_VectorOf" & $typeOfKeypoints & "Release", $vectorKeypoints)
    EndIf

    If $typeOfKeypoints <> Default Then
        _cveOutputArrayRelease($oArrKeypoints)
        If $bKeypointsCreate Then
            Call("_cve" & $typeOfKeypoints & "Release", $keypoints)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaFeature2dAsyncComputeAsyncTyped

Func _cveCudaFeature2dAsyncComputeAsyncMat($feature2d, $image, $keypoints, $descriptors, $stream)
    ; cveCudaFeature2dAsyncComputeAsync using cv::Mat instead of _*Array
    _cveCudaFeature2dAsyncComputeAsyncTyped($feature2d, "Mat", $image, "Mat", $keypoints, "Mat", $descriptors, $stream)
EndFunc   ;==>_cveCudaFeature2dAsyncComputeAsyncMat

Func _cveCudaFeature2dAsyncDetectAndComputeAsync($feature2d, $image, $mask, $keypoints, $descriptors, $useProvidedKeypoints, $stream)
    ; CVAPI(void) cveCudaFeature2dAsyncDetectAndComputeAsync(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* image, cv::_InputArray* mask, cv::_OutputArray* keypoints, cv::_OutputArray* descriptors, bool useProvidedKeypoints, cv::cuda::Stream* stream);

    Local $sFeature2dDllType
    If IsDllStruct($feature2d) Then
        $sFeature2dDllType = "struct*"
    Else
        $sFeature2dDllType = "ptr"
    EndIf

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    Local $sDescriptorsDllType
    If IsDllStruct($descriptors) Then
        $sDescriptorsDllType = "struct*"
    Else
        $sDescriptorsDllType = "ptr"
    EndIf

    Local $sStreamDllType
    If IsDllStruct($stream) Then
        $sStreamDllType = "struct*"
    Else
        $sStreamDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncDetectAndComputeAsync", $sFeature2dDllType, $feature2d, $sImageDllType, $image, $sMaskDllType, $mask, $sKeypointsDllType, $keypoints, $sDescriptorsDllType, $descriptors, "boolean", $useProvidedKeypoints, $sStreamDllType, $stream), "cveCudaFeature2dAsyncDetectAndComputeAsync", @error)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAndComputeAsync

Func _cveCudaFeature2dAsyncDetectAndComputeAsyncTyped($feature2d, $typeOfImage, $image, $typeOfMask, $mask, $typeOfKeypoints, $keypoints, $typeOfDescriptors, $descriptors, $useProvidedKeypoints, $stream)

    Local $iArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $iArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $iArrImage = Call("_cveInputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $iArrImage = Call("_cveInputArrayFrom" & $typeOfImage, $image)
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

    Local $oArrKeypoints, $vectorKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)
    Local $bKeypointsCreate = IsDllStruct($keypoints) And $typeOfKeypoints == "Scalar"

    If $typeOfKeypoints == Default Then
        $oArrKeypoints = $keypoints
    ElseIf $bKeypointsIsArray Then
        $vectorKeypoints = Call("_VectorOf" & $typeOfKeypoints & "Create")

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            Call("_VectorOf" & $typeOfKeypoints & "Push", $vectorKeypoints, $keypoints[$i])
        Next

        $oArrKeypoints = Call("_cveOutputArrayFromVectorOf" & $typeOfKeypoints, $vectorKeypoints)
    Else
        If $bKeypointsCreate Then
            $keypoints = Call("_cve" & $typeOfKeypoints & "Create", $keypoints)
        EndIf
        $oArrKeypoints = Call("_cveOutputArrayFrom" & $typeOfKeypoints, $keypoints)
    EndIf

    Local $oArrDescriptors, $vectorDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = IsArray($descriptors)
    Local $bDescriptorsCreate = IsDllStruct($descriptors) And $typeOfDescriptors == "Scalar"

    If $typeOfDescriptors == Default Then
        $oArrDescriptors = $descriptors
    ElseIf $bDescriptorsIsArray Then
        $vectorDescriptors = Call("_VectorOf" & $typeOfDescriptors & "Create")

        $iArrDescriptorsSize = UBound($descriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            Call("_VectorOf" & $typeOfDescriptors & "Push", $vectorDescriptors, $descriptors[$i])
        Next

        $oArrDescriptors = Call("_cveOutputArrayFromVectorOf" & $typeOfDescriptors, $vectorDescriptors)
    Else
        If $bDescriptorsCreate Then
            $descriptors = Call("_cve" & $typeOfDescriptors & "Create", $descriptors)
        EndIf
        $oArrDescriptors = Call("_cveOutputArrayFrom" & $typeOfDescriptors, $descriptors)
    EndIf

    _cveCudaFeature2dAsyncDetectAndComputeAsync($feature2d, $iArrImage, $iArrMask, $oArrKeypoints, $oArrDescriptors, $useProvidedKeypoints, $stream)

    If $bDescriptorsIsArray Then
        Call("_VectorOf" & $typeOfDescriptors & "Release", $vectorDescriptors)
    EndIf

    If $typeOfDescriptors <> Default Then
        _cveOutputArrayRelease($oArrDescriptors)
        If $bDescriptorsCreate Then
            Call("_cve" & $typeOfDescriptors & "Release", $descriptors)
        EndIf
    EndIf

    If $bKeypointsIsArray Then
        Call("_VectorOf" & $typeOfKeypoints & "Release", $vectorKeypoints)
    EndIf

    If $typeOfKeypoints <> Default Then
        _cveOutputArrayRelease($oArrKeypoints)
        If $bKeypointsCreate Then
            Call("_cve" & $typeOfKeypoints & "Release", $keypoints)
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

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputArrayRelease($iArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAndComputeAsyncTyped

Func _cveCudaFeature2dAsyncDetectAndComputeAsyncMat($feature2d, $image, $mask, $keypoints, $descriptors, $useProvidedKeypoints, $stream)
    ; cveCudaFeature2dAsyncDetectAndComputeAsync using cv::Mat instead of _*Array
    _cveCudaFeature2dAsyncDetectAndComputeAsyncTyped($feature2d, "Mat", $image, "Mat", $mask, "Mat", $keypoints, "Mat", $descriptors, $useProvidedKeypoints, $stream)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAndComputeAsyncMat

Func _cveCudaFeature2dAsyncConvert($feature2d, $gpu_keypoints, $keypoints)
    ; CVAPI(void) cveCudaFeature2dAsyncConvert(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* gpu_keypoints, std::vector<cv::KeyPoint>* keypoints);

    Local $sFeature2dDllType
    If IsDllStruct($feature2d) Then
        $sFeature2dDllType = "struct*"
    Else
        $sFeature2dDllType = "ptr"
    EndIf

    Local $sGpu_keypointsDllType
    If IsDllStruct($gpu_keypoints) Then
        $sGpu_keypointsDllType = "struct*"
    Else
        $sGpu_keypointsDllType = "ptr"
    EndIf

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = IsArray($keypoints)

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    Local $sKeypointsDllType
    If IsDllStruct($keypoints) Then
        $sKeypointsDllType = "struct*"
    Else
        $sKeypointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncConvert", $sFeature2dDllType, $feature2d, $sGpu_keypointsDllType, $gpu_keypoints, $sKeypointsDllType, $vecKeypoints), "cveCudaFeature2dAsyncConvert", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveCudaFeature2dAsyncConvert

Func _cveCudaFeature2dAsyncConvertTyped($feature2d, $typeOfGpu_keypoints, $gpu_keypoints, $keypoints)

    Local $iArrGpu_keypoints, $vectorGpu_keypoints, $iArrGpu_keypointsSize
    Local $bGpu_keypointsIsArray = IsArray($gpu_keypoints)
    Local $bGpu_keypointsCreate = IsDllStruct($gpu_keypoints) And $typeOfGpu_keypoints == "Scalar"

    If $typeOfGpu_keypoints == Default Then
        $iArrGpu_keypoints = $gpu_keypoints
    ElseIf $bGpu_keypointsIsArray Then
        $vectorGpu_keypoints = Call("_VectorOf" & $typeOfGpu_keypoints & "Create")

        $iArrGpu_keypointsSize = UBound($gpu_keypoints)
        For $i = 0 To $iArrGpu_keypointsSize - 1
            Call("_VectorOf" & $typeOfGpu_keypoints & "Push", $vectorGpu_keypoints, $gpu_keypoints[$i])
        Next

        $iArrGpu_keypoints = Call("_cveInputArrayFromVectorOf" & $typeOfGpu_keypoints, $vectorGpu_keypoints)
    Else
        If $bGpu_keypointsCreate Then
            $gpu_keypoints = Call("_cve" & $typeOfGpu_keypoints & "Create", $gpu_keypoints)
        EndIf
        $iArrGpu_keypoints = Call("_cveInputArrayFrom" & $typeOfGpu_keypoints, $gpu_keypoints)
    EndIf

    _cveCudaFeature2dAsyncConvert($feature2d, $iArrGpu_keypoints, $keypoints)

    If $bGpu_keypointsIsArray Then
        Call("_VectorOf" & $typeOfGpu_keypoints & "Release", $vectorGpu_keypoints)
    EndIf

    If $typeOfGpu_keypoints <> Default Then
        _cveInputArrayRelease($iArrGpu_keypoints)
        If $bGpu_keypointsCreate Then
            Call("_cve" & $typeOfGpu_keypoints & "Release", $gpu_keypoints)
        EndIf
    EndIf
EndFunc   ;==>_cveCudaFeature2dAsyncConvertTyped

Func _cveCudaFeature2dAsyncConvertMat($feature2d, $gpu_keypoints, $keypoints)
    ; cveCudaFeature2dAsyncConvert using cv::Mat instead of _*Array
    _cveCudaFeature2dAsyncConvertTyped($feature2d, "Mat", $gpu_keypoints, $keypoints)
EndFunc   ;==>_cveCudaFeature2dAsyncConvertMat

Func _cveCudaFastFeatureDetectorCreate($threshold, $nonmaxSupression, $type, $maxPoints, $feature2D, $feature2dAsync, $sharedPtr)
    ; CVAPI(cv::cuda::FastFeatureDetector*) cveCudaFastFeatureDetectorCreate(int threshold, bool nonmaxSupression, int type, int maxPoints, cv::Feature2D** feature2D, cv::cuda::Feature2DAsync** feature2dAsync, cv::Ptr<cv::cuda::FastFeatureDetector>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sFeature2dAsyncDllType
    If IsDllStruct($feature2dAsync) Then
        $sFeature2dAsyncDllType = "struct*"
    ElseIf $feature2dAsync == Null Then
        $sFeature2dAsyncDllType = "ptr"
    Else
        $sFeature2dAsyncDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCudaFastFeatureDetectorCreate", "int", $threshold, "boolean", $nonmaxSupression, "int", $type, "int", $maxPoints, $sFeature2DDllType, $feature2D, $sFeature2dAsyncDllType, $feature2dAsync, $sSharedPtrDllType, $sharedPtr), "cveCudaFastFeatureDetectorCreate", @error)
EndFunc   ;==>_cveCudaFastFeatureDetectorCreate

Func _cveCudaFastFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveCudaFastFeatureDetectorRelease(cv::Ptr<cv::cuda::FastFeatureDetector>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFastFeatureDetectorRelease", $sSharedPtrDllType, $sharedPtr), "cveCudaFastFeatureDetectorRelease", @error)
EndFunc   ;==>_cveCudaFastFeatureDetectorRelease

Func _cveCudaORBCreate($numberOfFeatures, $scaleFactor, $nLevels, $edgeThreshold, $firstLevel, $WTA_K, $scoreType, $patchSize, $fastThreshold, $blurForDescriptor, $feature2D, $feature2dAsync, $sharedPtr)
    ; CVAPI(cv::cuda::ORB*) cveCudaORBCreate(int numberOfFeatures, float scaleFactor, int nLevels, int edgeThreshold, int firstLevel, int WTA_K, int scoreType, int patchSize, int fastThreshold, bool blurForDescriptor, cv::Feature2D** feature2D, cv::cuda::Feature2DAsync** feature2dAsync, cv::Ptr<cv::cuda::ORB>** sharedPtr);

    Local $sFeature2DDllType
    If IsDllStruct($feature2D) Then
        $sFeature2DDllType = "struct*"
    ElseIf $feature2D == Null Then
        $sFeature2DDllType = "ptr"
    Else
        $sFeature2DDllType = "ptr*"
    EndIf

    Local $sFeature2dAsyncDllType
    If IsDllStruct($feature2dAsync) Then
        $sFeature2dAsyncDllType = "struct*"
    ElseIf $feature2dAsync == Null Then
        $sFeature2dAsyncDllType = "ptr"
    Else
        $sFeature2dAsyncDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCudaORBCreate", "int", $numberOfFeatures, "float", $scaleFactor, "int", $nLevels, "int", $edgeThreshold, "int", $firstLevel, "int", $WTA_K, "int", $scoreType, "int", $patchSize, "int", $fastThreshold, "boolean", $blurForDescriptor, $sFeature2DDllType, $feature2D, $sFeature2dAsyncDllType, $feature2dAsync, $sSharedPtrDllType, $sharedPtr), "cveCudaORBCreate", @error)
EndFunc   ;==>_cveCudaORBCreate

Func _cveCudaORBRelease($sharedPtr)
    ; CVAPI(void) cveCudaORBRelease(cv::Ptr<cv::cuda::ORB>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaORBRelease", $sSharedPtrDllType, $sharedPtr), "cveCudaORBRelease", @error)
EndFunc   ;==>_cveCudaORBRelease