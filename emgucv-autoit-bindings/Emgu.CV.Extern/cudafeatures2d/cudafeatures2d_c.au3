#include-once
#include "..\..\CVEUtils.au3"

Func _cveCudaDescriptorMatcherCreateBFMatcher($distType, $algorithm, $sharedPtr)
    ; CVAPI(cv::cuda::DescriptorMatcher*) cveCudaDescriptorMatcherCreateBFMatcher(int distType, cv::Algorithm** algorithm, cv::Ptr<cv::cuda::DescriptorMatcher>** sharedPtr);

    Local $bAlgorithmDllType
    If VarGetType($algorithm) == "DLLStruct" Then
        $bAlgorithmDllType = "struct*"
    Else
        $bAlgorithmDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCudaDescriptorMatcherCreateBFMatcher", "int", $distType, $bAlgorithmDllType, $algorithm, $bSharedPtrDllType, $sharedPtr), "cveCudaDescriptorMatcherCreateBFMatcher", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherCreateBFMatcher

Func _cveCudaDescriptorMatcherRelease($sharedPtr)
    ; CVAPI(void) cveCudaDescriptorMatcherRelease(cv::Ptr<cv::cuda::DescriptorMatcher>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRelease", $bSharedPtrDllType, $sharedPtr), "cveCudaDescriptorMatcherRelease", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherRelease

Func _cveCudaDescriptorMatcherAdd($matcher, $trainDescs)
    ; CVAPI(void) cveCudaDescriptorMatcherAdd(cv::cuda::DescriptorMatcher* matcher, const std::vector<cv::cuda::GpuMat>* trainDescs);

    Local $vecTrainDescs, $iArrTrainDescsSize
    Local $bTrainDescsIsArray = VarGetType($trainDescs) == "Array"

    If $bTrainDescsIsArray Then
        $vecTrainDescs = _VectorOfGpuMatCreate()

        $iArrTrainDescsSize = UBound($trainDescs)
        For $i = 0 To $iArrTrainDescsSize - 1
            _VectorOfGpuMatPush($vecTrainDescs, $trainDescs[$i])
        Next
    Else
        $vecTrainDescs = $trainDescs
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherAdd", "ptr", $matcher, "ptr", $vecTrainDescs), "cveCudaDescriptorMatcherAdd", @error)

    If $bTrainDescsIsArray Then
        _VectorOfGpuMatRelease($vecTrainDescs)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherAdd

Func _cveCudaDescriptorMatcherIsMaskSupported($matcher)
    ; CVAPI(bool) cveCudaDescriptorMatcherIsMaskSupported(cv::cuda::DescriptorMatcher* matcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaDescriptorMatcherIsMaskSupported", "ptr", $matcher), "cveCudaDescriptorMatcherIsMaskSupported", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherIsMaskSupported

Func _cveCudaDescriptorMatcherClear($matcher)
    ; CVAPI(void) cveCudaDescriptorMatcherClear(cv::cuda::DescriptorMatcher* matcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherClear", "ptr", $matcher), "cveCudaDescriptorMatcherClear", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherClear

Func _cveCudaDescriptorMatcherEmpty($matcher)
    ; CVAPI(bool) cveCudaDescriptorMatcherEmpty(cv::cuda::DescriptorMatcher* matcher);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveCudaDescriptorMatcherEmpty", "ptr", $matcher), "cveCudaDescriptorMatcherEmpty", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherEmpty

Func _cveCudaDescriptorMatcherTrain($matcher)
    ; CVAPI(void) cveCudaDescriptorMatcherTrain(cv::cuda::DescriptorMatcher* matcher);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherTrain", "ptr", $matcher), "cveCudaDescriptorMatcherTrain", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherTrain

Func _cveCudaDescriptorMatcherMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask)
    ; CVAPI(void) cveCudaDescriptorMatcherMatch1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< cv::DMatch >* matches, cv::_InputArray* mask);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatch1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $vecMatches, "ptr", $mask), "cveCudaDescriptorMatcherMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatch1

Func _cveCudaDescriptorMatcherMatch1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matches, $matMask)
    ; cveCudaDescriptorMatcherMatch1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cveCudaDescriptorMatcherMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $iArrMask)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherMatch1Mat

Func _cveCudaDescriptorMatcherMatch2($matcher, $queryDescriptors, $matches, $masks)
    ; CVAPI(void) cveCudaDescriptorMatcherMatch2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< cv::DMatch >* matches, std::vector< cv::cuda::GpuMat >* masks);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($masks) == "Array"

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatch2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $vecMatches, "ptr", $vecMasks), "cveCudaDescriptorMatcherMatch2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatch2

Func _cveCudaDescriptorMatcherMatch2Mat($matcher, $matQueryDescriptors, $matches, $masks)
    ; cveCudaDescriptorMatcherMatch2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    _cveCudaDescriptorMatcherMatch2($matcher, $iArrQueryDescriptors, $matches, $masks)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherMatch2Mat

Func _cveCudaDescriptorMatcherMatchAsync1($matcher, $queryDescriptors, $trainDescriptors, $matches, $mask, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherMatchAsync1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, cv::_OutputArray* matches, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatchAsync1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $matches, "ptr", $mask, "ptr", $stream), "cveCudaDescriptorMatcherMatchAsync1", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync1

Func _cveCudaDescriptorMatcherMatchAsync1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matMatches, $matMask, $stream)
    ; cveCudaDescriptorMatcherMatchAsync1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
    EndIf

    Local $oArrMatches, $vectorOfMatMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matMatches) == "Array"

    If $bMatchesIsArray Then
        $vectorOfMatMatches = _VectorOfMatCreate()

        $iArrMatchesSize = UBound($matMatches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfMatPush($vectorOfMatMatches, $matMatches[$i])
        Next

        $oArrMatches = _cveOutputArrayFromVectorOfMat($vectorOfMatMatches)
    Else
        $oArrMatches = _cveOutputArrayFromMat($matMatches)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cveCudaDescriptorMatcherMatchAsync1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $oArrMatches, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatMatches)
    EndIf

    _cveOutputArrayRelease($oArrMatches)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync1Mat

Func _cveCudaDescriptorMatcherMatchAsync2($matcher, $queryDescriptors, $matches, $masks, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherMatchAsync2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_OutputArray* matches, std::vector< cv::cuda::GpuMat >* masks, cv::cuda::Stream* stream);

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($masks) == "Array"

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatchAsync2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $matches, "ptr", $vecMasks, "ptr", $stream), "cveCudaDescriptorMatcherMatchAsync2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync2

Func _cveCudaDescriptorMatcherMatchAsync2Mat($matcher, $matQueryDescriptors, $matMatches, $masks, $stream)
    ; cveCudaDescriptorMatcherMatchAsync2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $oArrMatches, $vectorOfMatMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matMatches) == "Array"

    If $bMatchesIsArray Then
        $vectorOfMatMatches = _VectorOfMatCreate()

        $iArrMatchesSize = UBound($matMatches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfMatPush($vectorOfMatMatches, $matMatches[$i])
        Next

        $oArrMatches = _cveOutputArrayFromVectorOfMat($vectorOfMatMatches)
    Else
        $oArrMatches = _cveOutputArrayFromMat($matMatches)
    EndIf

    _cveCudaDescriptorMatcherMatchAsync2($matcher, $iArrQueryDescriptors, $oArrMatches, $masks, $stream)

    If $bMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatMatches)
    EndIf

    _cveOutputArrayRelease($oArrMatches)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchAsync2Mat

Func _cveCudaDescriptorMatcherMatchConvert($matcher, $gpuMatches, $matches)
    ; CVAPI(void) cveCudaDescriptorMatcherMatchConvert(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* gpuMatches, std::vector< cv::DMatch >* matches);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherMatchConvert", "ptr", $matcher, "ptr", $gpuMatches, "ptr", $vecMatches), "cveCudaDescriptorMatcherMatchConvert", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherMatchConvert

Func _cveCudaDescriptorMatcherMatchConvertMat($matcher, $matGpuMatches, $matches)
    ; cveCudaDescriptorMatcherMatchConvert using cv::Mat instead of _*Array

    Local $iArrGpuMatches, $vectorOfMatGpuMatches, $iArrGpuMatchesSize
    Local $bGpuMatchesIsArray = VarGetType($matGpuMatches) == "Array"

    If $bGpuMatchesIsArray Then
        $vectorOfMatGpuMatches = _VectorOfMatCreate()

        $iArrGpuMatchesSize = UBound($matGpuMatches)
        For $i = 0 To $iArrGpuMatchesSize - 1
            _VectorOfMatPush($vectorOfMatGpuMatches, $matGpuMatches[$i])
        Next

        $iArrGpuMatches = _cveInputArrayFromVectorOfMat($vectorOfMatGpuMatches)
    Else
        $iArrGpuMatches = _cveInputArrayFromMat($matGpuMatches)
    EndIf

    _cveCudaDescriptorMatcherMatchConvert($matcher, $iArrGpuMatches, $matches)

    If $bGpuMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatGpuMatches)
    EndIf

    _cveInputArrayRelease($iArrGpuMatches)
EndFunc   ;==>_cveCudaDescriptorMatcherMatchConvertMat

Func _cveCudaDescriptorMatcherKnnMatch1($matcher, $queryDescs, $trainDescs, $matches, $k, $masks, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatch1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescs, cv::_InputArray* trainDescs, std::vector< std::vector< cv::DMatch > >* matches, int k, cv::_InputArray* masks, bool compactResult);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatch1", "ptr", $matcher, "ptr", $queryDescs, "ptr", $trainDescs, "ptr", $vecMatches, "int", $k, "ptr", $masks, "boolean", $compactResult), "cveCudaDescriptorMatcherKnnMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch1

Func _cveCudaDescriptorMatcherKnnMatch1Mat($matcher, $matQueryDescs, $matTrainDescs, $matches, $k, $matMasks, $compactResult)
    ; cveCudaDescriptorMatcherKnnMatch1 using cv::Mat instead of _*Array

    Local $iArrQueryDescs, $vectorOfMatQueryDescs, $iArrQueryDescsSize
    Local $bQueryDescsIsArray = VarGetType($matQueryDescs) == "Array"

    If $bQueryDescsIsArray Then
        $vectorOfMatQueryDescs = _VectorOfMatCreate()

        $iArrQueryDescsSize = UBound($matQueryDescs)
        For $i = 0 To $iArrQueryDescsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescs, $matQueryDescs[$i])
        Next

        $iArrQueryDescs = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescs)
    Else
        $iArrQueryDescs = _cveInputArrayFromMat($matQueryDescs)
    EndIf

    Local $iArrTrainDescs, $vectorOfMatTrainDescs, $iArrTrainDescsSize
    Local $bTrainDescsIsArray = VarGetType($matTrainDescs) == "Array"

    If $bTrainDescsIsArray Then
        $vectorOfMatTrainDescs = _VectorOfMatCreate()

        $iArrTrainDescsSize = UBound($matTrainDescs)
        For $i = 0 To $iArrTrainDescsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescs, $matTrainDescs[$i])
        Next

        $iArrTrainDescs = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescs)
    Else
        $iArrTrainDescs = _cveInputArrayFromMat($matTrainDescs)
    EndIf

    Local $iArrMasks, $vectorOfMatMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($matMasks) == "Array"

    If $bMasksIsArray Then
        $vectorOfMatMasks = _VectorOfMatCreate()

        $iArrMasksSize = UBound($matMasks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfMatPush($vectorOfMatMasks, $matMasks[$i])
        Next

        $iArrMasks = _cveInputArrayFromVectorOfMat($vectorOfMatMasks)
    Else
        $iArrMasks = _cveInputArrayFromMat($matMasks)
    EndIf

    _cveCudaDescriptorMatcherKnnMatch1($matcher, $iArrQueryDescs, $iArrTrainDescs, $matches, $k, $iArrMasks, $compactResult)

    If $bMasksIsArray Then
        _VectorOfMatRelease($vectorOfMatMasks)
    EndIf

    _cveInputArrayRelease($iArrMasks)

    If $bTrainDescsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescs)
    EndIf

    _cveInputArrayRelease($iArrTrainDescs)

    If $bQueryDescsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescs)
    EndIf

    _cveInputArrayRelease($iArrQueryDescs)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch1Mat

Func _cveCudaDescriptorMatcherKnnMatch2($matcher, $queryDescriptors, $matches, $k, $masks, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatch2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< std::vector< cv::DMatch > >* matches, int k, std::vector< cv::cuda::GpuMat >* masks, bool compactResult);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($masks) == "Array"

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatch2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $vecMatches, "int", $k, "ptr", $vecMasks, "boolean", $compactResult), "cveCudaDescriptorMatcherKnnMatch2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch2

Func _cveCudaDescriptorMatcherKnnMatch2Mat($matcher, $matQueryDescriptors, $matches, $k, $masks, $compactResult)
    ; cveCudaDescriptorMatcherKnnMatch2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    _cveCudaDescriptorMatcherKnnMatch2($matcher, $iArrQueryDescriptors, $matches, $k, $masks, $compactResult)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatch2Mat

Func _cveCudaDescriptorMatcherKnnMatchAsync1($matcher, $queryDescriptors, $trainDescriptors, $matches, $k, $mask, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatchAsync1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, cv::_OutputArray* matches, int k, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatchAsync1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $matches, "int", $k, "ptr", $mask, "ptr", $stream), "cveCudaDescriptorMatcherKnnMatchAsync1", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync1

Func _cveCudaDescriptorMatcherKnnMatchAsync1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matMatches, $k, $matMask, $stream)
    ; cveCudaDescriptorMatcherKnnMatchAsync1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
    EndIf

    Local $oArrMatches, $vectorOfMatMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matMatches) == "Array"

    If $bMatchesIsArray Then
        $vectorOfMatMatches = _VectorOfMatCreate()

        $iArrMatchesSize = UBound($matMatches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfMatPush($vectorOfMatMatches, $matMatches[$i])
        Next

        $oArrMatches = _cveOutputArrayFromVectorOfMat($vectorOfMatMatches)
    Else
        $oArrMatches = _cveOutputArrayFromMat($matMatches)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cveCudaDescriptorMatcherKnnMatchAsync1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $oArrMatches, $k, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatMatches)
    EndIf

    _cveOutputArrayRelease($oArrMatches)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync1Mat

Func _cveCudaDescriptorMatcherKnnMatchAsync2($matcher, $queryDescriptors, $matches, $k, $masks, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatchAsync2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_OutputArray* matches, int k, std::vector< cv::cuda::GpuMat >* masks, cv::cuda::Stream* stream);

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($masks) == "Array"

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatchAsync2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $matches, "int", $k, "ptr", $vecMasks, "ptr", $stream), "cveCudaDescriptorMatcherKnnMatchAsync2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync2

Func _cveCudaDescriptorMatcherKnnMatchAsync2Mat($matcher, $matQueryDescriptors, $matMatches, $k, $masks, $stream)
    ; cveCudaDescriptorMatcherKnnMatchAsync2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $oArrMatches, $vectorOfMatMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matMatches) == "Array"

    If $bMatchesIsArray Then
        $vectorOfMatMatches = _VectorOfMatCreate()

        $iArrMatchesSize = UBound($matMatches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfMatPush($vectorOfMatMatches, $matMatches[$i])
        Next

        $oArrMatches = _cveOutputArrayFromVectorOfMat($vectorOfMatMatches)
    Else
        $oArrMatches = _cveOutputArrayFromMat($matMatches)
    EndIf

    _cveCudaDescriptorMatcherKnnMatchAsync2($matcher, $iArrQueryDescriptors, $oArrMatches, $k, $masks, $stream)

    If $bMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatMatches)
    EndIf

    _cveOutputArrayRelease($oArrMatches)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchAsync2Mat

Func _cveCudaDescriptorMatcherKnnMatchConvert($matcher, $gpuMatches, $matches, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherKnnMatchConvert(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* gpuMatches, std::vector< std::vector< cv::DMatch > >* matches, bool compactResult);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherKnnMatchConvert", "ptr", $matcher, "ptr", $gpuMatches, "ptr", $vecMatches, "boolean", $compactResult), "cveCudaDescriptorMatcherKnnMatchConvert", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchConvert

Func _cveCudaDescriptorMatcherKnnMatchConvertMat($matcher, $matGpuMatches, $matches, $compactResult)
    ; cveCudaDescriptorMatcherKnnMatchConvert using cv::Mat instead of _*Array

    Local $iArrGpuMatches, $vectorOfMatGpuMatches, $iArrGpuMatchesSize
    Local $bGpuMatchesIsArray = VarGetType($matGpuMatches) == "Array"

    If $bGpuMatchesIsArray Then
        $vectorOfMatGpuMatches = _VectorOfMatCreate()

        $iArrGpuMatchesSize = UBound($matGpuMatches)
        For $i = 0 To $iArrGpuMatchesSize - 1
            _VectorOfMatPush($vectorOfMatGpuMatches, $matGpuMatches[$i])
        Next

        $iArrGpuMatches = _cveInputArrayFromVectorOfMat($vectorOfMatGpuMatches)
    Else
        $iArrGpuMatches = _cveInputArrayFromMat($matGpuMatches)
    EndIf

    _cveCudaDescriptorMatcherKnnMatchConvert($matcher, $iArrGpuMatches, $matches, $compactResult)

    If $bGpuMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatGpuMatches)
    EndIf

    _cveInputArrayRelease($iArrGpuMatches)
EndFunc   ;==>_cveCudaDescriptorMatcherKnnMatchConvertMat

Func _cveCudaDescriptorMatcherRadiusMatch1($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatch1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, std::vector< std::vector< cv::DMatch > >* matches, float maxDistance, cv::_InputArray* mask, bool compactResult);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatch1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $vecMatches, "float", $maxDistance, "ptr", $mask, "boolean", $compactResult), "cveCudaDescriptorMatcherRadiusMatch1", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch1

Func _cveCudaDescriptorMatcherRadiusMatch1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matches, $maxDistance, $matMask, $compactResult)
    ; cveCudaDescriptorMatcherRadiusMatch1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatch1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $matches, $maxDistance, $iArrMask, $compactResult)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch1Mat

Func _cveCudaDescriptorMatcherRadiusMatch2($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatch2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, std::vector< std::vector< cv::DMatch > >* matches, float maxDistance, std::vector< cv::cuda::GpuMat >* masks, bool compactResult);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($masks) == "Array"

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatch2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $vecMatches, "float", $maxDistance, "ptr", $vecMasks, "boolean", $compactResult), "cveCudaDescriptorMatcherRadiusMatch2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch2

Func _cveCudaDescriptorMatcherRadiusMatch2Mat($matcher, $matQueryDescriptors, $matches, $maxDistance, $masks, $compactResult)
    ; cveCudaDescriptorMatcherRadiusMatch2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatch2($matcher, $iArrQueryDescriptors, $matches, $maxDistance, $masks, $compactResult)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatch2Mat

Func _cveCudaDescriptorMatcherRadiusMatchAsync1($matcher, $queryDescriptors, $trainDescriptors, $matches, $maxDistance, $mask, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatchAsync1(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_InputArray* trainDescriptors, cv::_OutputArray* matches, float maxDistance, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatchAsync1", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $trainDescriptors, "ptr", $matches, "float", $maxDistance, "ptr", $mask, "ptr", $stream), "cveCudaDescriptorMatcherRadiusMatchAsync1", @error)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync1

Func _cveCudaDescriptorMatcherRadiusMatchAsync1Mat($matcher, $matQueryDescriptors, $matTrainDescriptors, $matMatches, $maxDistance, $matMask, $stream)
    ; cveCudaDescriptorMatcherRadiusMatchAsync1 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $iArrTrainDescriptors, $vectorOfMatTrainDescriptors, $iArrTrainDescriptorsSize
    Local $bTrainDescriptorsIsArray = VarGetType($matTrainDescriptors) == "Array"

    If $bTrainDescriptorsIsArray Then
        $vectorOfMatTrainDescriptors = _VectorOfMatCreate()

        $iArrTrainDescriptorsSize = UBound($matTrainDescriptors)
        For $i = 0 To $iArrTrainDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatTrainDescriptors, $matTrainDescriptors[$i])
        Next

        $iArrTrainDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatTrainDescriptors)
    Else
        $iArrTrainDescriptors = _cveInputArrayFromMat($matTrainDescriptors)
    EndIf

    Local $oArrMatches, $vectorOfMatMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matMatches) == "Array"

    If $bMatchesIsArray Then
        $vectorOfMatMatches = _VectorOfMatCreate()

        $iArrMatchesSize = UBound($matMatches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfMatPush($vectorOfMatMatches, $matMatches[$i])
        Next

        $oArrMatches = _cveOutputArrayFromVectorOfMat($vectorOfMatMatches)
    Else
        $oArrMatches = _cveOutputArrayFromMat($matMatches)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatchAsync1($matcher, $iArrQueryDescriptors, $iArrTrainDescriptors, $oArrMatches, $maxDistance, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatMatches)
    EndIf

    _cveOutputArrayRelease($oArrMatches)

    If $bTrainDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatTrainDescriptors)
    EndIf

    _cveInputArrayRelease($iArrTrainDescriptors)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync1Mat

Func _cveCudaDescriptorMatcherRadiusMatchAsync2($matcher, $queryDescriptors, $matches, $maxDistance, $masks, $stream)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatchAsync2(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* queryDescriptors, cv::_OutputArray* matches, float maxDistance, std::vector< cv::cuda::GpuMat >* masks, cv::cuda::Stream* stream);

    Local $vecMasks, $iArrMasksSize
    Local $bMasksIsArray = VarGetType($masks) == "Array"

    If $bMasksIsArray Then
        $vecMasks = _VectorOfGpuMatCreate()

        $iArrMasksSize = UBound($masks)
        For $i = 0 To $iArrMasksSize - 1
            _VectorOfGpuMatPush($vecMasks, $masks[$i])
        Next
    Else
        $vecMasks = $masks
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatchAsync2", "ptr", $matcher, "ptr", $queryDescriptors, "ptr", $matches, "float", $maxDistance, "ptr", $vecMasks, "ptr", $stream), "cveCudaDescriptorMatcherRadiusMatchAsync2", @error)

    If $bMasksIsArray Then
        _VectorOfGpuMatRelease($vecMasks)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync2

Func _cveCudaDescriptorMatcherRadiusMatchAsync2Mat($matcher, $matQueryDescriptors, $matMatches, $maxDistance, $masks, $stream)
    ; cveCudaDescriptorMatcherRadiusMatchAsync2 using cv::Mat instead of _*Array

    Local $iArrQueryDescriptors, $vectorOfMatQueryDescriptors, $iArrQueryDescriptorsSize
    Local $bQueryDescriptorsIsArray = VarGetType($matQueryDescriptors) == "Array"

    If $bQueryDescriptorsIsArray Then
        $vectorOfMatQueryDescriptors = _VectorOfMatCreate()

        $iArrQueryDescriptorsSize = UBound($matQueryDescriptors)
        For $i = 0 To $iArrQueryDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatQueryDescriptors, $matQueryDescriptors[$i])
        Next

        $iArrQueryDescriptors = _cveInputArrayFromVectorOfMat($vectorOfMatQueryDescriptors)
    Else
        $iArrQueryDescriptors = _cveInputArrayFromMat($matQueryDescriptors)
    EndIf

    Local $oArrMatches, $vectorOfMatMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matMatches) == "Array"

    If $bMatchesIsArray Then
        $vectorOfMatMatches = _VectorOfMatCreate()

        $iArrMatchesSize = UBound($matMatches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfMatPush($vectorOfMatMatches, $matMatches[$i])
        Next

        $oArrMatches = _cveOutputArrayFromVectorOfMat($vectorOfMatMatches)
    Else
        $oArrMatches = _cveOutputArrayFromMat($matMatches)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatchAsync2($matcher, $iArrQueryDescriptors, $oArrMatches, $maxDistance, $masks, $stream)

    If $bMatchesIsArray Then
        _VectorOfMatRelease($vectorOfMatMatches)
    EndIf

    _cveOutputArrayRelease($oArrMatches)

    If $bQueryDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatQueryDescriptors)
    EndIf

    _cveInputArrayRelease($iArrQueryDescriptors)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchAsync2Mat

Func _cveCudaDescriptorMatcherRadiusMatchConvert($matcher, $gpu_matches, $matches, $compactResult)
    ; CVAPI(void) cveCudaDescriptorMatcherRadiusMatchConvert(cv::cuda::DescriptorMatcher* matcher, cv::_InputArray* gpu_matches, std::vector< std::vector< cv::DMatch > >* matches, bool compactResult);

    Local $vecMatches, $iArrMatchesSize
    Local $bMatchesIsArray = VarGetType($matches) == "Array"

    If $bMatchesIsArray Then
        $vecMatches = _VectorOfVectorOfDMatchCreate()

        $iArrMatchesSize = UBound($matches)
        For $i = 0 To $iArrMatchesSize - 1
            _VectorOfVectorOfDMatchPush($vecMatches, $matches[$i])
        Next
    Else
        $vecMatches = $matches
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaDescriptorMatcherRadiusMatchConvert", "ptr", $matcher, "ptr", $gpu_matches, "ptr", $vecMatches, "boolean", $compactResult), "cveCudaDescriptorMatcherRadiusMatchConvert", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchConvert

Func _cveCudaDescriptorMatcherRadiusMatchConvertMat($matcher, $matGpu_matches, $matches, $compactResult)
    ; cveCudaDescriptorMatcherRadiusMatchConvert using cv::Mat instead of _*Array

    Local $iArrGpu_matches, $vectorOfMatGpu_matches, $iArrGpu_matchesSize
    Local $bGpu_matchesIsArray = VarGetType($matGpu_matches) == "Array"

    If $bGpu_matchesIsArray Then
        $vectorOfMatGpu_matches = _VectorOfMatCreate()

        $iArrGpu_matchesSize = UBound($matGpu_matches)
        For $i = 0 To $iArrGpu_matchesSize - 1
            _VectorOfMatPush($vectorOfMatGpu_matches, $matGpu_matches[$i])
        Next

        $iArrGpu_matches = _cveInputArrayFromVectorOfMat($vectorOfMatGpu_matches)
    Else
        $iArrGpu_matches = _cveInputArrayFromMat($matGpu_matches)
    EndIf

    _cveCudaDescriptorMatcherRadiusMatchConvert($matcher, $iArrGpu_matches, $matches, $compactResult)

    If $bGpu_matchesIsArray Then
        _VectorOfMatRelease($vectorOfMatGpu_matches)
    EndIf

    _cveInputArrayRelease($iArrGpu_matches)
EndFunc   ;==>_cveCudaDescriptorMatcherRadiusMatchConvertMat

Func _cveCudaFeature2dAsyncDetectAsync($feature2d, $image, $keypoints, $mask, $stream)
    ; CVAPI(void) cveCudaFeature2dAsyncDetectAsync(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* image, cv::_OutputArray* keypoints, cv::_InputArray* mask, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncDetectAsync", "ptr", $feature2d, "ptr", $image, "ptr", $keypoints, "ptr", $mask, "ptr", $stream), "cveCudaFeature2dAsyncDetectAsync", @error)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAsync

Func _cveCudaFeature2dAsyncDetectAsyncMat($feature2d, $matImage, $matKeypoints, $matMask, $stream)
    ; cveCudaFeature2dAsyncDetectAsync using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $oArrKeypoints, $vectorOfMatKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($matKeypoints) == "Array"

    If $bKeypointsIsArray Then
        $vectorOfMatKeypoints = _VectorOfMatCreate()

        $iArrKeypointsSize = UBound($matKeypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfMatPush($vectorOfMatKeypoints, $matKeypoints[$i])
        Next

        $oArrKeypoints = _cveOutputArrayFromVectorOfMat($vectorOfMatKeypoints)
    Else
        $oArrKeypoints = _cveOutputArrayFromMat($matKeypoints)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    _cveCudaFeature2dAsyncDetectAsync($feature2d, $iArrImage, $oArrKeypoints, $iArrMask, $stream)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bKeypointsIsArray Then
        _VectorOfMatRelease($vectorOfMatKeypoints)
    EndIf

    _cveOutputArrayRelease($oArrKeypoints)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAsyncMat

Func _cveCudaFeature2dAsyncComputeAsync($feature2d, $image, $keypoints, $descriptors, $stream)
    ; CVAPI(void) cveCudaFeature2dAsyncComputeAsync(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* image, cv::_OutputArray* keypoints, cv::_OutputArray* descriptors, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncComputeAsync", "ptr", $feature2d, "ptr", $image, "ptr", $keypoints, "ptr", $descriptors, "ptr", $stream), "cveCudaFeature2dAsyncComputeAsync", @error)
EndFunc   ;==>_cveCudaFeature2dAsyncComputeAsync

Func _cveCudaFeature2dAsyncComputeAsyncMat($feature2d, $matImage, $matKeypoints, $matDescriptors, $stream)
    ; cveCudaFeature2dAsyncComputeAsync using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $oArrKeypoints, $vectorOfMatKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($matKeypoints) == "Array"

    If $bKeypointsIsArray Then
        $vectorOfMatKeypoints = _VectorOfMatCreate()

        $iArrKeypointsSize = UBound($matKeypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfMatPush($vectorOfMatKeypoints, $matKeypoints[$i])
        Next

        $oArrKeypoints = _cveOutputArrayFromVectorOfMat($vectorOfMatKeypoints)
    Else
        $oArrKeypoints = _cveOutputArrayFromMat($matKeypoints)
    EndIf

    Local $oArrDescriptors, $vectorOfMatDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = VarGetType($matDescriptors) == "Array"

    If $bDescriptorsIsArray Then
        $vectorOfMatDescriptors = _VectorOfMatCreate()

        $iArrDescriptorsSize = UBound($matDescriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatDescriptors, $matDescriptors[$i])
        Next

        $oArrDescriptors = _cveOutputArrayFromVectorOfMat($vectorOfMatDescriptors)
    Else
        $oArrDescriptors = _cveOutputArrayFromMat($matDescriptors)
    EndIf

    _cveCudaFeature2dAsyncComputeAsync($feature2d, $iArrImage, $oArrKeypoints, $oArrDescriptors, $stream)

    If $bDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatDescriptors)
    EndIf

    _cveOutputArrayRelease($oArrDescriptors)

    If $bKeypointsIsArray Then
        _VectorOfMatRelease($vectorOfMatKeypoints)
    EndIf

    _cveOutputArrayRelease($oArrKeypoints)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveCudaFeature2dAsyncComputeAsyncMat

Func _cveCudaFeature2dAsyncDetectAndComputeAsync($feature2d, $image, $mask, $keypoints, $descriptors, $useProvidedKeypoints, $stream)
    ; CVAPI(void) cveCudaFeature2dAsyncDetectAndComputeAsync(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* image, cv::_InputArray* mask, cv::_OutputArray* keypoints, cv::_OutputArray* descriptors, bool useProvidedKeypoints, cv::cuda::Stream* stream);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncDetectAndComputeAsync", "ptr", $feature2d, "ptr", $image, "ptr", $mask, "ptr", $keypoints, "ptr", $descriptors, "boolean", $useProvidedKeypoints, "ptr", $stream), "cveCudaFeature2dAsyncDetectAndComputeAsync", @error)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAndComputeAsync

Func _cveCudaFeature2dAsyncDetectAndComputeAsyncMat($feature2d, $matImage, $matMask, $matKeypoints, $matDescriptors, $useProvidedKeypoints, $stream)
    ; cveCudaFeature2dAsyncDetectAndComputeAsync using cv::Mat instead of _*Array

    Local $iArrImage, $vectorOfMatImage, $iArrImageSize
    Local $bImageIsArray = VarGetType($matImage) == "Array"

    If $bImageIsArray Then
        $vectorOfMatImage = _VectorOfMatCreate()

        $iArrImageSize = UBound($matImage)
        For $i = 0 To $iArrImageSize - 1
            _VectorOfMatPush($vectorOfMatImage, $matImage[$i])
        Next

        $iArrImage = _cveInputArrayFromVectorOfMat($vectorOfMatImage)
    Else
        $iArrImage = _cveInputArrayFromMat($matImage)
    EndIf

    Local $iArrMask, $vectorOfMatMask, $iArrMaskSize
    Local $bMaskIsArray = VarGetType($matMask) == "Array"

    If $bMaskIsArray Then
        $vectorOfMatMask = _VectorOfMatCreate()

        $iArrMaskSize = UBound($matMask)
        For $i = 0 To $iArrMaskSize - 1
            _VectorOfMatPush($vectorOfMatMask, $matMask[$i])
        Next

        $iArrMask = _cveInputArrayFromVectorOfMat($vectorOfMatMask)
    Else
        $iArrMask = _cveInputArrayFromMat($matMask)
    EndIf

    Local $oArrKeypoints, $vectorOfMatKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($matKeypoints) == "Array"

    If $bKeypointsIsArray Then
        $vectorOfMatKeypoints = _VectorOfMatCreate()

        $iArrKeypointsSize = UBound($matKeypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfMatPush($vectorOfMatKeypoints, $matKeypoints[$i])
        Next

        $oArrKeypoints = _cveOutputArrayFromVectorOfMat($vectorOfMatKeypoints)
    Else
        $oArrKeypoints = _cveOutputArrayFromMat($matKeypoints)
    EndIf

    Local $oArrDescriptors, $vectorOfMatDescriptors, $iArrDescriptorsSize
    Local $bDescriptorsIsArray = VarGetType($matDescriptors) == "Array"

    If $bDescriptorsIsArray Then
        $vectorOfMatDescriptors = _VectorOfMatCreate()

        $iArrDescriptorsSize = UBound($matDescriptors)
        For $i = 0 To $iArrDescriptorsSize - 1
            _VectorOfMatPush($vectorOfMatDescriptors, $matDescriptors[$i])
        Next

        $oArrDescriptors = _cveOutputArrayFromVectorOfMat($vectorOfMatDescriptors)
    Else
        $oArrDescriptors = _cveOutputArrayFromMat($matDescriptors)
    EndIf

    _cveCudaFeature2dAsyncDetectAndComputeAsync($feature2d, $iArrImage, $iArrMask, $oArrKeypoints, $oArrDescriptors, $useProvidedKeypoints, $stream)

    If $bDescriptorsIsArray Then
        _VectorOfMatRelease($vectorOfMatDescriptors)
    EndIf

    _cveOutputArrayRelease($oArrDescriptors)

    If $bKeypointsIsArray Then
        _VectorOfMatRelease($vectorOfMatKeypoints)
    EndIf

    _cveOutputArrayRelease($oArrKeypoints)

    If $bMaskIsArray Then
        _VectorOfMatRelease($vectorOfMatMask)
    EndIf

    _cveInputArrayRelease($iArrMask)

    If $bImageIsArray Then
        _VectorOfMatRelease($vectorOfMatImage)
    EndIf

    _cveInputArrayRelease($iArrImage)
EndFunc   ;==>_cveCudaFeature2dAsyncDetectAndComputeAsyncMat

Func _cveCudaFeature2dAsyncConvert($feature2d, $gpu_keypoints, $keypoints)
    ; CVAPI(void) cveCudaFeature2dAsyncConvert(cv::cuda::Feature2DAsync* feature2d, cv::_InputArray* gpu_keypoints, std::vector<cv::KeyPoint>* keypoints);

    Local $vecKeypoints, $iArrKeypointsSize
    Local $bKeypointsIsArray = VarGetType($keypoints) == "Array"

    If $bKeypointsIsArray Then
        $vecKeypoints = _VectorOfKeyPointCreate()

        $iArrKeypointsSize = UBound($keypoints)
        For $i = 0 To $iArrKeypointsSize - 1
            _VectorOfKeyPointPush($vecKeypoints, $keypoints[$i])
        Next
    Else
        $vecKeypoints = $keypoints
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFeature2dAsyncConvert", "ptr", $feature2d, "ptr", $gpu_keypoints, "ptr", $vecKeypoints), "cveCudaFeature2dAsyncConvert", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_cveCudaFeature2dAsyncConvert

Func _cveCudaFeature2dAsyncConvertMat($feature2d, $matGpu_keypoints, $keypoints)
    ; cveCudaFeature2dAsyncConvert using cv::Mat instead of _*Array

    Local $iArrGpu_keypoints, $vectorOfMatGpu_keypoints, $iArrGpu_keypointsSize
    Local $bGpu_keypointsIsArray = VarGetType($matGpu_keypoints) == "Array"

    If $bGpu_keypointsIsArray Then
        $vectorOfMatGpu_keypoints = _VectorOfMatCreate()

        $iArrGpu_keypointsSize = UBound($matGpu_keypoints)
        For $i = 0 To $iArrGpu_keypointsSize - 1
            _VectorOfMatPush($vectorOfMatGpu_keypoints, $matGpu_keypoints[$i])
        Next

        $iArrGpu_keypoints = _cveInputArrayFromVectorOfMat($vectorOfMatGpu_keypoints)
    Else
        $iArrGpu_keypoints = _cveInputArrayFromMat($matGpu_keypoints)
    EndIf

    _cveCudaFeature2dAsyncConvert($feature2d, $iArrGpu_keypoints, $keypoints)

    If $bGpu_keypointsIsArray Then
        _VectorOfMatRelease($vectorOfMatGpu_keypoints)
    EndIf

    _cveInputArrayRelease($iArrGpu_keypoints)
EndFunc   ;==>_cveCudaFeature2dAsyncConvertMat

Func _cveCudaFastFeatureDetectorCreate($threshold, $nonmaxSupression, $type, $maxPoints, $feature2D, $feature2dAsync, $sharedPtr)
    ; CVAPI(cv::cuda::FastFeatureDetector*) cveCudaFastFeatureDetectorCreate(int threshold, bool nonmaxSupression, int type, int maxPoints, cv::Feature2D** feature2D, cv::cuda::Feature2DAsync** feature2dAsync, cv::Ptr<cv::cuda::FastFeatureDetector>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bFeature2dAsyncDllType
    If VarGetType($feature2dAsync) == "DLLStruct" Then
        $bFeature2dAsyncDllType = "struct*"
    Else
        $bFeature2dAsyncDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCudaFastFeatureDetectorCreate", "int", $threshold, "boolean", $nonmaxSupression, "int", $type, "int", $maxPoints, $bFeature2DDllType, $feature2D, $bFeature2dAsyncDllType, $feature2dAsync, $bSharedPtrDllType, $sharedPtr), "cveCudaFastFeatureDetectorCreate", @error)
EndFunc   ;==>_cveCudaFastFeatureDetectorCreate

Func _cveCudaFastFeatureDetectorRelease($sharedPtr)
    ; CVAPI(void) cveCudaFastFeatureDetectorRelease(cv::Ptr<cv::cuda::FastFeatureDetector>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaFastFeatureDetectorRelease", $bSharedPtrDllType, $sharedPtr), "cveCudaFastFeatureDetectorRelease", @error)
EndFunc   ;==>_cveCudaFastFeatureDetectorRelease

Func _cveCudaORBCreate($numberOfFeatures, $scaleFactor, $nLevels, $edgeThreshold, $firstLevel, $WTA_K, $scoreType, $patchSize, $fastThreshold, $blurForDescriptor, $feature2D, $feature2dAsync, $sharedPtr)
    ; CVAPI(cv::cuda::ORB*) cveCudaORBCreate(int numberOfFeatures, float scaleFactor, int nLevels, int edgeThreshold, int firstLevel, int WTA_K, int scoreType, int patchSize, int fastThreshold, bool blurForDescriptor, cv::Feature2D** feature2D, cv::cuda::Feature2DAsync** feature2dAsync, cv::Ptr<cv::cuda::ORB>** sharedPtr);

    Local $bFeature2DDllType
    If VarGetType($feature2D) == "DLLStruct" Then
        $bFeature2DDllType = "struct*"
    Else
        $bFeature2DDllType = "ptr*"
    EndIf

    Local $bFeature2dAsyncDllType
    If VarGetType($feature2dAsync) == "DLLStruct" Then
        $bFeature2dAsyncDllType = "struct*"
    Else
        $bFeature2dAsyncDllType = "ptr*"
    EndIf

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCudaORBCreate", "int", $numberOfFeatures, "float", $scaleFactor, "int", $nLevels, "int", $edgeThreshold, "int", $firstLevel, "int", $WTA_K, "int", $scoreType, "int", $patchSize, "int", $fastThreshold, "boolean", $blurForDescriptor, $bFeature2DDllType, $feature2D, $bFeature2dAsyncDllType, $feature2dAsync, $bSharedPtrDllType, $sharedPtr), "cveCudaORBCreate", @error)
EndFunc   ;==>_cveCudaORBCreate

Func _cveCudaORBRelease($sharedPtr)
    ; CVAPI(void) cveCudaORBRelease(cv::Ptr<cv::cuda::ORB>** sharedPtr);

    Local $bSharedPtrDllType
    If VarGetType($sharedPtr) == "DLLStruct" Then
        $bSharedPtrDllType = "struct*"
    Else
        $bSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCudaORBRelease", $bSharedPtrDllType, $sharedPtr), "cveCudaORBRelease", @error)
EndFunc   ;==>_cveCudaORBRelease