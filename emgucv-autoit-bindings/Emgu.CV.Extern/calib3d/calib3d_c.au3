#include-once
#include "..\..\CVEUtils.au3"

Func _cveEstimateAffine3D($src, $dst, $out, $inliers, $ransacThreshold = 3, $confidence = 0.99)
    ; CVAPI(int) cveEstimateAffine3D(cv::_InputArray* src, cv::_InputArray* dst, cv::_OutputArray* out, cv::_OutputArray* inliers, double ransacThreshold, double confidence);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sOutDllType
    If IsDllStruct($out) Then
        $sOutDllType = "struct*"
    Else
        $sOutDllType = "ptr"
    EndIf

    Local $sInliersDllType
    If IsDllStruct($inliers) Then
        $sInliersDllType = "struct*"
    Else
        $sInliersDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveEstimateAffine3D", $sSrcDllType, $src, $sDstDllType, $dst, $sOutDllType, $out, $sInliersDllType, $inliers, "double", $ransacThreshold, "double", $confidence), "cveEstimateAffine3D", @error)
EndFunc   ;==>_cveEstimateAffine3D

Func _cveEstimateAffine3DTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfOut, $out, $typeOfInliers, $inliers, $ransacThreshold = 3, $confidence = 0.99)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $iArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $iArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $iArrDst = Call("_cveInputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $iArrDst = Call("_cveInputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $oArrOut, $vectorOut, $iArrOutSize
    Local $bOutIsArray = IsArray($out)
    Local $bOutCreate = IsDllStruct($out) And $typeOfOut == "Scalar"

    If $typeOfOut == Default Then
        $oArrOut = $out
    ElseIf $bOutIsArray Then
        $vectorOut = Call("_VectorOf" & $typeOfOut & "Create")

        $iArrOutSize = UBound($out)
        For $i = 0 To $iArrOutSize - 1
            Call("_VectorOf" & $typeOfOut & "Push", $vectorOut, $out[$i])
        Next

        $oArrOut = Call("_cveOutputArrayFromVectorOf" & $typeOfOut, $vectorOut)
    Else
        If $bOutCreate Then
            $out = Call("_cve" & $typeOfOut & "Create", $out)
        EndIf
        $oArrOut = Call("_cveOutputArrayFrom" & $typeOfOut, $out)
    EndIf

    Local $oArrInliers, $vectorInliers, $iArrInliersSize
    Local $bInliersIsArray = IsArray($inliers)
    Local $bInliersCreate = IsDllStruct($inliers) And $typeOfInliers == "Scalar"

    If $typeOfInliers == Default Then
        $oArrInliers = $inliers
    ElseIf $bInliersIsArray Then
        $vectorInliers = Call("_VectorOf" & $typeOfInliers & "Create")

        $iArrInliersSize = UBound($inliers)
        For $i = 0 To $iArrInliersSize - 1
            Call("_VectorOf" & $typeOfInliers & "Push", $vectorInliers, $inliers[$i])
        Next

        $oArrInliers = Call("_cveOutputArrayFromVectorOf" & $typeOfInliers, $vectorInliers)
    Else
        If $bInliersCreate Then
            $inliers = Call("_cve" & $typeOfInliers & "Create", $inliers)
        EndIf
        $oArrInliers = Call("_cveOutputArrayFrom" & $typeOfInliers, $inliers)
    EndIf

    Local $retval = _cveEstimateAffine3D($iArrSrc, $iArrDst, $oArrOut, $oArrInliers, $ransacThreshold, $confidence)

    If $bInliersIsArray Then
        Call("_VectorOf" & $typeOfInliers & "Release", $vectorInliers)
    EndIf

    If $typeOfInliers <> Default Then
        _cveOutputArrayRelease($oArrInliers)
        If $bInliersCreate Then
            Call("_cve" & $typeOfInliers & "Release", $inliers)
        EndIf
    EndIf

    If $bOutIsArray Then
        Call("_VectorOf" & $typeOfOut & "Release", $vectorOut)
    EndIf

    If $typeOfOut <> Default Then
        _cveOutputArrayRelease($oArrOut)
        If $bOutCreate Then
            Call("_cve" & $typeOfOut & "Release", $out)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveInputArrayRelease($iArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveEstimateAffine3DTyped

Func _cveEstimateAffine3DMat($src, $dst, $out, $inliers, $ransacThreshold = 3, $confidence = 0.99)
    ; cveEstimateAffine3D using cv::Mat instead of _*Array
    Local $retval = _cveEstimateAffine3DTyped("Mat", $src, "Mat", $dst, "Mat", $out, "Mat", $inliers, $ransacThreshold, $confidence)

    Return $retval
EndFunc   ;==>_cveEstimateAffine3DMat

Func _cveStereoSGBMCreate($minDisparity, $numDisparities, $blockSize, $P1, $P2, $disp12MaxDiff, $preFilterCap, $uniquenessRatio, $speckleWindowSize, $speckleRange, $mode, $stereoMatcher, $sharedPtr)
    ; CVAPI(cv::StereoSGBM*) cveStereoSGBMCreate(int minDisparity, int numDisparities, int blockSize, int P1, int P2, int disp12MaxDiff, int preFilterCap, int uniquenessRatio, int speckleWindowSize, int speckleRange, int mode, cv::StereoMatcher** stereoMatcher, cv::Ptr<cv::StereoSGBM>** sharedPtr);

    Local $sStereoMatcherDllType
    If IsDllStruct($stereoMatcher) Then
        $sStereoMatcherDllType = "struct*"
    ElseIf $stereoMatcher == Null Then
        $sStereoMatcherDllType = "ptr"
    Else
        $sStereoMatcherDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStereoSGBMCreate", "int", $minDisparity, "int", $numDisparities, "int", $blockSize, "int", $P1, "int", $P2, "int", $disp12MaxDiff, "int", $preFilterCap, "int", $uniquenessRatio, "int", $speckleWindowSize, "int", $speckleRange, "int", $mode, $sStereoMatcherDllType, $stereoMatcher, $sSharedPtrDllType, $sharedPtr), "cveStereoSGBMCreate", @error)
EndFunc   ;==>_cveStereoSGBMCreate

Func _cveStereoSGBMRelease($sharedPtr)
    ; CVAPI(void) cveStereoSGBMRelease(cv::Ptr<cv::StereoSGBM>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoSGBMRelease", $sSharedPtrDllType, $sharedPtr), "cveStereoSGBMRelease", @error)
EndFunc   ;==>_cveStereoSGBMRelease

Func _cveStereoBMCreate($mode, $numberOfDisparities, $sharedPtr)
    ; CVAPI(cv::StereoMatcher*) cveStereoBMCreate(int mode, int numberOfDisparities, cv::Ptr<cv::StereoMatcher>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveStereoBMCreate", "int", $mode, "int", $numberOfDisparities, $sSharedPtrDllType, $sharedPtr), "cveStereoBMCreate", @error)
EndFunc   ;==>_cveStereoBMCreate

Func _cveStereoMatcherCompute($disparitySolver, $left, $right, $disparity)
    ; CVAPI(void) cveStereoMatcherCompute(cv::StereoMatcher* disparitySolver, cv::_InputArray* left, cv::_InputArray* right, cv::_OutputArray* disparity);

    Local $sDisparitySolverDllType
    If IsDllStruct($disparitySolver) Then
        $sDisparitySolverDllType = "struct*"
    Else
        $sDisparitySolverDllType = "ptr"
    EndIf

    Local $sLeftDllType
    If IsDllStruct($left) Then
        $sLeftDllType = "struct*"
    Else
        $sLeftDllType = "ptr"
    EndIf

    Local $sRightDllType
    If IsDllStruct($right) Then
        $sRightDllType = "struct*"
    Else
        $sRightDllType = "ptr"
    EndIf

    Local $sDisparityDllType
    If IsDllStruct($disparity) Then
        $sDisparityDllType = "struct*"
    Else
        $sDisparityDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoMatcherCompute", $sDisparitySolverDllType, $disparitySolver, $sLeftDllType, $left, $sRightDllType, $right, $sDisparityDllType, $disparity), "cveStereoMatcherCompute", @error)
EndFunc   ;==>_cveStereoMatcherCompute

Func _cveStereoMatcherComputeTyped($disparitySolver, $typeOfLeft, $left, $typeOfRight, $right, $typeOfDisparity, $disparity)

    Local $iArrLeft, $vectorLeft, $iArrLeftSize
    Local $bLeftIsArray = IsArray($left)
    Local $bLeftCreate = IsDllStruct($left) And $typeOfLeft == "Scalar"

    If $typeOfLeft == Default Then
        $iArrLeft = $left
    ElseIf $bLeftIsArray Then
        $vectorLeft = Call("_VectorOf" & $typeOfLeft & "Create")

        $iArrLeftSize = UBound($left)
        For $i = 0 To $iArrLeftSize - 1
            Call("_VectorOf" & $typeOfLeft & "Push", $vectorLeft, $left[$i])
        Next

        $iArrLeft = Call("_cveInputArrayFromVectorOf" & $typeOfLeft, $vectorLeft)
    Else
        If $bLeftCreate Then
            $left = Call("_cve" & $typeOfLeft & "Create", $left)
        EndIf
        $iArrLeft = Call("_cveInputArrayFrom" & $typeOfLeft, $left)
    EndIf

    Local $iArrRight, $vectorRight, $iArrRightSize
    Local $bRightIsArray = IsArray($right)
    Local $bRightCreate = IsDllStruct($right) And $typeOfRight == "Scalar"

    If $typeOfRight == Default Then
        $iArrRight = $right
    ElseIf $bRightIsArray Then
        $vectorRight = Call("_VectorOf" & $typeOfRight & "Create")

        $iArrRightSize = UBound($right)
        For $i = 0 To $iArrRightSize - 1
            Call("_VectorOf" & $typeOfRight & "Push", $vectorRight, $right[$i])
        Next

        $iArrRight = Call("_cveInputArrayFromVectorOf" & $typeOfRight, $vectorRight)
    Else
        If $bRightCreate Then
            $right = Call("_cve" & $typeOfRight & "Create", $right)
        EndIf
        $iArrRight = Call("_cveInputArrayFrom" & $typeOfRight, $right)
    EndIf

    Local $oArrDisparity, $vectorDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = IsArray($disparity)
    Local $bDisparityCreate = IsDllStruct($disparity) And $typeOfDisparity == "Scalar"

    If $typeOfDisparity == Default Then
        $oArrDisparity = $disparity
    ElseIf $bDisparityIsArray Then
        $vectorDisparity = Call("_VectorOf" & $typeOfDisparity & "Create")

        $iArrDisparitySize = UBound($disparity)
        For $i = 0 To $iArrDisparitySize - 1
            Call("_VectorOf" & $typeOfDisparity & "Push", $vectorDisparity, $disparity[$i])
        Next

        $oArrDisparity = Call("_cveOutputArrayFromVectorOf" & $typeOfDisparity, $vectorDisparity)
    Else
        If $bDisparityCreate Then
            $disparity = Call("_cve" & $typeOfDisparity & "Create", $disparity)
        EndIf
        $oArrDisparity = Call("_cveOutputArrayFrom" & $typeOfDisparity, $disparity)
    EndIf

    _cveStereoMatcherCompute($disparitySolver, $iArrLeft, $iArrRight, $oArrDisparity)

    If $bDisparityIsArray Then
        Call("_VectorOf" & $typeOfDisparity & "Release", $vectorDisparity)
    EndIf

    If $typeOfDisparity <> Default Then
        _cveOutputArrayRelease($oArrDisparity)
        If $bDisparityCreate Then
            Call("_cve" & $typeOfDisparity & "Release", $disparity)
        EndIf
    EndIf

    If $bRightIsArray Then
        Call("_VectorOf" & $typeOfRight & "Release", $vectorRight)
    EndIf

    If $typeOfRight <> Default Then
        _cveInputArrayRelease($iArrRight)
        If $bRightCreate Then
            Call("_cve" & $typeOfRight & "Release", $right)
        EndIf
    EndIf

    If $bLeftIsArray Then
        Call("_VectorOf" & $typeOfLeft & "Release", $vectorLeft)
    EndIf

    If $typeOfLeft <> Default Then
        _cveInputArrayRelease($iArrLeft)
        If $bLeftCreate Then
            Call("_cve" & $typeOfLeft & "Release", $left)
        EndIf
    EndIf
EndFunc   ;==>_cveStereoMatcherComputeTyped

Func _cveStereoMatcherComputeMat($disparitySolver, $left, $right, $disparity)
    ; cveStereoMatcherCompute using cv::Mat instead of _*Array
    _cveStereoMatcherComputeTyped($disparitySolver, "Mat", $left, "Mat", $right, "Mat", $disparity)
EndFunc   ;==>_cveStereoMatcherComputeMat

Func _cveStereoMatcherRelease($sharedPtr)
    ; CVAPI(void) cveStereoMatcherRelease(cv::Ptr<cv::StereoMatcher>** sharedPtr);

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoMatcherRelease", $sSharedPtrDllType, $sharedPtr), "cveStereoMatcherRelease", @error)
EndFunc   ;==>_cveStereoMatcherRelease

Func _getHomographyMatrixFromMatchedFeatures($model, $observed, $matches, $mask, $randsacThreshold, $homography)
    ; CVAPI(bool) getHomographyMatrixFromMatchedFeatures(std::vector<cv::KeyPoint>* model, std::vector<cv::KeyPoint>* observed, std::vector<std::vector<cv::DMatch>>* matches, cv::Mat* mask, double randsacThreshold, cv::Mat* homography);

    Local $vecModel, $iArrModelSize
    Local $bModelIsArray = IsArray($model)

    If $bModelIsArray Then
        $vecModel = _VectorOfKeyPointCreate()

        $iArrModelSize = UBound($model)
        For $i = 0 To $iArrModelSize - 1
            _VectorOfKeyPointPush($vecModel, $model[$i])
        Next
    Else
        $vecModel = $model
    EndIf

    Local $sModelDllType
    If IsDllStruct($model) Then
        $sModelDllType = "struct*"
    Else
        $sModelDllType = "ptr"
    EndIf

    Local $vecObserved, $iArrObservedSize
    Local $bObservedIsArray = IsArray($observed)

    If $bObservedIsArray Then
        $vecObserved = _VectorOfKeyPointCreate()

        $iArrObservedSize = UBound($observed)
        For $i = 0 To $iArrObservedSize - 1
            _VectorOfKeyPointPush($vecObserved, $observed[$i])
        Next
    Else
        $vecObserved = $observed
    EndIf

    Local $sObservedDllType
    If IsDllStruct($observed) Then
        $sObservedDllType = "struct*"
    Else
        $sObservedDllType = "ptr"
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

    Local $sHomographyDllType
    If IsDllStruct($homography) Then
        $sHomographyDllType = "struct*"
    Else
        $sHomographyDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "getHomographyMatrixFromMatchedFeatures", $sModelDllType, $vecModel, $sObservedDllType, $vecObserved, $sMatchesDllType, $vecMatches, $sMaskDllType, $mask, "double", $randsacThreshold, $sHomographyDllType, $homography), "getHomographyMatrixFromMatchedFeatures", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf

    If $bObservedIsArray Then
        _VectorOfKeyPointRelease($vecObserved)
    EndIf

    If $bModelIsArray Then
        _VectorOfKeyPointRelease($vecModel)
    EndIf

    Return $retval
EndFunc   ;==>_getHomographyMatrixFromMatchedFeatures

Func _cveFindCirclesGrid($image, $patternSize, $centers, $flags, $blobDetector)
    ; CVAPI(bool) cveFindCirclesGrid(cv::_InputArray* image, CvSize* patternSize, cv::_OutputArray* centers, int flags, cv::Feature2D* blobDetector);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sPatternSizeDllType
    If IsDllStruct($patternSize) Then
        $sPatternSizeDllType = "struct*"
    Else
        $sPatternSizeDllType = "ptr"
    EndIf

    Local $sCentersDllType
    If IsDllStruct($centers) Then
        $sCentersDllType = "struct*"
    Else
        $sCentersDllType = "ptr"
    EndIf

    Local $sBlobDetectorDllType
    If IsDllStruct($blobDetector) Then
        $sBlobDetectorDllType = "struct*"
    Else
        $sBlobDetectorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFindCirclesGrid", $sImageDllType, $image, $sPatternSizeDllType, $patternSize, $sCentersDllType, $centers, "int", $flags, $sBlobDetectorDllType, $blobDetector), "cveFindCirclesGrid", @error)
EndFunc   ;==>_cveFindCirclesGrid

Func _cveFindCirclesGridTyped($typeOfImage, $image, $patternSize, $typeOfCenters, $centers, $flags, $blobDetector)

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

    Local $oArrCenters, $vectorCenters, $iArrCentersSize
    Local $bCentersIsArray = IsArray($centers)
    Local $bCentersCreate = IsDllStruct($centers) And $typeOfCenters == "Scalar"

    If $typeOfCenters == Default Then
        $oArrCenters = $centers
    ElseIf $bCentersIsArray Then
        $vectorCenters = Call("_VectorOf" & $typeOfCenters & "Create")

        $iArrCentersSize = UBound($centers)
        For $i = 0 To $iArrCentersSize - 1
            Call("_VectorOf" & $typeOfCenters & "Push", $vectorCenters, $centers[$i])
        Next

        $oArrCenters = Call("_cveOutputArrayFromVectorOf" & $typeOfCenters, $vectorCenters)
    Else
        If $bCentersCreate Then
            $centers = Call("_cve" & $typeOfCenters & "Create", $centers)
        EndIf
        $oArrCenters = Call("_cveOutputArrayFrom" & $typeOfCenters, $centers)
    EndIf

    Local $retval = _cveFindCirclesGrid($iArrImage, $patternSize, $oArrCenters, $flags, $blobDetector)

    If $bCentersIsArray Then
        Call("_VectorOf" & $typeOfCenters & "Release", $vectorCenters)
    EndIf

    If $typeOfCenters <> Default Then
        _cveOutputArrayRelease($oArrCenters)
        If $bCentersCreate Then
            Call("_cve" & $typeOfCenters & "Release", $centers)
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

    Return $retval
EndFunc   ;==>_cveFindCirclesGridTyped

Func _cveFindCirclesGridMat($image, $patternSize, $centers, $flags, $blobDetector)
    ; cveFindCirclesGrid using cv::Mat instead of _*Array
    Local $retval = _cveFindCirclesGridTyped("Mat", $image, $patternSize, "Mat", $centers, $flags, $blobDetector)

    Return $retval
EndFunc   ;==>_cveFindCirclesGridMat

Func _cveTriangulatePoints($projMat1, $projMat2, $projPoints1, $projPoints2, $points4D)
    ; CVAPI(void) cveTriangulatePoints(cv::_InputArray* projMat1, cv::_InputArray* projMat2, cv::_InputArray* projPoints1, cv::_InputArray* projPoints2, cv::_OutputArray* points4D);

    Local $sProjMat1DllType
    If IsDllStruct($projMat1) Then
        $sProjMat1DllType = "struct*"
    Else
        $sProjMat1DllType = "ptr"
    EndIf

    Local $sProjMat2DllType
    If IsDllStruct($projMat2) Then
        $sProjMat2DllType = "struct*"
    Else
        $sProjMat2DllType = "ptr"
    EndIf

    Local $sProjPoints1DllType
    If IsDllStruct($projPoints1) Then
        $sProjPoints1DllType = "struct*"
    Else
        $sProjPoints1DllType = "ptr"
    EndIf

    Local $sProjPoints2DllType
    If IsDllStruct($projPoints2) Then
        $sProjPoints2DllType = "struct*"
    Else
        $sProjPoints2DllType = "ptr"
    EndIf

    Local $sPoints4DDllType
    If IsDllStruct($points4D) Then
        $sPoints4DDllType = "struct*"
    Else
        $sPoints4DDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveTriangulatePoints", $sProjMat1DllType, $projMat1, $sProjMat2DllType, $projMat2, $sProjPoints1DllType, $projPoints1, $sProjPoints2DllType, $projPoints2, $sPoints4DDllType, $points4D), "cveTriangulatePoints", @error)
EndFunc   ;==>_cveTriangulatePoints

Func _cveTriangulatePointsTyped($typeOfProjMat1, $projMat1, $typeOfProjMat2, $projMat2, $typeOfProjPoints1, $projPoints1, $typeOfProjPoints2, $projPoints2, $typeOfPoints4D, $points4D)

    Local $iArrProjMat1, $vectorProjMat1, $iArrProjMat1Size
    Local $bProjMat1IsArray = IsArray($projMat1)
    Local $bProjMat1Create = IsDllStruct($projMat1) And $typeOfProjMat1 == "Scalar"

    If $typeOfProjMat1 == Default Then
        $iArrProjMat1 = $projMat1
    ElseIf $bProjMat1IsArray Then
        $vectorProjMat1 = Call("_VectorOf" & $typeOfProjMat1 & "Create")

        $iArrProjMat1Size = UBound($projMat1)
        For $i = 0 To $iArrProjMat1Size - 1
            Call("_VectorOf" & $typeOfProjMat1 & "Push", $vectorProjMat1, $projMat1[$i])
        Next

        $iArrProjMat1 = Call("_cveInputArrayFromVectorOf" & $typeOfProjMat1, $vectorProjMat1)
    Else
        If $bProjMat1Create Then
            $projMat1 = Call("_cve" & $typeOfProjMat1 & "Create", $projMat1)
        EndIf
        $iArrProjMat1 = Call("_cveInputArrayFrom" & $typeOfProjMat1, $projMat1)
    EndIf

    Local $iArrProjMat2, $vectorProjMat2, $iArrProjMat2Size
    Local $bProjMat2IsArray = IsArray($projMat2)
    Local $bProjMat2Create = IsDllStruct($projMat2) And $typeOfProjMat2 == "Scalar"

    If $typeOfProjMat2 == Default Then
        $iArrProjMat2 = $projMat2
    ElseIf $bProjMat2IsArray Then
        $vectorProjMat2 = Call("_VectorOf" & $typeOfProjMat2 & "Create")

        $iArrProjMat2Size = UBound($projMat2)
        For $i = 0 To $iArrProjMat2Size - 1
            Call("_VectorOf" & $typeOfProjMat2 & "Push", $vectorProjMat2, $projMat2[$i])
        Next

        $iArrProjMat2 = Call("_cveInputArrayFromVectorOf" & $typeOfProjMat2, $vectorProjMat2)
    Else
        If $bProjMat2Create Then
            $projMat2 = Call("_cve" & $typeOfProjMat2 & "Create", $projMat2)
        EndIf
        $iArrProjMat2 = Call("_cveInputArrayFrom" & $typeOfProjMat2, $projMat2)
    EndIf

    Local $iArrProjPoints1, $vectorProjPoints1, $iArrProjPoints1Size
    Local $bProjPoints1IsArray = IsArray($projPoints1)
    Local $bProjPoints1Create = IsDllStruct($projPoints1) And $typeOfProjPoints1 == "Scalar"

    If $typeOfProjPoints1 == Default Then
        $iArrProjPoints1 = $projPoints1
    ElseIf $bProjPoints1IsArray Then
        $vectorProjPoints1 = Call("_VectorOf" & $typeOfProjPoints1 & "Create")

        $iArrProjPoints1Size = UBound($projPoints1)
        For $i = 0 To $iArrProjPoints1Size - 1
            Call("_VectorOf" & $typeOfProjPoints1 & "Push", $vectorProjPoints1, $projPoints1[$i])
        Next

        $iArrProjPoints1 = Call("_cveInputArrayFromVectorOf" & $typeOfProjPoints1, $vectorProjPoints1)
    Else
        If $bProjPoints1Create Then
            $projPoints1 = Call("_cve" & $typeOfProjPoints1 & "Create", $projPoints1)
        EndIf
        $iArrProjPoints1 = Call("_cveInputArrayFrom" & $typeOfProjPoints1, $projPoints1)
    EndIf

    Local $iArrProjPoints2, $vectorProjPoints2, $iArrProjPoints2Size
    Local $bProjPoints2IsArray = IsArray($projPoints2)
    Local $bProjPoints2Create = IsDllStruct($projPoints2) And $typeOfProjPoints2 == "Scalar"

    If $typeOfProjPoints2 == Default Then
        $iArrProjPoints2 = $projPoints2
    ElseIf $bProjPoints2IsArray Then
        $vectorProjPoints2 = Call("_VectorOf" & $typeOfProjPoints2 & "Create")

        $iArrProjPoints2Size = UBound($projPoints2)
        For $i = 0 To $iArrProjPoints2Size - 1
            Call("_VectorOf" & $typeOfProjPoints2 & "Push", $vectorProjPoints2, $projPoints2[$i])
        Next

        $iArrProjPoints2 = Call("_cveInputArrayFromVectorOf" & $typeOfProjPoints2, $vectorProjPoints2)
    Else
        If $bProjPoints2Create Then
            $projPoints2 = Call("_cve" & $typeOfProjPoints2 & "Create", $projPoints2)
        EndIf
        $iArrProjPoints2 = Call("_cveInputArrayFrom" & $typeOfProjPoints2, $projPoints2)
    EndIf

    Local $oArrPoints4D, $vectorPoints4D, $iArrPoints4DSize
    Local $bPoints4DIsArray = IsArray($points4D)
    Local $bPoints4DCreate = IsDllStruct($points4D) And $typeOfPoints4D == "Scalar"

    If $typeOfPoints4D == Default Then
        $oArrPoints4D = $points4D
    ElseIf $bPoints4DIsArray Then
        $vectorPoints4D = Call("_VectorOf" & $typeOfPoints4D & "Create")

        $iArrPoints4DSize = UBound($points4D)
        For $i = 0 To $iArrPoints4DSize - 1
            Call("_VectorOf" & $typeOfPoints4D & "Push", $vectorPoints4D, $points4D[$i])
        Next

        $oArrPoints4D = Call("_cveOutputArrayFromVectorOf" & $typeOfPoints4D, $vectorPoints4D)
    Else
        If $bPoints4DCreate Then
            $points4D = Call("_cve" & $typeOfPoints4D & "Create", $points4D)
        EndIf
        $oArrPoints4D = Call("_cveOutputArrayFrom" & $typeOfPoints4D, $points4D)
    EndIf

    _cveTriangulatePoints($iArrProjMat1, $iArrProjMat2, $iArrProjPoints1, $iArrProjPoints2, $oArrPoints4D)

    If $bPoints4DIsArray Then
        Call("_VectorOf" & $typeOfPoints4D & "Release", $vectorPoints4D)
    EndIf

    If $typeOfPoints4D <> Default Then
        _cveOutputArrayRelease($oArrPoints4D)
        If $bPoints4DCreate Then
            Call("_cve" & $typeOfPoints4D & "Release", $points4D)
        EndIf
    EndIf

    If $bProjPoints2IsArray Then
        Call("_VectorOf" & $typeOfProjPoints2 & "Release", $vectorProjPoints2)
    EndIf

    If $typeOfProjPoints2 <> Default Then
        _cveInputArrayRelease($iArrProjPoints2)
        If $bProjPoints2Create Then
            Call("_cve" & $typeOfProjPoints2 & "Release", $projPoints2)
        EndIf
    EndIf

    If $bProjPoints1IsArray Then
        Call("_VectorOf" & $typeOfProjPoints1 & "Release", $vectorProjPoints1)
    EndIf

    If $typeOfProjPoints1 <> Default Then
        _cveInputArrayRelease($iArrProjPoints1)
        If $bProjPoints1Create Then
            Call("_cve" & $typeOfProjPoints1 & "Release", $projPoints1)
        EndIf
    EndIf

    If $bProjMat2IsArray Then
        Call("_VectorOf" & $typeOfProjMat2 & "Release", $vectorProjMat2)
    EndIf

    If $typeOfProjMat2 <> Default Then
        _cveInputArrayRelease($iArrProjMat2)
        If $bProjMat2Create Then
            Call("_cve" & $typeOfProjMat2 & "Release", $projMat2)
        EndIf
    EndIf

    If $bProjMat1IsArray Then
        Call("_VectorOf" & $typeOfProjMat1 & "Release", $vectorProjMat1)
    EndIf

    If $typeOfProjMat1 <> Default Then
        _cveInputArrayRelease($iArrProjMat1)
        If $bProjMat1Create Then
            Call("_cve" & $typeOfProjMat1 & "Release", $projMat1)
        EndIf
    EndIf
EndFunc   ;==>_cveTriangulatePointsTyped

Func _cveTriangulatePointsMat($projMat1, $projMat2, $projPoints1, $projPoints2, $points4D)
    ; cveTriangulatePoints using cv::Mat instead of _*Array
    _cveTriangulatePointsTyped("Mat", $projMat1, "Mat", $projMat2, "Mat", $projPoints1, "Mat", $projPoints2, "Mat", $points4D)
EndFunc   ;==>_cveTriangulatePointsMat

Func _cveCorrectMatches($f, $points1, $points2, $newPoints1, $newPoints2)
    ; CVAPI(void) cveCorrectMatches(cv::_InputArray* f, cv::_InputArray* points1, cv::_InputArray* points2, cv::_OutputArray* newPoints1, cv::_OutputArray* newPoints2);

    Local $sFDllType
    If IsDllStruct($f) Then
        $sFDllType = "struct*"
    Else
        $sFDllType = "ptr"
    EndIf

    Local $sPoints1DllType
    If IsDllStruct($points1) Then
        $sPoints1DllType = "struct*"
    Else
        $sPoints1DllType = "ptr"
    EndIf

    Local $sPoints2DllType
    If IsDllStruct($points2) Then
        $sPoints2DllType = "struct*"
    Else
        $sPoints2DllType = "ptr"
    EndIf

    Local $sNewPoints1DllType
    If IsDllStruct($newPoints1) Then
        $sNewPoints1DllType = "struct*"
    Else
        $sNewPoints1DllType = "ptr"
    EndIf

    Local $sNewPoints2DllType
    If IsDllStruct($newPoints2) Then
        $sNewPoints2DllType = "struct*"
    Else
        $sNewPoints2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCorrectMatches", $sFDllType, $f, $sPoints1DllType, $points1, $sPoints2DllType, $points2, $sNewPoints1DllType, $newPoints1, $sNewPoints2DllType, $newPoints2), "cveCorrectMatches", @error)
EndFunc   ;==>_cveCorrectMatches

Func _cveCorrectMatchesTyped($typeOfF, $f, $typeOfPoints1, $points1, $typeOfPoints2, $points2, $typeOfNewPoints1, $newPoints1, $typeOfNewPoints2, $newPoints2)

    Local $iArrF, $vectorF, $iArrFSize
    Local $bFIsArray = IsArray($f)
    Local $bFCreate = IsDllStruct($f) And $typeOfF == "Scalar"

    If $typeOfF == Default Then
        $iArrF = $f
    ElseIf $bFIsArray Then
        $vectorF = Call("_VectorOf" & $typeOfF & "Create")

        $iArrFSize = UBound($f)
        For $i = 0 To $iArrFSize - 1
            Call("_VectorOf" & $typeOfF & "Push", $vectorF, $f[$i])
        Next

        $iArrF = Call("_cveInputArrayFromVectorOf" & $typeOfF, $vectorF)
    Else
        If $bFCreate Then
            $f = Call("_cve" & $typeOfF & "Create", $f)
        EndIf
        $iArrF = Call("_cveInputArrayFrom" & $typeOfF, $f)
    EndIf

    Local $iArrPoints1, $vectorPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = IsArray($points1)
    Local $bPoints1Create = IsDllStruct($points1) And $typeOfPoints1 == "Scalar"

    If $typeOfPoints1 == Default Then
        $iArrPoints1 = $points1
    ElseIf $bPoints1IsArray Then
        $vectorPoints1 = Call("_VectorOf" & $typeOfPoints1 & "Create")

        $iArrPoints1Size = UBound($points1)
        For $i = 0 To $iArrPoints1Size - 1
            Call("_VectorOf" & $typeOfPoints1 & "Push", $vectorPoints1, $points1[$i])
        Next

        $iArrPoints1 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints1, $vectorPoints1)
    Else
        If $bPoints1Create Then
            $points1 = Call("_cve" & $typeOfPoints1 & "Create", $points1)
        EndIf
        $iArrPoints1 = Call("_cveInputArrayFrom" & $typeOfPoints1, $points1)
    EndIf

    Local $iArrPoints2, $vectorPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = IsArray($points2)
    Local $bPoints2Create = IsDllStruct($points2) And $typeOfPoints2 == "Scalar"

    If $typeOfPoints2 == Default Then
        $iArrPoints2 = $points2
    ElseIf $bPoints2IsArray Then
        $vectorPoints2 = Call("_VectorOf" & $typeOfPoints2 & "Create")

        $iArrPoints2Size = UBound($points2)
        For $i = 0 To $iArrPoints2Size - 1
            Call("_VectorOf" & $typeOfPoints2 & "Push", $vectorPoints2, $points2[$i])
        Next

        $iArrPoints2 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints2, $vectorPoints2)
    Else
        If $bPoints2Create Then
            $points2 = Call("_cve" & $typeOfPoints2 & "Create", $points2)
        EndIf
        $iArrPoints2 = Call("_cveInputArrayFrom" & $typeOfPoints2, $points2)
    EndIf

    Local $oArrNewPoints1, $vectorNewPoints1, $iArrNewPoints1Size
    Local $bNewPoints1IsArray = IsArray($newPoints1)
    Local $bNewPoints1Create = IsDllStruct($newPoints1) And $typeOfNewPoints1 == "Scalar"

    If $typeOfNewPoints1 == Default Then
        $oArrNewPoints1 = $newPoints1
    ElseIf $bNewPoints1IsArray Then
        $vectorNewPoints1 = Call("_VectorOf" & $typeOfNewPoints1 & "Create")

        $iArrNewPoints1Size = UBound($newPoints1)
        For $i = 0 To $iArrNewPoints1Size - 1
            Call("_VectorOf" & $typeOfNewPoints1 & "Push", $vectorNewPoints1, $newPoints1[$i])
        Next

        $oArrNewPoints1 = Call("_cveOutputArrayFromVectorOf" & $typeOfNewPoints1, $vectorNewPoints1)
    Else
        If $bNewPoints1Create Then
            $newPoints1 = Call("_cve" & $typeOfNewPoints1 & "Create", $newPoints1)
        EndIf
        $oArrNewPoints1 = Call("_cveOutputArrayFrom" & $typeOfNewPoints1, $newPoints1)
    EndIf

    Local $oArrNewPoints2, $vectorNewPoints2, $iArrNewPoints2Size
    Local $bNewPoints2IsArray = IsArray($newPoints2)
    Local $bNewPoints2Create = IsDllStruct($newPoints2) And $typeOfNewPoints2 == "Scalar"

    If $typeOfNewPoints2 == Default Then
        $oArrNewPoints2 = $newPoints2
    ElseIf $bNewPoints2IsArray Then
        $vectorNewPoints2 = Call("_VectorOf" & $typeOfNewPoints2 & "Create")

        $iArrNewPoints2Size = UBound($newPoints2)
        For $i = 0 To $iArrNewPoints2Size - 1
            Call("_VectorOf" & $typeOfNewPoints2 & "Push", $vectorNewPoints2, $newPoints2[$i])
        Next

        $oArrNewPoints2 = Call("_cveOutputArrayFromVectorOf" & $typeOfNewPoints2, $vectorNewPoints2)
    Else
        If $bNewPoints2Create Then
            $newPoints2 = Call("_cve" & $typeOfNewPoints2 & "Create", $newPoints2)
        EndIf
        $oArrNewPoints2 = Call("_cveOutputArrayFrom" & $typeOfNewPoints2, $newPoints2)
    EndIf

    _cveCorrectMatches($iArrF, $iArrPoints1, $iArrPoints2, $oArrNewPoints1, $oArrNewPoints2)

    If $bNewPoints2IsArray Then
        Call("_VectorOf" & $typeOfNewPoints2 & "Release", $vectorNewPoints2)
    EndIf

    If $typeOfNewPoints2 <> Default Then
        _cveOutputArrayRelease($oArrNewPoints2)
        If $bNewPoints2Create Then
            Call("_cve" & $typeOfNewPoints2 & "Release", $newPoints2)
        EndIf
    EndIf

    If $bNewPoints1IsArray Then
        Call("_VectorOf" & $typeOfNewPoints1 & "Release", $vectorNewPoints1)
    EndIf

    If $typeOfNewPoints1 <> Default Then
        _cveOutputArrayRelease($oArrNewPoints1)
        If $bNewPoints1Create Then
            Call("_cve" & $typeOfNewPoints1 & "Release", $newPoints1)
        EndIf
    EndIf

    If $bPoints2IsArray Then
        Call("_VectorOf" & $typeOfPoints2 & "Release", $vectorPoints2)
    EndIf

    If $typeOfPoints2 <> Default Then
        _cveInputArrayRelease($iArrPoints2)
        If $bPoints2Create Then
            Call("_cve" & $typeOfPoints2 & "Release", $points2)
        EndIf
    EndIf

    If $bPoints1IsArray Then
        Call("_VectorOf" & $typeOfPoints1 & "Release", $vectorPoints1)
    EndIf

    If $typeOfPoints1 <> Default Then
        _cveInputArrayRelease($iArrPoints1)
        If $bPoints1Create Then
            Call("_cve" & $typeOfPoints1 & "Release", $points1)
        EndIf
    EndIf

    If $bFIsArray Then
        Call("_VectorOf" & $typeOfF & "Release", $vectorF)
    EndIf

    If $typeOfF <> Default Then
        _cveInputArrayRelease($iArrF)
        If $bFCreate Then
            Call("_cve" & $typeOfF & "Release", $f)
        EndIf
    EndIf
EndFunc   ;==>_cveCorrectMatchesTyped

Func _cveCorrectMatchesMat($f, $points1, $points2, $newPoints1, $newPoints2)
    ; cveCorrectMatches using cv::Mat instead of _*Array
    _cveCorrectMatchesTyped("Mat", $f, "Mat", $points1, "Mat", $points2, "Mat", $newPoints1, "Mat", $newPoints2)
EndFunc   ;==>_cveCorrectMatchesMat

Func _cveFindChessboardCornersSB($image, $patternSize, $corners, $flags)
    ; CVAPI(bool) cveFindChessboardCornersSB(cv::_InputArray* image, CvSize* patternSize, cv::_OutputArray* corners, int flags);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sPatternSizeDllType
    If IsDllStruct($patternSize) Then
        $sPatternSizeDllType = "struct*"
    Else
        $sPatternSizeDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFindChessboardCornersSB", $sImageDllType, $image, $sPatternSizeDllType, $patternSize, $sCornersDllType, $corners, "int", $flags), "cveFindChessboardCornersSB", @error)
EndFunc   ;==>_cveFindChessboardCornersSB

Func _cveFindChessboardCornersSBTyped($typeOfImage, $image, $patternSize, $typeOfCorners, $corners, $flags)

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

    Local $oArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $oArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $oArrCorners = Call("_cveOutputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $oArrCorners = Call("_cveOutputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $retval = _cveFindChessboardCornersSB($iArrImage, $patternSize, $oArrCorners, $flags)

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveOutputArrayRelease($oArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
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

    Return $retval
EndFunc   ;==>_cveFindChessboardCornersSBTyped

Func _cveFindChessboardCornersSBMat($image, $patternSize, $corners, $flags)
    ; cveFindChessboardCornersSB using cv::Mat instead of _*Array
    Local $retval = _cveFindChessboardCornersSBTyped("Mat", $image, $patternSize, "Mat", $corners, $flags)

    Return $retval
EndFunc   ;==>_cveFindChessboardCornersSBMat

Func _cveEstimateChessboardSharpness($image, $patternSize, $corners, $riseDistance, $vertical, $sharpness, $result)
    ; CVAPI(void) cveEstimateChessboardSharpness(cv::_InputArray* image, CvSize* patternSize, cv::_InputArray* corners, float riseDistance, bool vertical, cv::_OutputArray* sharpness, CvScalar* result);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sPatternSizeDllType
    If IsDllStruct($patternSize) Then
        $sPatternSizeDllType = "struct*"
    Else
        $sPatternSizeDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sSharpnessDllType
    If IsDllStruct($sharpness) Then
        $sSharpnessDllType = "struct*"
    Else
        $sSharpnessDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEstimateChessboardSharpness", $sImageDllType, $image, $sPatternSizeDllType, $patternSize, $sCornersDllType, $corners, "float", $riseDistance, "boolean", $vertical, $sSharpnessDllType, $sharpness, $sResultDllType, $result), "cveEstimateChessboardSharpness", @error)
EndFunc   ;==>_cveEstimateChessboardSharpness

Func _cveEstimateChessboardSharpnessTyped($typeOfImage, $image, $patternSize, $typeOfCorners, $corners, $riseDistance, $vertical, $typeOfSharpness, $sharpness, $result)

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

    Local $iArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $iArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $iArrCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $iArrCorners = Call("_cveInputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $oArrSharpness, $vectorSharpness, $iArrSharpnessSize
    Local $bSharpnessIsArray = IsArray($sharpness)
    Local $bSharpnessCreate = IsDllStruct($sharpness) And $typeOfSharpness == "Scalar"

    If $typeOfSharpness == Default Then
        $oArrSharpness = $sharpness
    ElseIf $bSharpnessIsArray Then
        $vectorSharpness = Call("_VectorOf" & $typeOfSharpness & "Create")

        $iArrSharpnessSize = UBound($sharpness)
        For $i = 0 To $iArrSharpnessSize - 1
            Call("_VectorOf" & $typeOfSharpness & "Push", $vectorSharpness, $sharpness[$i])
        Next

        $oArrSharpness = Call("_cveOutputArrayFromVectorOf" & $typeOfSharpness, $vectorSharpness)
    Else
        If $bSharpnessCreate Then
            $sharpness = Call("_cve" & $typeOfSharpness & "Create", $sharpness)
        EndIf
        $oArrSharpness = Call("_cveOutputArrayFrom" & $typeOfSharpness, $sharpness)
    EndIf

    _cveEstimateChessboardSharpness($iArrImage, $patternSize, $iArrCorners, $riseDistance, $vertical, $oArrSharpness, $result)

    If $bSharpnessIsArray Then
        Call("_VectorOf" & $typeOfSharpness & "Release", $vectorSharpness)
    EndIf

    If $typeOfSharpness <> Default Then
        _cveOutputArrayRelease($oArrSharpness)
        If $bSharpnessCreate Then
            Call("_cve" & $typeOfSharpness & "Release", $sharpness)
        EndIf
    EndIf

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputArrayRelease($iArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
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
EndFunc   ;==>_cveEstimateChessboardSharpnessTyped

Func _cveEstimateChessboardSharpnessMat($image, $patternSize, $corners, $riseDistance, $vertical, $sharpness, $result)
    ; cveEstimateChessboardSharpness using cv::Mat instead of _*Array
    _cveEstimateChessboardSharpnessTyped("Mat", $image, $patternSize, "Mat", $corners, $riseDistance, $vertical, "Mat", $sharpness, $result)
EndFunc   ;==>_cveEstimateChessboardSharpnessMat

Func _cveDrawChessboardCorners($image, $patternSize, $corners, $patternWasFound)
    ; CVAPI(void) cveDrawChessboardCorners(cv::_InputOutputArray* image, CvSize* patternSize, cv::_InputArray* corners, bool patternWasFound);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sPatternSizeDllType
    If IsDllStruct($patternSize) Then
        $sPatternSizeDllType = "struct*"
    Else
        $sPatternSizeDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDrawChessboardCorners", $sImageDllType, $image, $sPatternSizeDllType, $patternSize, $sCornersDllType, $corners, "boolean", $patternWasFound), "cveDrawChessboardCorners", @error)
EndFunc   ;==>_cveDrawChessboardCorners

Func _cveDrawChessboardCornersTyped($typeOfImage, $image, $patternSize, $typeOfCorners, $corners, $patternWasFound)

    Local $ioArrImage, $vectorImage, $iArrImageSize
    Local $bImageIsArray = IsArray($image)
    Local $bImageCreate = IsDllStruct($image) And $typeOfImage == "Scalar"

    If $typeOfImage == Default Then
        $ioArrImage = $image
    ElseIf $bImageIsArray Then
        $vectorImage = Call("_VectorOf" & $typeOfImage & "Create")

        $iArrImageSize = UBound($image)
        For $i = 0 To $iArrImageSize - 1
            Call("_VectorOf" & $typeOfImage & "Push", $vectorImage, $image[$i])
        Next

        $ioArrImage = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImage, $vectorImage)
    Else
        If $bImageCreate Then
            $image = Call("_cve" & $typeOfImage & "Create", $image)
        EndIf
        $ioArrImage = Call("_cveInputOutputArrayFrom" & $typeOfImage, $image)
    EndIf

    Local $iArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $iArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $iArrCorners = Call("_cveInputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $iArrCorners = Call("_cveInputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    _cveDrawChessboardCorners($ioArrImage, $patternSize, $iArrCorners, $patternWasFound)

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputArrayRelease($iArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
        EndIf
    EndIf

    If $bImageIsArray Then
        Call("_VectorOf" & $typeOfImage & "Release", $vectorImage)
    EndIf

    If $typeOfImage <> Default Then
        _cveInputOutputArrayRelease($ioArrImage)
        If $bImageCreate Then
            Call("_cve" & $typeOfImage & "Release", $image)
        EndIf
    EndIf
EndFunc   ;==>_cveDrawChessboardCornersTyped

Func _cveDrawChessboardCornersMat($image, $patternSize, $corners, $patternWasFound)
    ; cveDrawChessboardCorners using cv::Mat instead of _*Array
    _cveDrawChessboardCornersTyped("Mat", $image, $patternSize, "Mat", $corners, $patternWasFound)
EndFunc   ;==>_cveDrawChessboardCornersMat

Func _cveFilterSpeckles($img, $newVal, $maxSpeckleSize, $maxDiff, $buf = _cveNoArray())
    ; CVAPI(void) cveFilterSpeckles(cv::_InputOutputArray* img, double newVal, int maxSpeckleSize, double maxDiff, cv::_InputOutputArray* buf);

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sBufDllType
    If IsDllStruct($buf) Then
        $sBufDllType = "struct*"
    Else
        $sBufDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFilterSpeckles", $sImgDllType, $img, "double", $newVal, "int", $maxSpeckleSize, "double", $maxDiff, $sBufDllType, $buf), "cveFilterSpeckles", @error)
EndFunc   ;==>_cveFilterSpeckles

Func _cveFilterSpecklesTyped($typeOfImg, $img, $newVal, $maxSpeckleSize, $maxDiff, $typeOfBuf = Default, $buf = _cveNoArray())

    Local $ioArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $ioArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $ioArrImg = Call("_cveInputOutputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $ioArrImg = Call("_cveInputOutputArrayFrom" & $typeOfImg, $img)
    EndIf

    Local $ioArrBuf, $vectorBuf, $iArrBufSize
    Local $bBufIsArray = IsArray($buf)
    Local $bBufCreate = IsDllStruct($buf) And $typeOfBuf == "Scalar"

    If $typeOfBuf == Default Then
        $ioArrBuf = $buf
    ElseIf $bBufIsArray Then
        $vectorBuf = Call("_VectorOf" & $typeOfBuf & "Create")

        $iArrBufSize = UBound($buf)
        For $i = 0 To $iArrBufSize - 1
            Call("_VectorOf" & $typeOfBuf & "Push", $vectorBuf, $buf[$i])
        Next

        $ioArrBuf = Call("_cveInputOutputArrayFromVectorOf" & $typeOfBuf, $vectorBuf)
    Else
        If $bBufCreate Then
            $buf = Call("_cve" & $typeOfBuf & "Create", $buf)
        EndIf
        $ioArrBuf = Call("_cveInputOutputArrayFrom" & $typeOfBuf, $buf)
    EndIf

    _cveFilterSpeckles($ioArrImg, $newVal, $maxSpeckleSize, $maxDiff, $ioArrBuf)

    If $bBufIsArray Then
        Call("_VectorOf" & $typeOfBuf & "Release", $vectorBuf)
    EndIf

    If $typeOfBuf <> Default Then
        _cveInputOutputArrayRelease($ioArrBuf)
        If $bBufCreate Then
            Call("_cve" & $typeOfBuf & "Release", $buf)
        EndIf
    EndIf

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputOutputArrayRelease($ioArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveFilterSpecklesTyped

Func _cveFilterSpecklesMat($img, $newVal, $maxSpeckleSize, $maxDiff, $buf = _cveNoArrayMat())
    ; cveFilterSpeckles using cv::Mat instead of _*Array
    _cveFilterSpecklesTyped("Mat", $img, $newVal, $maxSpeckleSize, $maxDiff, "Mat", $buf)
EndFunc   ;==>_cveFilterSpecklesMat

Func _cveFindChessboardCorners($image, $patternSize, $corners, $flags = $CV_CALIB_CB_ADAPTIVE_THRESH + $CV_CALIB_CB_NORMALIZE_IMAGE)
    ; CVAPI(bool) cveFindChessboardCorners(cv::_InputArray* image, CvSize* patternSize, cv::_OutputArray* corners, int flags);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sPatternSizeDllType
    If IsDllStruct($patternSize) Then
        $sPatternSizeDllType = "struct*"
    Else
        $sPatternSizeDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFindChessboardCorners", $sImageDllType, $image, $sPatternSizeDllType, $patternSize, $sCornersDllType, $corners, "int", $flags), "cveFindChessboardCorners", @error)
EndFunc   ;==>_cveFindChessboardCorners

Func _cveFindChessboardCornersTyped($typeOfImage, $image, $patternSize, $typeOfCorners, $corners, $flags = $CV_CALIB_CB_ADAPTIVE_THRESH + $CV_CALIB_CB_NORMALIZE_IMAGE)

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

    Local $oArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $oArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $oArrCorners = Call("_cveOutputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $oArrCorners = Call("_cveOutputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $retval = _cveFindChessboardCorners($iArrImage, $patternSize, $oArrCorners, $flags)

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveOutputArrayRelease($oArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
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

    Return $retval
EndFunc   ;==>_cveFindChessboardCornersTyped

Func _cveFindChessboardCornersMat($image, $patternSize, $corners, $flags = $CV_CALIB_CB_ADAPTIVE_THRESH + $CV_CALIB_CB_NORMALIZE_IMAGE)
    ; cveFindChessboardCorners using cv::Mat instead of _*Array
    Local $retval = _cveFindChessboardCornersTyped("Mat", $image, $patternSize, "Mat", $corners, $flags)

    Return $retval
EndFunc   ;==>_cveFindChessboardCornersMat

Func _cveFind4QuadCornerSubpix($image, $corners, $regionSize)
    ; CVAPI(bool) cveFind4QuadCornerSubpix(cv::_InputArray* image, cv::_InputOutputArray* corners, CvSize* regionSize);

    Local $sImageDllType
    If IsDllStruct($image) Then
        $sImageDllType = "struct*"
    Else
        $sImageDllType = "ptr"
    EndIf

    Local $sCornersDllType
    If IsDllStruct($corners) Then
        $sCornersDllType = "struct*"
    Else
        $sCornersDllType = "ptr"
    EndIf

    Local $sRegionSizeDllType
    If IsDllStruct($regionSize) Then
        $sRegionSizeDllType = "struct*"
    Else
        $sRegionSizeDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveFind4QuadCornerSubpix", $sImageDllType, $image, $sCornersDllType, $corners, $sRegionSizeDllType, $regionSize), "cveFind4QuadCornerSubpix", @error)
EndFunc   ;==>_cveFind4QuadCornerSubpix

Func _cveFind4QuadCornerSubpixTyped($typeOfImage, $image, $typeOfCorners, $corners, $regionSize)

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

    Local $ioArrCorners, $vectorCorners, $iArrCornersSize
    Local $bCornersIsArray = IsArray($corners)
    Local $bCornersCreate = IsDllStruct($corners) And $typeOfCorners == "Scalar"

    If $typeOfCorners == Default Then
        $ioArrCorners = $corners
    ElseIf $bCornersIsArray Then
        $vectorCorners = Call("_VectorOf" & $typeOfCorners & "Create")

        $iArrCornersSize = UBound($corners)
        For $i = 0 To $iArrCornersSize - 1
            Call("_VectorOf" & $typeOfCorners & "Push", $vectorCorners, $corners[$i])
        Next

        $ioArrCorners = Call("_cveInputOutputArrayFromVectorOf" & $typeOfCorners, $vectorCorners)
    Else
        If $bCornersCreate Then
            $corners = Call("_cve" & $typeOfCorners & "Create", $corners)
        EndIf
        $ioArrCorners = Call("_cveInputOutputArrayFrom" & $typeOfCorners, $corners)
    EndIf

    Local $retval = _cveFind4QuadCornerSubpix($iArrImage, $ioArrCorners, $regionSize)

    If $bCornersIsArray Then
        Call("_VectorOf" & $typeOfCorners & "Release", $vectorCorners)
    EndIf

    If $typeOfCorners <> Default Then
        _cveInputOutputArrayRelease($ioArrCorners)
        If $bCornersCreate Then
            Call("_cve" & $typeOfCorners & "Release", $corners)
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

    Return $retval
EndFunc   ;==>_cveFind4QuadCornerSubpixTyped

Func _cveFind4QuadCornerSubpixMat($image, $corners, $regionSize)
    ; cveFind4QuadCornerSubpix using cv::Mat instead of _*Array
    Local $retval = _cveFind4QuadCornerSubpixTyped("Mat", $image, "Mat", $corners, $regionSize)

    Return $retval
EndFunc   ;==>_cveFind4QuadCornerSubpixMat

Func _cveStereoRectifyUncalibrated($points1, $points2, $f, $imgSize, $h1, $h2, $threshold = 5)
    ; CVAPI(bool) cveStereoRectifyUncalibrated(cv::_InputArray* points1, cv::_InputArray* points2, cv::_InputArray* f, CvSize* imgSize, cv::_OutputArray* h1, cv::_OutputArray* h2, double threshold);

    Local $sPoints1DllType
    If IsDllStruct($points1) Then
        $sPoints1DllType = "struct*"
    Else
        $sPoints1DllType = "ptr"
    EndIf

    Local $sPoints2DllType
    If IsDllStruct($points2) Then
        $sPoints2DllType = "struct*"
    Else
        $sPoints2DllType = "ptr"
    EndIf

    Local $sFDllType
    If IsDllStruct($f) Then
        $sFDllType = "struct*"
    Else
        $sFDllType = "ptr"
    EndIf

    Local $sImgSizeDllType
    If IsDllStruct($imgSize) Then
        $sImgSizeDllType = "struct*"
    Else
        $sImgSizeDllType = "ptr"
    EndIf

    Local $sH1DllType
    If IsDllStruct($h1) Then
        $sH1DllType = "struct*"
    Else
        $sH1DllType = "ptr"
    EndIf

    Local $sH2DllType
    If IsDllStruct($h2) Then
        $sH2DllType = "struct*"
    Else
        $sH2DllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveStereoRectifyUncalibrated", $sPoints1DllType, $points1, $sPoints2DllType, $points2, $sFDllType, $f, $sImgSizeDllType, $imgSize, $sH1DllType, $h1, $sH2DllType, $h2, "double", $threshold), "cveStereoRectifyUncalibrated", @error)
EndFunc   ;==>_cveStereoRectifyUncalibrated

Func _cveStereoRectifyUncalibratedTyped($typeOfPoints1, $points1, $typeOfPoints2, $points2, $typeOfF, $f, $imgSize, $typeOfH1, $h1, $typeOfH2, $h2, $threshold = 5)

    Local $iArrPoints1, $vectorPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = IsArray($points1)
    Local $bPoints1Create = IsDllStruct($points1) And $typeOfPoints1 == "Scalar"

    If $typeOfPoints1 == Default Then
        $iArrPoints1 = $points1
    ElseIf $bPoints1IsArray Then
        $vectorPoints1 = Call("_VectorOf" & $typeOfPoints1 & "Create")

        $iArrPoints1Size = UBound($points1)
        For $i = 0 To $iArrPoints1Size - 1
            Call("_VectorOf" & $typeOfPoints1 & "Push", $vectorPoints1, $points1[$i])
        Next

        $iArrPoints1 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints1, $vectorPoints1)
    Else
        If $bPoints1Create Then
            $points1 = Call("_cve" & $typeOfPoints1 & "Create", $points1)
        EndIf
        $iArrPoints1 = Call("_cveInputArrayFrom" & $typeOfPoints1, $points1)
    EndIf

    Local $iArrPoints2, $vectorPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = IsArray($points2)
    Local $bPoints2Create = IsDllStruct($points2) And $typeOfPoints2 == "Scalar"

    If $typeOfPoints2 == Default Then
        $iArrPoints2 = $points2
    ElseIf $bPoints2IsArray Then
        $vectorPoints2 = Call("_VectorOf" & $typeOfPoints2 & "Create")

        $iArrPoints2Size = UBound($points2)
        For $i = 0 To $iArrPoints2Size - 1
            Call("_VectorOf" & $typeOfPoints2 & "Push", $vectorPoints2, $points2[$i])
        Next

        $iArrPoints2 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints2, $vectorPoints2)
    Else
        If $bPoints2Create Then
            $points2 = Call("_cve" & $typeOfPoints2 & "Create", $points2)
        EndIf
        $iArrPoints2 = Call("_cveInputArrayFrom" & $typeOfPoints2, $points2)
    EndIf

    Local $iArrF, $vectorF, $iArrFSize
    Local $bFIsArray = IsArray($f)
    Local $bFCreate = IsDllStruct($f) And $typeOfF == "Scalar"

    If $typeOfF == Default Then
        $iArrF = $f
    ElseIf $bFIsArray Then
        $vectorF = Call("_VectorOf" & $typeOfF & "Create")

        $iArrFSize = UBound($f)
        For $i = 0 To $iArrFSize - 1
            Call("_VectorOf" & $typeOfF & "Push", $vectorF, $f[$i])
        Next

        $iArrF = Call("_cveInputArrayFromVectorOf" & $typeOfF, $vectorF)
    Else
        If $bFCreate Then
            $f = Call("_cve" & $typeOfF & "Create", $f)
        EndIf
        $iArrF = Call("_cveInputArrayFrom" & $typeOfF, $f)
    EndIf

    Local $oArrH1, $vectorH1, $iArrH1Size
    Local $bH1IsArray = IsArray($h1)
    Local $bH1Create = IsDllStruct($h1) And $typeOfH1 == "Scalar"

    If $typeOfH1 == Default Then
        $oArrH1 = $h1
    ElseIf $bH1IsArray Then
        $vectorH1 = Call("_VectorOf" & $typeOfH1 & "Create")

        $iArrH1Size = UBound($h1)
        For $i = 0 To $iArrH1Size - 1
            Call("_VectorOf" & $typeOfH1 & "Push", $vectorH1, $h1[$i])
        Next

        $oArrH1 = Call("_cveOutputArrayFromVectorOf" & $typeOfH1, $vectorH1)
    Else
        If $bH1Create Then
            $h1 = Call("_cve" & $typeOfH1 & "Create", $h1)
        EndIf
        $oArrH1 = Call("_cveOutputArrayFrom" & $typeOfH1, $h1)
    EndIf

    Local $oArrH2, $vectorH2, $iArrH2Size
    Local $bH2IsArray = IsArray($h2)
    Local $bH2Create = IsDllStruct($h2) And $typeOfH2 == "Scalar"

    If $typeOfH2 == Default Then
        $oArrH2 = $h2
    ElseIf $bH2IsArray Then
        $vectorH2 = Call("_VectorOf" & $typeOfH2 & "Create")

        $iArrH2Size = UBound($h2)
        For $i = 0 To $iArrH2Size - 1
            Call("_VectorOf" & $typeOfH2 & "Push", $vectorH2, $h2[$i])
        Next

        $oArrH2 = Call("_cveOutputArrayFromVectorOf" & $typeOfH2, $vectorH2)
    Else
        If $bH2Create Then
            $h2 = Call("_cve" & $typeOfH2 & "Create", $h2)
        EndIf
        $oArrH2 = Call("_cveOutputArrayFrom" & $typeOfH2, $h2)
    EndIf

    Local $retval = _cveStereoRectifyUncalibrated($iArrPoints1, $iArrPoints2, $iArrF, $imgSize, $oArrH1, $oArrH2, $threshold)

    If $bH2IsArray Then
        Call("_VectorOf" & $typeOfH2 & "Release", $vectorH2)
    EndIf

    If $typeOfH2 <> Default Then
        _cveOutputArrayRelease($oArrH2)
        If $bH2Create Then
            Call("_cve" & $typeOfH2 & "Release", $h2)
        EndIf
    EndIf

    If $bH1IsArray Then
        Call("_VectorOf" & $typeOfH1 & "Release", $vectorH1)
    EndIf

    If $typeOfH1 <> Default Then
        _cveOutputArrayRelease($oArrH1)
        If $bH1Create Then
            Call("_cve" & $typeOfH1 & "Release", $h1)
        EndIf
    EndIf

    If $bFIsArray Then
        Call("_VectorOf" & $typeOfF & "Release", $vectorF)
    EndIf

    If $typeOfF <> Default Then
        _cveInputArrayRelease($iArrF)
        If $bFCreate Then
            Call("_cve" & $typeOfF & "Release", $f)
        EndIf
    EndIf

    If $bPoints2IsArray Then
        Call("_VectorOf" & $typeOfPoints2 & "Release", $vectorPoints2)
    EndIf

    If $typeOfPoints2 <> Default Then
        _cveInputArrayRelease($iArrPoints2)
        If $bPoints2Create Then
            Call("_cve" & $typeOfPoints2 & "Release", $points2)
        EndIf
    EndIf

    If $bPoints1IsArray Then
        Call("_VectorOf" & $typeOfPoints1 & "Release", $vectorPoints1)
    EndIf

    If $typeOfPoints1 <> Default Then
        _cveInputArrayRelease($iArrPoints1)
        If $bPoints1Create Then
            Call("_cve" & $typeOfPoints1 & "Release", $points1)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveStereoRectifyUncalibratedTyped

Func _cveStereoRectifyUncalibratedMat($points1, $points2, $f, $imgSize, $h1, $h2, $threshold = 5)
    ; cveStereoRectifyUncalibrated using cv::Mat instead of _*Array
    Local $retval = _cveStereoRectifyUncalibratedTyped("Mat", $points1, "Mat", $points2, "Mat", $f, $imgSize, "Mat", $h1, "Mat", $h2, $threshold)

    Return $retval
EndFunc   ;==>_cveStereoRectifyUncalibratedMat

Func _cveStereoRectify($cameraMatrix1, $distCoeffs1, $cameraMatrix2, $distCoeffs2, $imageSize, $r, $t, $r1, $r2, $p1, $p2, $q, $flags = $CV_CALIB_ZERO_DISPARITY, $alpha = -1, $newImageSize = _cvSize(), $validPixROI1 = 0, $validPixROI2 = 0)
    ; CVAPI(void) cveStereoRectify(cv::_InputArray* cameraMatrix1, cv::_InputArray* distCoeffs1, cv::_InputArray* cameraMatrix2, cv::_InputArray* distCoeffs2, CvSize* imageSize, cv::_InputArray* r, cv::_InputArray* t, cv::_OutputArray* r1, cv::_OutputArray* r2, cv::_OutputArray* p1, cv::_OutputArray* p2, cv::_OutputArray* q, int flags, double alpha, CvSize* newImageSize, CvRect* validPixROI1, CvRect* validPixROI2);

    Local $sCameraMatrix1DllType
    If IsDllStruct($cameraMatrix1) Then
        $sCameraMatrix1DllType = "struct*"
    Else
        $sCameraMatrix1DllType = "ptr"
    EndIf

    Local $sDistCoeffs1DllType
    If IsDllStruct($distCoeffs1) Then
        $sDistCoeffs1DllType = "struct*"
    Else
        $sDistCoeffs1DllType = "ptr"
    EndIf

    Local $sCameraMatrix2DllType
    If IsDllStruct($cameraMatrix2) Then
        $sCameraMatrix2DllType = "struct*"
    Else
        $sCameraMatrix2DllType = "ptr"
    EndIf

    Local $sDistCoeffs2DllType
    If IsDllStruct($distCoeffs2) Then
        $sDistCoeffs2DllType = "struct*"
    Else
        $sDistCoeffs2DllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($r) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sTDllType
    If IsDllStruct($t) Then
        $sTDllType = "struct*"
    Else
        $sTDllType = "ptr"
    EndIf

    Local $sR1DllType
    If IsDllStruct($r1) Then
        $sR1DllType = "struct*"
    Else
        $sR1DllType = "ptr"
    EndIf

    Local $sR2DllType
    If IsDllStruct($r2) Then
        $sR2DllType = "struct*"
    Else
        $sR2DllType = "ptr"
    EndIf

    Local $sP1DllType
    If IsDllStruct($p1) Then
        $sP1DllType = "struct*"
    Else
        $sP1DllType = "ptr"
    EndIf

    Local $sP2DllType
    If IsDllStruct($p2) Then
        $sP2DllType = "struct*"
    Else
        $sP2DllType = "ptr"
    EndIf

    Local $sQDllType
    If IsDllStruct($q) Then
        $sQDllType = "struct*"
    Else
        $sQDllType = "ptr"
    EndIf

    Local $sNewImageSizeDllType
    If IsDllStruct($newImageSize) Then
        $sNewImageSizeDllType = "struct*"
    Else
        $sNewImageSizeDllType = "ptr"
    EndIf

    Local $sValidPixROI1DllType
    If IsDllStruct($validPixROI1) Then
        $sValidPixROI1DllType = "struct*"
    Else
        $sValidPixROI1DllType = "ptr"
    EndIf

    Local $sValidPixROI2DllType
    If IsDllStruct($validPixROI2) Then
        $sValidPixROI2DllType = "struct*"
    Else
        $sValidPixROI2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveStereoRectify", $sCameraMatrix1DllType, $cameraMatrix1, $sDistCoeffs1DllType, $distCoeffs1, $sCameraMatrix2DllType, $cameraMatrix2, $sDistCoeffs2DllType, $distCoeffs2, $sImageSizeDllType, $imageSize, $sRDllType, $r, $sTDllType, $t, $sR1DllType, $r1, $sR2DllType, $r2, $sP1DllType, $p1, $sP2DllType, $p2, $sQDllType, $q, "int", $flags, "double", $alpha, $sNewImageSizeDllType, $newImageSize, $sValidPixROI1DllType, $validPixROI1, $sValidPixROI2DllType, $validPixROI2), "cveStereoRectify", @error)
EndFunc   ;==>_cveStereoRectify

Func _cveStereoRectifyTyped($typeOfCameraMatrix1, $cameraMatrix1, $typeOfDistCoeffs1, $distCoeffs1, $typeOfCameraMatrix2, $cameraMatrix2, $typeOfDistCoeffs2, $distCoeffs2, $imageSize, $typeOfR, $r, $typeOfT, $t, $typeOfR1, $r1, $typeOfR2, $r2, $typeOfP1, $p1, $typeOfP2, $p2, $typeOfQ, $q, $flags = $CV_CALIB_ZERO_DISPARITY, $alpha = -1, $newImageSize = _cvSize(), $validPixROI1 = 0, $validPixROI2 = 0)

    Local $iArrCameraMatrix1, $vectorCameraMatrix1, $iArrCameraMatrix1Size
    Local $bCameraMatrix1IsArray = IsArray($cameraMatrix1)
    Local $bCameraMatrix1Create = IsDllStruct($cameraMatrix1) And $typeOfCameraMatrix1 == "Scalar"

    If $typeOfCameraMatrix1 == Default Then
        $iArrCameraMatrix1 = $cameraMatrix1
    ElseIf $bCameraMatrix1IsArray Then
        $vectorCameraMatrix1 = Call("_VectorOf" & $typeOfCameraMatrix1 & "Create")

        $iArrCameraMatrix1Size = UBound($cameraMatrix1)
        For $i = 0 To $iArrCameraMatrix1Size - 1
            Call("_VectorOf" & $typeOfCameraMatrix1 & "Push", $vectorCameraMatrix1, $cameraMatrix1[$i])
        Next

        $iArrCameraMatrix1 = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix1, $vectorCameraMatrix1)
    Else
        If $bCameraMatrix1Create Then
            $cameraMatrix1 = Call("_cve" & $typeOfCameraMatrix1 & "Create", $cameraMatrix1)
        EndIf
        $iArrCameraMatrix1 = Call("_cveInputArrayFrom" & $typeOfCameraMatrix1, $cameraMatrix1)
    EndIf

    Local $iArrDistCoeffs1, $vectorDistCoeffs1, $iArrDistCoeffs1Size
    Local $bDistCoeffs1IsArray = IsArray($distCoeffs1)
    Local $bDistCoeffs1Create = IsDllStruct($distCoeffs1) And $typeOfDistCoeffs1 == "Scalar"

    If $typeOfDistCoeffs1 == Default Then
        $iArrDistCoeffs1 = $distCoeffs1
    ElseIf $bDistCoeffs1IsArray Then
        $vectorDistCoeffs1 = Call("_VectorOf" & $typeOfDistCoeffs1 & "Create")

        $iArrDistCoeffs1Size = UBound($distCoeffs1)
        For $i = 0 To $iArrDistCoeffs1Size - 1
            Call("_VectorOf" & $typeOfDistCoeffs1 & "Push", $vectorDistCoeffs1, $distCoeffs1[$i])
        Next

        $iArrDistCoeffs1 = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs1, $vectorDistCoeffs1)
    Else
        If $bDistCoeffs1Create Then
            $distCoeffs1 = Call("_cve" & $typeOfDistCoeffs1 & "Create", $distCoeffs1)
        EndIf
        $iArrDistCoeffs1 = Call("_cveInputArrayFrom" & $typeOfDistCoeffs1, $distCoeffs1)
    EndIf

    Local $iArrCameraMatrix2, $vectorCameraMatrix2, $iArrCameraMatrix2Size
    Local $bCameraMatrix2IsArray = IsArray($cameraMatrix2)
    Local $bCameraMatrix2Create = IsDllStruct($cameraMatrix2) And $typeOfCameraMatrix2 == "Scalar"

    If $typeOfCameraMatrix2 == Default Then
        $iArrCameraMatrix2 = $cameraMatrix2
    ElseIf $bCameraMatrix2IsArray Then
        $vectorCameraMatrix2 = Call("_VectorOf" & $typeOfCameraMatrix2 & "Create")

        $iArrCameraMatrix2Size = UBound($cameraMatrix2)
        For $i = 0 To $iArrCameraMatrix2Size - 1
            Call("_VectorOf" & $typeOfCameraMatrix2 & "Push", $vectorCameraMatrix2, $cameraMatrix2[$i])
        Next

        $iArrCameraMatrix2 = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix2, $vectorCameraMatrix2)
    Else
        If $bCameraMatrix2Create Then
            $cameraMatrix2 = Call("_cve" & $typeOfCameraMatrix2 & "Create", $cameraMatrix2)
        EndIf
        $iArrCameraMatrix2 = Call("_cveInputArrayFrom" & $typeOfCameraMatrix2, $cameraMatrix2)
    EndIf

    Local $iArrDistCoeffs2, $vectorDistCoeffs2, $iArrDistCoeffs2Size
    Local $bDistCoeffs2IsArray = IsArray($distCoeffs2)
    Local $bDistCoeffs2Create = IsDllStruct($distCoeffs2) And $typeOfDistCoeffs2 == "Scalar"

    If $typeOfDistCoeffs2 == Default Then
        $iArrDistCoeffs2 = $distCoeffs2
    ElseIf $bDistCoeffs2IsArray Then
        $vectorDistCoeffs2 = Call("_VectorOf" & $typeOfDistCoeffs2 & "Create")

        $iArrDistCoeffs2Size = UBound($distCoeffs2)
        For $i = 0 To $iArrDistCoeffs2Size - 1
            Call("_VectorOf" & $typeOfDistCoeffs2 & "Push", $vectorDistCoeffs2, $distCoeffs2[$i])
        Next

        $iArrDistCoeffs2 = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs2, $vectorDistCoeffs2)
    Else
        If $bDistCoeffs2Create Then
            $distCoeffs2 = Call("_cve" & $typeOfDistCoeffs2 & "Create", $distCoeffs2)
        EndIf
        $iArrDistCoeffs2 = Call("_cveInputArrayFrom" & $typeOfDistCoeffs2, $distCoeffs2)
    EndIf

    Local $iArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($r)
    Local $bRCreate = IsDllStruct($r) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $iArrR = $r
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($r)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $r[$i])
        Next

        $iArrR = Call("_cveInputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $r = Call("_cve" & $typeOfR & "Create", $r)
        EndIf
        $iArrR = Call("_cveInputArrayFrom" & $typeOfR, $r)
    EndIf

    Local $iArrT, $vectorT, $iArrTSize
    Local $bTIsArray = IsArray($t)
    Local $bTCreate = IsDllStruct($t) And $typeOfT == "Scalar"

    If $typeOfT == Default Then
        $iArrT = $t
    ElseIf $bTIsArray Then
        $vectorT = Call("_VectorOf" & $typeOfT & "Create")

        $iArrTSize = UBound($t)
        For $i = 0 To $iArrTSize - 1
            Call("_VectorOf" & $typeOfT & "Push", $vectorT, $t[$i])
        Next

        $iArrT = Call("_cveInputArrayFromVectorOf" & $typeOfT, $vectorT)
    Else
        If $bTCreate Then
            $t = Call("_cve" & $typeOfT & "Create", $t)
        EndIf
        $iArrT = Call("_cveInputArrayFrom" & $typeOfT, $t)
    EndIf

    Local $oArrR1, $vectorR1, $iArrR1Size
    Local $bR1IsArray = IsArray($r1)
    Local $bR1Create = IsDllStruct($r1) And $typeOfR1 == "Scalar"

    If $typeOfR1 == Default Then
        $oArrR1 = $r1
    ElseIf $bR1IsArray Then
        $vectorR1 = Call("_VectorOf" & $typeOfR1 & "Create")

        $iArrR1Size = UBound($r1)
        For $i = 0 To $iArrR1Size - 1
            Call("_VectorOf" & $typeOfR1 & "Push", $vectorR1, $r1[$i])
        Next

        $oArrR1 = Call("_cveOutputArrayFromVectorOf" & $typeOfR1, $vectorR1)
    Else
        If $bR1Create Then
            $r1 = Call("_cve" & $typeOfR1 & "Create", $r1)
        EndIf
        $oArrR1 = Call("_cveOutputArrayFrom" & $typeOfR1, $r1)
    EndIf

    Local $oArrR2, $vectorR2, $iArrR2Size
    Local $bR2IsArray = IsArray($r2)
    Local $bR2Create = IsDllStruct($r2) And $typeOfR2 == "Scalar"

    If $typeOfR2 == Default Then
        $oArrR2 = $r2
    ElseIf $bR2IsArray Then
        $vectorR2 = Call("_VectorOf" & $typeOfR2 & "Create")

        $iArrR2Size = UBound($r2)
        For $i = 0 To $iArrR2Size - 1
            Call("_VectorOf" & $typeOfR2 & "Push", $vectorR2, $r2[$i])
        Next

        $oArrR2 = Call("_cveOutputArrayFromVectorOf" & $typeOfR2, $vectorR2)
    Else
        If $bR2Create Then
            $r2 = Call("_cve" & $typeOfR2 & "Create", $r2)
        EndIf
        $oArrR2 = Call("_cveOutputArrayFrom" & $typeOfR2, $r2)
    EndIf

    Local $oArrP1, $vectorP1, $iArrP1Size
    Local $bP1IsArray = IsArray($p1)
    Local $bP1Create = IsDllStruct($p1) And $typeOfP1 == "Scalar"

    If $typeOfP1 == Default Then
        $oArrP1 = $p1
    ElseIf $bP1IsArray Then
        $vectorP1 = Call("_VectorOf" & $typeOfP1 & "Create")

        $iArrP1Size = UBound($p1)
        For $i = 0 To $iArrP1Size - 1
            Call("_VectorOf" & $typeOfP1 & "Push", $vectorP1, $p1[$i])
        Next

        $oArrP1 = Call("_cveOutputArrayFromVectorOf" & $typeOfP1, $vectorP1)
    Else
        If $bP1Create Then
            $p1 = Call("_cve" & $typeOfP1 & "Create", $p1)
        EndIf
        $oArrP1 = Call("_cveOutputArrayFrom" & $typeOfP1, $p1)
    EndIf

    Local $oArrP2, $vectorP2, $iArrP2Size
    Local $bP2IsArray = IsArray($p2)
    Local $bP2Create = IsDllStruct($p2) And $typeOfP2 == "Scalar"

    If $typeOfP2 == Default Then
        $oArrP2 = $p2
    ElseIf $bP2IsArray Then
        $vectorP2 = Call("_VectorOf" & $typeOfP2 & "Create")

        $iArrP2Size = UBound($p2)
        For $i = 0 To $iArrP2Size - 1
            Call("_VectorOf" & $typeOfP2 & "Push", $vectorP2, $p2[$i])
        Next

        $oArrP2 = Call("_cveOutputArrayFromVectorOf" & $typeOfP2, $vectorP2)
    Else
        If $bP2Create Then
            $p2 = Call("_cve" & $typeOfP2 & "Create", $p2)
        EndIf
        $oArrP2 = Call("_cveOutputArrayFrom" & $typeOfP2, $p2)
    EndIf

    Local $oArrQ, $vectorQ, $iArrQSize
    Local $bQIsArray = IsArray($q)
    Local $bQCreate = IsDllStruct($q) And $typeOfQ == "Scalar"

    If $typeOfQ == Default Then
        $oArrQ = $q
    ElseIf $bQIsArray Then
        $vectorQ = Call("_VectorOf" & $typeOfQ & "Create")

        $iArrQSize = UBound($q)
        For $i = 0 To $iArrQSize - 1
            Call("_VectorOf" & $typeOfQ & "Push", $vectorQ, $q[$i])
        Next

        $oArrQ = Call("_cveOutputArrayFromVectorOf" & $typeOfQ, $vectorQ)
    Else
        If $bQCreate Then
            $q = Call("_cve" & $typeOfQ & "Create", $q)
        EndIf
        $oArrQ = Call("_cveOutputArrayFrom" & $typeOfQ, $q)
    EndIf

    _cveStereoRectify($iArrCameraMatrix1, $iArrDistCoeffs1, $iArrCameraMatrix2, $iArrDistCoeffs2, $imageSize, $iArrR, $iArrT, $oArrR1, $oArrR2, $oArrP1, $oArrP2, $oArrQ, $flags, $alpha, $newImageSize, $validPixROI1, $validPixROI2)

    If $bQIsArray Then
        Call("_VectorOf" & $typeOfQ & "Release", $vectorQ)
    EndIf

    If $typeOfQ <> Default Then
        _cveOutputArrayRelease($oArrQ)
        If $bQCreate Then
            Call("_cve" & $typeOfQ & "Release", $q)
        EndIf
    EndIf

    If $bP2IsArray Then
        Call("_VectorOf" & $typeOfP2 & "Release", $vectorP2)
    EndIf

    If $typeOfP2 <> Default Then
        _cveOutputArrayRelease($oArrP2)
        If $bP2Create Then
            Call("_cve" & $typeOfP2 & "Release", $p2)
        EndIf
    EndIf

    If $bP1IsArray Then
        Call("_VectorOf" & $typeOfP1 & "Release", $vectorP1)
    EndIf

    If $typeOfP1 <> Default Then
        _cveOutputArrayRelease($oArrP1)
        If $bP1Create Then
            Call("_cve" & $typeOfP1 & "Release", $p1)
        EndIf
    EndIf

    If $bR2IsArray Then
        Call("_VectorOf" & $typeOfR2 & "Release", $vectorR2)
    EndIf

    If $typeOfR2 <> Default Then
        _cveOutputArrayRelease($oArrR2)
        If $bR2Create Then
            Call("_cve" & $typeOfR2 & "Release", $r2)
        EndIf
    EndIf

    If $bR1IsArray Then
        Call("_VectorOf" & $typeOfR1 & "Release", $vectorR1)
    EndIf

    If $typeOfR1 <> Default Then
        _cveOutputArrayRelease($oArrR1)
        If $bR1Create Then
            Call("_cve" & $typeOfR1 & "Release", $r1)
        EndIf
    EndIf

    If $bTIsArray Then
        Call("_VectorOf" & $typeOfT & "Release", $vectorT)
    EndIf

    If $typeOfT <> Default Then
        _cveInputArrayRelease($iArrT)
        If $bTCreate Then
            Call("_cve" & $typeOfT & "Release", $t)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveInputArrayRelease($iArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $r)
        EndIf
    EndIf

    If $bDistCoeffs2IsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs2 & "Release", $vectorDistCoeffs2)
    EndIf

    If $typeOfDistCoeffs2 <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs2)
        If $bDistCoeffs2Create Then
            Call("_cve" & $typeOfDistCoeffs2 & "Release", $distCoeffs2)
        EndIf
    EndIf

    If $bCameraMatrix2IsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix2 & "Release", $vectorCameraMatrix2)
    EndIf

    If $typeOfCameraMatrix2 <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix2)
        If $bCameraMatrix2Create Then
            Call("_cve" & $typeOfCameraMatrix2 & "Release", $cameraMatrix2)
        EndIf
    EndIf

    If $bDistCoeffs1IsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs1 & "Release", $vectorDistCoeffs1)
    EndIf

    If $typeOfDistCoeffs1 <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs1)
        If $bDistCoeffs1Create Then
            Call("_cve" & $typeOfDistCoeffs1 & "Release", $distCoeffs1)
        EndIf
    EndIf

    If $bCameraMatrix1IsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix1 & "Release", $vectorCameraMatrix1)
    EndIf

    If $typeOfCameraMatrix1 <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix1)
        If $bCameraMatrix1Create Then
            Call("_cve" & $typeOfCameraMatrix1 & "Release", $cameraMatrix1)
        EndIf
    EndIf
EndFunc   ;==>_cveStereoRectifyTyped

Func _cveStereoRectifyMat($cameraMatrix1, $distCoeffs1, $cameraMatrix2, $distCoeffs2, $imageSize, $r, $t, $r1, $r2, $p1, $p2, $q, $flags = $CV_CALIB_ZERO_DISPARITY, $alpha = -1, $newImageSize = _cvSize(), $validPixROI1 = 0, $validPixROI2 = 0)
    ; cveStereoRectify using cv::Mat instead of _*Array
    _cveStereoRectifyTyped("Mat", $cameraMatrix1, "Mat", $distCoeffs1, "Mat", $cameraMatrix2, "Mat", $distCoeffs2, $imageSize, "Mat", $r, "Mat", $t, "Mat", $r1, "Mat", $r2, "Mat", $p1, "Mat", $p2, "Mat", $q, $flags, $alpha, $newImageSize, $validPixROI1, $validPixROI2)
EndFunc   ;==>_cveStereoRectifyMat

Func _cveRodrigues($src, $dst, $jacobian = _cveNoArray())
    ; CVAPI(void) cveRodrigues(cv::_InputArray* src, cv::_OutputArray* dst, cv::_OutputArray* jacobian);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sJacobianDllType
    If IsDllStruct($jacobian) Then
        $sJacobianDllType = "struct*"
    Else
        $sJacobianDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRodrigues", $sSrcDllType, $src, $sDstDllType, $dst, $sJacobianDllType, $jacobian), "cveRodrigues", @error)
EndFunc   ;==>_cveRodrigues

Func _cveRodriguesTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfJacobian = Default, $jacobian = _cveNoArray())

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $oArrJacobian, $vectorJacobian, $iArrJacobianSize
    Local $bJacobianIsArray = IsArray($jacobian)
    Local $bJacobianCreate = IsDllStruct($jacobian) And $typeOfJacobian == "Scalar"

    If $typeOfJacobian == Default Then
        $oArrJacobian = $jacobian
    ElseIf $bJacobianIsArray Then
        $vectorJacobian = Call("_VectorOf" & $typeOfJacobian & "Create")

        $iArrJacobianSize = UBound($jacobian)
        For $i = 0 To $iArrJacobianSize - 1
            Call("_VectorOf" & $typeOfJacobian & "Push", $vectorJacobian, $jacobian[$i])
        Next

        $oArrJacobian = Call("_cveOutputArrayFromVectorOf" & $typeOfJacobian, $vectorJacobian)
    Else
        If $bJacobianCreate Then
            $jacobian = Call("_cve" & $typeOfJacobian & "Create", $jacobian)
        EndIf
        $oArrJacobian = Call("_cveOutputArrayFrom" & $typeOfJacobian, $jacobian)
    EndIf

    _cveRodrigues($iArrSrc, $oArrDst, $oArrJacobian)

    If $bJacobianIsArray Then
        Call("_VectorOf" & $typeOfJacobian & "Release", $vectorJacobian)
    EndIf

    If $typeOfJacobian <> Default Then
        _cveOutputArrayRelease($oArrJacobian)
        If $bJacobianCreate Then
            Call("_cve" & $typeOfJacobian & "Release", $jacobian)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveRodriguesTyped

Func _cveRodriguesMat($src, $dst, $jacobian = _cveNoArrayMat())
    ; cveRodrigues using cv::Mat instead of _*Array
    _cveRodriguesTyped("Mat", $src, "Mat", $dst, "Mat", $jacobian)
EndFunc   ;==>_cveRodriguesMat

Func _cveCalibrateCamera($objectPoints, $imagePoints, $imageSize, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $flags = 0, $criteria = _cvTermCriteria( $CV_TERM_CRITERIA_COUNT + $CV_TERM_CRITERIA_EPS, 30, $CV_DBL_EPSILON))
    ; CVAPI(double) cveCalibrateCamera(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, CvSize* imageSize, cv::_InputOutputArray* cameraMatrix, cv::_InputOutputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, int flags, CvTermCriteria* criteria);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecsDllType
    If IsDllStruct($rvecs) Then
        $sRvecsDllType = "struct*"
    Else
        $sRvecsDllType = "ptr"
    EndIf

    Local $sTvecsDllType
    If IsDllStruct($tvecs) Then
        $sTvecsDllType = "struct*"
    Else
        $sTvecsDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveCalibrateCamera", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sImageSizeDllType, $imageSize, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecsDllType, $rvecs, $sTvecsDllType, $tvecs, "int", $flags, $sCriteriaDllType, $criteria), "cveCalibrateCamera", @error)
EndFunc   ;==>_cveCalibrateCamera

Func _cveCalibrateCameraTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $imageSize, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvecs, $rvecs, $typeOfTvecs, $tvecs, $flags = 0, $criteria = _cvTermCriteria( $CV_TERM_CRITERIA_COUNT + $CV_TERM_CRITERIA_EPS, 30, $CV_DBL_EPSILON))

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $ioArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $ioArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $ioArrCameraMatrix = Call("_cveInputOutputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $ioArrCameraMatrix = Call("_cveInputOutputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $ioArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $ioArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $ioArrDistCoeffs = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $ioArrDistCoeffs = Call("_cveInputOutputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvecs, $vectorRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = IsArray($rvecs)
    Local $bRvecsCreate = IsDllStruct($rvecs) And $typeOfRvecs == "Scalar"

    If $typeOfRvecs == Default Then
        $oArrRvecs = $rvecs
    ElseIf $bRvecsIsArray Then
        $vectorRvecs = Call("_VectorOf" & $typeOfRvecs & "Create")

        $iArrRvecsSize = UBound($rvecs)
        For $i = 0 To $iArrRvecsSize - 1
            Call("_VectorOf" & $typeOfRvecs & "Push", $vectorRvecs, $rvecs[$i])
        Next

        $oArrRvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfRvecs, $vectorRvecs)
    Else
        If $bRvecsCreate Then
            $rvecs = Call("_cve" & $typeOfRvecs & "Create", $rvecs)
        EndIf
        $oArrRvecs = Call("_cveOutputArrayFrom" & $typeOfRvecs, $rvecs)
    EndIf

    Local $oArrTvecs, $vectorTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = IsArray($tvecs)
    Local $bTvecsCreate = IsDllStruct($tvecs) And $typeOfTvecs == "Scalar"

    If $typeOfTvecs == Default Then
        $oArrTvecs = $tvecs
    ElseIf $bTvecsIsArray Then
        $vectorTvecs = Call("_VectorOf" & $typeOfTvecs & "Create")

        $iArrTvecsSize = UBound($tvecs)
        For $i = 0 To $iArrTvecsSize - 1
            Call("_VectorOf" & $typeOfTvecs & "Push", $vectorTvecs, $tvecs[$i])
        Next

        $oArrTvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfTvecs, $vectorTvecs)
    Else
        If $bTvecsCreate Then
            $tvecs = Call("_cve" & $typeOfTvecs & "Create", $tvecs)
        EndIf
        $oArrTvecs = Call("_cveOutputArrayFrom" & $typeOfTvecs, $tvecs)
    EndIf

    Local $retval = _cveCalibrateCamera($iArrObjectPoints, $iArrImagePoints, $imageSize, $ioArrCameraMatrix, $ioArrDistCoeffs, $oArrRvecs, $oArrTvecs, $flags, $criteria)

    If $bTvecsIsArray Then
        Call("_VectorOf" & $typeOfTvecs & "Release", $vectorTvecs)
    EndIf

    If $typeOfTvecs <> Default Then
        _cveOutputArrayRelease($oArrTvecs)
        If $bTvecsCreate Then
            Call("_cve" & $typeOfTvecs & "Release", $tvecs)
        EndIf
    EndIf

    If $bRvecsIsArray Then
        Call("_VectorOf" & $typeOfRvecs & "Release", $vectorRvecs)
    EndIf

    If $typeOfRvecs <> Default Then
        _cveOutputArrayRelease($oArrRvecs)
        If $bRvecsCreate Then
            Call("_cve" & $typeOfRvecs & "Release", $rvecs)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputOutputArrayRelease($ioArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputOutputArrayRelease($ioArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveCalibrateCameraTyped

Func _cveCalibrateCameraMat($objectPoints, $imagePoints, $imageSize, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $flags = 0, $criteria = _cvTermCriteria( $CV_TERM_CRITERIA_COUNT + $CV_TERM_CRITERIA_EPS, 30, $CV_DBL_EPSILON))
    ; cveCalibrateCamera using cv::Mat instead of _*Array
    Local $retval = _cveCalibrateCameraTyped("Mat", $objectPoints, "Mat", $imagePoints, $imageSize, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvecs, "Mat", $tvecs, $flags, $criteria)

    Return $retval
EndFunc   ;==>_cveCalibrateCameraMat

Func _cveReprojectImageTo3D($disparity, $threeDImage, $q, $handleMissingValues = false, $ddepth = -1)
    ; CVAPI(void) cveReprojectImageTo3D(cv::_InputArray* disparity, cv::_OutputArray* threeDImage, cv::_InputArray* q, bool handleMissingValues, int ddepth);

    Local $sDisparityDllType
    If IsDllStruct($disparity) Then
        $sDisparityDllType = "struct*"
    Else
        $sDisparityDllType = "ptr"
    EndIf

    Local $sThreeDImageDllType
    If IsDllStruct($threeDImage) Then
        $sThreeDImageDllType = "struct*"
    Else
        $sThreeDImageDllType = "ptr"
    EndIf

    Local $sQDllType
    If IsDllStruct($q) Then
        $sQDllType = "struct*"
    Else
        $sQDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReprojectImageTo3D", $sDisparityDllType, $disparity, $sThreeDImageDllType, $threeDImage, $sQDllType, $q, "boolean", $handleMissingValues, "int", $ddepth), "cveReprojectImageTo3D", @error)
EndFunc   ;==>_cveReprojectImageTo3D

Func _cveReprojectImageTo3DTyped($typeOfDisparity, $disparity, $typeOfThreeDImage, $threeDImage, $typeOfQ, $q, $handleMissingValues = false, $ddepth = -1)

    Local $iArrDisparity, $vectorDisparity, $iArrDisparitySize
    Local $bDisparityIsArray = IsArray($disparity)
    Local $bDisparityCreate = IsDllStruct($disparity) And $typeOfDisparity == "Scalar"

    If $typeOfDisparity == Default Then
        $iArrDisparity = $disparity
    ElseIf $bDisparityIsArray Then
        $vectorDisparity = Call("_VectorOf" & $typeOfDisparity & "Create")

        $iArrDisparitySize = UBound($disparity)
        For $i = 0 To $iArrDisparitySize - 1
            Call("_VectorOf" & $typeOfDisparity & "Push", $vectorDisparity, $disparity[$i])
        Next

        $iArrDisparity = Call("_cveInputArrayFromVectorOf" & $typeOfDisparity, $vectorDisparity)
    Else
        If $bDisparityCreate Then
            $disparity = Call("_cve" & $typeOfDisparity & "Create", $disparity)
        EndIf
        $iArrDisparity = Call("_cveInputArrayFrom" & $typeOfDisparity, $disparity)
    EndIf

    Local $oArrThreeDImage, $vectorThreeDImage, $iArrThreeDImageSize
    Local $bThreeDImageIsArray = IsArray($threeDImage)
    Local $bThreeDImageCreate = IsDllStruct($threeDImage) And $typeOfThreeDImage == "Scalar"

    If $typeOfThreeDImage == Default Then
        $oArrThreeDImage = $threeDImage
    ElseIf $bThreeDImageIsArray Then
        $vectorThreeDImage = Call("_VectorOf" & $typeOfThreeDImage & "Create")

        $iArrThreeDImageSize = UBound($threeDImage)
        For $i = 0 To $iArrThreeDImageSize - 1
            Call("_VectorOf" & $typeOfThreeDImage & "Push", $vectorThreeDImage, $threeDImage[$i])
        Next

        $oArrThreeDImage = Call("_cveOutputArrayFromVectorOf" & $typeOfThreeDImage, $vectorThreeDImage)
    Else
        If $bThreeDImageCreate Then
            $threeDImage = Call("_cve" & $typeOfThreeDImage & "Create", $threeDImage)
        EndIf
        $oArrThreeDImage = Call("_cveOutputArrayFrom" & $typeOfThreeDImage, $threeDImage)
    EndIf

    Local $iArrQ, $vectorQ, $iArrQSize
    Local $bQIsArray = IsArray($q)
    Local $bQCreate = IsDllStruct($q) And $typeOfQ == "Scalar"

    If $typeOfQ == Default Then
        $iArrQ = $q
    ElseIf $bQIsArray Then
        $vectorQ = Call("_VectorOf" & $typeOfQ & "Create")

        $iArrQSize = UBound($q)
        For $i = 0 To $iArrQSize - 1
            Call("_VectorOf" & $typeOfQ & "Push", $vectorQ, $q[$i])
        Next

        $iArrQ = Call("_cveInputArrayFromVectorOf" & $typeOfQ, $vectorQ)
    Else
        If $bQCreate Then
            $q = Call("_cve" & $typeOfQ & "Create", $q)
        EndIf
        $iArrQ = Call("_cveInputArrayFrom" & $typeOfQ, $q)
    EndIf

    _cveReprojectImageTo3D($iArrDisparity, $oArrThreeDImage, $iArrQ, $handleMissingValues, $ddepth)

    If $bQIsArray Then
        Call("_VectorOf" & $typeOfQ & "Release", $vectorQ)
    EndIf

    If $typeOfQ <> Default Then
        _cveInputArrayRelease($iArrQ)
        If $bQCreate Then
            Call("_cve" & $typeOfQ & "Release", $q)
        EndIf
    EndIf

    If $bThreeDImageIsArray Then
        Call("_VectorOf" & $typeOfThreeDImage & "Release", $vectorThreeDImage)
    EndIf

    If $typeOfThreeDImage <> Default Then
        _cveOutputArrayRelease($oArrThreeDImage)
        If $bThreeDImageCreate Then
            Call("_cve" & $typeOfThreeDImage & "Release", $threeDImage)
        EndIf
    EndIf

    If $bDisparityIsArray Then
        Call("_VectorOf" & $typeOfDisparity & "Release", $vectorDisparity)
    EndIf

    If $typeOfDisparity <> Default Then
        _cveInputArrayRelease($iArrDisparity)
        If $bDisparityCreate Then
            Call("_cve" & $typeOfDisparity & "Release", $disparity)
        EndIf
    EndIf
EndFunc   ;==>_cveReprojectImageTo3DTyped

Func _cveReprojectImageTo3DMat($disparity, $threeDImage, $q, $handleMissingValues = false, $ddepth = -1)
    ; cveReprojectImageTo3D using cv::Mat instead of _*Array
    _cveReprojectImageTo3DTyped("Mat", $disparity, "Mat", $threeDImage, "Mat", $q, $handleMissingValues, $ddepth)
EndFunc   ;==>_cveReprojectImageTo3DMat

Func _cveConvertPointsToHomogeneous($src, $dst)
    ; CVAPI(void) cveConvertPointsToHomogeneous(cv::_InputArray* src, cv::_OutputArray* dst);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertPointsToHomogeneous", $sSrcDllType, $src, $sDstDllType, $dst), "cveConvertPointsToHomogeneous", @error)
EndFunc   ;==>_cveConvertPointsToHomogeneous

Func _cveConvertPointsToHomogeneousTyped($typeOfSrc, $src, $typeOfDst, $dst)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveConvertPointsToHomogeneous($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveConvertPointsToHomogeneousTyped

Func _cveConvertPointsToHomogeneousMat($src, $dst)
    ; cveConvertPointsToHomogeneous using cv::Mat instead of _*Array
    _cveConvertPointsToHomogeneousTyped("Mat", $src, "Mat", $dst)
EndFunc   ;==>_cveConvertPointsToHomogeneousMat

Func _cveConvertPointsFromHomogeneous($src, $dst)
    ; CVAPI(void) cveConvertPointsFromHomogeneous(cv::_InputArray* src, cv::_OutputArray* dst);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveConvertPointsFromHomogeneous", $sSrcDllType, $src, $sDstDllType, $dst), "cveConvertPointsFromHomogeneous", @error)
EndFunc   ;==>_cveConvertPointsFromHomogeneous

Func _cveConvertPointsFromHomogeneousTyped($typeOfSrc, $src, $typeOfDst, $dst)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    _cveConvertPointsFromHomogeneous($iArrSrc, $oArrDst)

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveConvertPointsFromHomogeneousTyped

Func _cveConvertPointsFromHomogeneousMat($src, $dst)
    ; cveConvertPointsFromHomogeneous using cv::Mat instead of _*Array
    _cveConvertPointsFromHomogeneousTyped("Mat", $src, "Mat", $dst)
EndFunc   ;==>_cveConvertPointsFromHomogeneousMat

Func _cveFindEssentialMat($points1, $points2, $cameraMatrix, $method, $prob, $threshold, $mask, $essentialMat)
    ; CVAPI(void) cveFindEssentialMat(cv::_InputArray* points1, cv::_InputArray* points2, cv::_InputArray* cameraMatrix, int method, double prob, double threshold, cv::_OutputArray* mask, cv::Mat* essentialMat);

    Local $sPoints1DllType
    If IsDllStruct($points1) Then
        $sPoints1DllType = "struct*"
    Else
        $sPoints1DllType = "ptr"
    EndIf

    Local $sPoints2DllType
    If IsDllStruct($points2) Then
        $sPoints2DllType = "struct*"
    Else
        $sPoints2DllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    Local $sEssentialMatDllType
    If IsDllStruct($essentialMat) Then
        $sEssentialMatDllType = "struct*"
    Else
        $sEssentialMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindEssentialMat", $sPoints1DllType, $points1, $sPoints2DllType, $points2, $sCameraMatrixDllType, $cameraMatrix, "int", $method, "double", $prob, "double", $threshold, $sMaskDllType, $mask, $sEssentialMatDllType, $essentialMat), "cveFindEssentialMat", @error)
EndFunc   ;==>_cveFindEssentialMat

Func _cveFindEssentialMatTyped($typeOfPoints1, $points1, $typeOfPoints2, $points2, $typeOfCameraMatrix, $cameraMatrix, $method, $prob, $threshold, $typeOfMask, $mask, $essentialMat)

    Local $iArrPoints1, $vectorPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = IsArray($points1)
    Local $bPoints1Create = IsDllStruct($points1) And $typeOfPoints1 == "Scalar"

    If $typeOfPoints1 == Default Then
        $iArrPoints1 = $points1
    ElseIf $bPoints1IsArray Then
        $vectorPoints1 = Call("_VectorOf" & $typeOfPoints1 & "Create")

        $iArrPoints1Size = UBound($points1)
        For $i = 0 To $iArrPoints1Size - 1
            Call("_VectorOf" & $typeOfPoints1 & "Push", $vectorPoints1, $points1[$i])
        Next

        $iArrPoints1 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints1, $vectorPoints1)
    Else
        If $bPoints1Create Then
            $points1 = Call("_cve" & $typeOfPoints1 & "Create", $points1)
        EndIf
        $iArrPoints1 = Call("_cveInputArrayFrom" & $typeOfPoints1, $points1)
    EndIf

    Local $iArrPoints2, $vectorPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = IsArray($points2)
    Local $bPoints2Create = IsDllStruct($points2) And $typeOfPoints2 == "Scalar"

    If $typeOfPoints2 == Default Then
        $iArrPoints2 = $points2
    ElseIf $bPoints2IsArray Then
        $vectorPoints2 = Call("_VectorOf" & $typeOfPoints2 & "Create")

        $iArrPoints2Size = UBound($points2)
        For $i = 0 To $iArrPoints2Size - 1
            Call("_VectorOf" & $typeOfPoints2 & "Push", $vectorPoints2, $points2[$i])
        Next

        $iArrPoints2 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints2, $vectorPoints2)
    Else
        If $bPoints2Create Then
            $points2 = Call("_cve" & $typeOfPoints2 & "Create", $points2)
        EndIf
        $iArrPoints2 = Call("_cveInputArrayFrom" & $typeOfPoints2, $points2)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
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

    _cveFindEssentialMat($iArrPoints1, $iArrPoints2, $iArrCameraMatrix, $method, $prob, $threshold, $oArrMask, $essentialMat)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveOutputArrayRelease($oArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bPoints2IsArray Then
        Call("_VectorOf" & $typeOfPoints2 & "Release", $vectorPoints2)
    EndIf

    If $typeOfPoints2 <> Default Then
        _cveInputArrayRelease($iArrPoints2)
        If $bPoints2Create Then
            Call("_cve" & $typeOfPoints2 & "Release", $points2)
        EndIf
    EndIf

    If $bPoints1IsArray Then
        Call("_VectorOf" & $typeOfPoints1 & "Release", $vectorPoints1)
    EndIf

    If $typeOfPoints1 <> Default Then
        _cveInputArrayRelease($iArrPoints1)
        If $bPoints1Create Then
            Call("_cve" & $typeOfPoints1 & "Release", $points1)
        EndIf
    EndIf
EndFunc   ;==>_cveFindEssentialMatTyped

Func _cveFindEssentialMatMat($points1, $points2, $cameraMatrix, $method, $prob, $threshold, $mask, $essentialMat)
    ; cveFindEssentialMat using cv::Mat instead of _*Array
    _cveFindEssentialMatTyped("Mat", $points1, "Mat", $points2, "Mat", $cameraMatrix, $method, $prob, $threshold, "Mat", $mask, $essentialMat)
EndFunc   ;==>_cveFindEssentialMatMat

Func _cveFindFundamentalMat($points1, $points2, $dst, $method, $param1, $param2, $mask = _cveNoArray())
    ; CVAPI(void) cveFindFundamentalMat(cv::_InputArray* points1, cv::_InputArray* points2, cv::_OutputArray* dst, int method, double param1, double param2, cv::_OutputArray* mask);

    Local $sPoints1DllType
    If IsDllStruct($points1) Then
        $sPoints1DllType = "struct*"
    Else
        $sPoints1DllType = "ptr"
    EndIf

    Local $sPoints2DllType
    If IsDllStruct($points2) Then
        $sPoints2DllType = "struct*"
    Else
        $sPoints2DllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindFundamentalMat", $sPoints1DllType, $points1, $sPoints2DllType, $points2, $sDstDllType, $dst, "int", $method, "double", $param1, "double", $param2, $sMaskDllType, $mask), "cveFindFundamentalMat", @error)
EndFunc   ;==>_cveFindFundamentalMat

Func _cveFindFundamentalMatTyped($typeOfPoints1, $points1, $typeOfPoints2, $points2, $typeOfDst, $dst, $method, $param1, $param2, $typeOfMask = Default, $mask = _cveNoArray())

    Local $iArrPoints1, $vectorPoints1, $iArrPoints1Size
    Local $bPoints1IsArray = IsArray($points1)
    Local $bPoints1Create = IsDllStruct($points1) And $typeOfPoints1 == "Scalar"

    If $typeOfPoints1 == Default Then
        $iArrPoints1 = $points1
    ElseIf $bPoints1IsArray Then
        $vectorPoints1 = Call("_VectorOf" & $typeOfPoints1 & "Create")

        $iArrPoints1Size = UBound($points1)
        For $i = 0 To $iArrPoints1Size - 1
            Call("_VectorOf" & $typeOfPoints1 & "Push", $vectorPoints1, $points1[$i])
        Next

        $iArrPoints1 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints1, $vectorPoints1)
    Else
        If $bPoints1Create Then
            $points1 = Call("_cve" & $typeOfPoints1 & "Create", $points1)
        EndIf
        $iArrPoints1 = Call("_cveInputArrayFrom" & $typeOfPoints1, $points1)
    EndIf

    Local $iArrPoints2, $vectorPoints2, $iArrPoints2Size
    Local $bPoints2IsArray = IsArray($points2)
    Local $bPoints2Create = IsDllStruct($points2) And $typeOfPoints2 == "Scalar"

    If $typeOfPoints2 == Default Then
        $iArrPoints2 = $points2
    ElseIf $bPoints2IsArray Then
        $vectorPoints2 = Call("_VectorOf" & $typeOfPoints2 & "Create")

        $iArrPoints2Size = UBound($points2)
        For $i = 0 To $iArrPoints2Size - 1
            Call("_VectorOf" & $typeOfPoints2 & "Push", $vectorPoints2, $points2[$i])
        Next

        $iArrPoints2 = Call("_cveInputArrayFromVectorOf" & $typeOfPoints2, $vectorPoints2)
    Else
        If $bPoints2Create Then
            $points2 = Call("_cve" & $typeOfPoints2 & "Create", $points2)
        EndIf
        $iArrPoints2 = Call("_cveInputArrayFrom" & $typeOfPoints2, $points2)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
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

    _cveFindFundamentalMat($iArrPoints1, $iArrPoints2, $oArrDst, $method, $param1, $param2, $oArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveOutputArrayRelease($oArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bPoints2IsArray Then
        Call("_VectorOf" & $typeOfPoints2 & "Release", $vectorPoints2)
    EndIf

    If $typeOfPoints2 <> Default Then
        _cveInputArrayRelease($iArrPoints2)
        If $bPoints2Create Then
            Call("_cve" & $typeOfPoints2 & "Release", $points2)
        EndIf
    EndIf

    If $bPoints1IsArray Then
        Call("_VectorOf" & $typeOfPoints1 & "Release", $vectorPoints1)
    EndIf

    If $typeOfPoints1 <> Default Then
        _cveInputArrayRelease($iArrPoints1)
        If $bPoints1Create Then
            Call("_cve" & $typeOfPoints1 & "Release", $points1)
        EndIf
    EndIf
EndFunc   ;==>_cveFindFundamentalMatTyped

Func _cveFindFundamentalMatMat($points1, $points2, $dst, $method, $param1, $param2, $mask = _cveNoArrayMat())
    ; cveFindFundamentalMat using cv::Mat instead of _*Array
    _cveFindFundamentalMatTyped("Mat", $points1, "Mat", $points2, "Mat", $dst, $method, $param1, $param2, "Mat", $mask)
EndFunc   ;==>_cveFindFundamentalMatMat

Func _cveFindHomography($srcPoints, $dstPoints, $dst, $method = 0, $ransacReprojThreshold = 3, $mask = _cveNoArray())
    ; CVAPI(void) cveFindHomography(cv::_InputArray* srcPoints, cv::_InputArray* dstPoints, cv::_OutputArray* dst, int method, double ransacReprojThreshold, cv::_OutputArray* mask);

    Local $sSrcPointsDllType
    If IsDllStruct($srcPoints) Then
        $sSrcPointsDllType = "struct*"
    Else
        $sSrcPointsDllType = "ptr"
    EndIf

    Local $sDstPointsDllType
    If IsDllStruct($dstPoints) Then
        $sDstPointsDllType = "struct*"
    Else
        $sDstPointsDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFindHomography", $sSrcPointsDllType, $srcPoints, $sDstPointsDllType, $dstPoints, $sDstDllType, $dst, "int", $method, "double", $ransacReprojThreshold, $sMaskDllType, $mask), "cveFindHomography", @error)
EndFunc   ;==>_cveFindHomography

Func _cveFindHomographyTyped($typeOfSrcPoints, $srcPoints, $typeOfDstPoints, $dstPoints, $typeOfDst, $dst, $method = 0, $ransacReprojThreshold = 3, $typeOfMask = Default, $mask = _cveNoArray())

    Local $iArrSrcPoints, $vectorSrcPoints, $iArrSrcPointsSize
    Local $bSrcPointsIsArray = IsArray($srcPoints)
    Local $bSrcPointsCreate = IsDllStruct($srcPoints) And $typeOfSrcPoints == "Scalar"

    If $typeOfSrcPoints == Default Then
        $iArrSrcPoints = $srcPoints
    ElseIf $bSrcPointsIsArray Then
        $vectorSrcPoints = Call("_VectorOf" & $typeOfSrcPoints & "Create")

        $iArrSrcPointsSize = UBound($srcPoints)
        For $i = 0 To $iArrSrcPointsSize - 1
            Call("_VectorOf" & $typeOfSrcPoints & "Push", $vectorSrcPoints, $srcPoints[$i])
        Next

        $iArrSrcPoints = Call("_cveInputArrayFromVectorOf" & $typeOfSrcPoints, $vectorSrcPoints)
    Else
        If $bSrcPointsCreate Then
            $srcPoints = Call("_cve" & $typeOfSrcPoints & "Create", $srcPoints)
        EndIf
        $iArrSrcPoints = Call("_cveInputArrayFrom" & $typeOfSrcPoints, $srcPoints)
    EndIf

    Local $iArrDstPoints, $vectorDstPoints, $iArrDstPointsSize
    Local $bDstPointsIsArray = IsArray($dstPoints)
    Local $bDstPointsCreate = IsDllStruct($dstPoints) And $typeOfDstPoints == "Scalar"

    If $typeOfDstPoints == Default Then
        $iArrDstPoints = $dstPoints
    ElseIf $bDstPointsIsArray Then
        $vectorDstPoints = Call("_VectorOf" & $typeOfDstPoints & "Create")

        $iArrDstPointsSize = UBound($dstPoints)
        For $i = 0 To $iArrDstPointsSize - 1
            Call("_VectorOf" & $typeOfDstPoints & "Push", $vectorDstPoints, $dstPoints[$i])
        Next

        $iArrDstPoints = Call("_cveInputArrayFromVectorOf" & $typeOfDstPoints, $vectorDstPoints)
    Else
        If $bDstPointsCreate Then
            $dstPoints = Call("_cve" & $typeOfDstPoints & "Create", $dstPoints)
        EndIf
        $iArrDstPoints = Call("_cveInputArrayFrom" & $typeOfDstPoints, $dstPoints)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
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

    _cveFindHomography($iArrSrcPoints, $iArrDstPoints, $oArrDst, $method, $ransacReprojThreshold, $oArrMask)

    If $bMaskIsArray Then
        Call("_VectorOf" & $typeOfMask & "Release", $vectorMask)
    EndIf

    If $typeOfMask <> Default Then
        _cveOutputArrayRelease($oArrMask)
        If $bMaskCreate Then
            Call("_cve" & $typeOfMask & "Release", $mask)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bDstPointsIsArray Then
        Call("_VectorOf" & $typeOfDstPoints & "Release", $vectorDstPoints)
    EndIf

    If $typeOfDstPoints <> Default Then
        _cveInputArrayRelease($iArrDstPoints)
        If $bDstPointsCreate Then
            Call("_cve" & $typeOfDstPoints & "Release", $dstPoints)
        EndIf
    EndIf

    If $bSrcPointsIsArray Then
        Call("_VectorOf" & $typeOfSrcPoints & "Release", $vectorSrcPoints)
    EndIf

    If $typeOfSrcPoints <> Default Then
        _cveInputArrayRelease($iArrSrcPoints)
        If $bSrcPointsCreate Then
            Call("_cve" & $typeOfSrcPoints & "Release", $srcPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveFindHomographyTyped

Func _cveFindHomographyMat($srcPoints, $dstPoints, $dst, $method = 0, $ransacReprojThreshold = 3, $mask = _cveNoArrayMat())
    ; cveFindHomography using cv::Mat instead of _*Array
    _cveFindHomographyTyped("Mat", $srcPoints, "Mat", $dstPoints, "Mat", $dst, $method, $ransacReprojThreshold, "Mat", $mask)
EndFunc   ;==>_cveFindHomographyMat

Func _cveComputeCorrespondEpilines($points, $whichImage, $f, $lines)
    ; CVAPI(void) cveComputeCorrespondEpilines(cv::_InputArray* points, int whichImage, cv::_InputArray* f, cv::_OutputArray* lines);

    Local $sPointsDllType
    If IsDllStruct($points) Then
        $sPointsDllType = "struct*"
    Else
        $sPointsDllType = "ptr"
    EndIf

    Local $sFDllType
    If IsDllStruct($f) Then
        $sFDllType = "struct*"
    Else
        $sFDllType = "ptr"
    EndIf

    Local $sLinesDllType
    If IsDllStruct($lines) Then
        $sLinesDllType = "struct*"
    Else
        $sLinesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveComputeCorrespondEpilines", $sPointsDllType, $points, "int", $whichImage, $sFDllType, $f, $sLinesDllType, $lines), "cveComputeCorrespondEpilines", @error)
EndFunc   ;==>_cveComputeCorrespondEpilines

Func _cveComputeCorrespondEpilinesTyped($typeOfPoints, $points, $whichImage, $typeOfF, $f, $typeOfLines, $lines)

    Local $iArrPoints, $vectorPoints, $iArrPointsSize
    Local $bPointsIsArray = IsArray($points)
    Local $bPointsCreate = IsDllStruct($points) And $typeOfPoints == "Scalar"

    If $typeOfPoints == Default Then
        $iArrPoints = $points
    ElseIf $bPointsIsArray Then
        $vectorPoints = Call("_VectorOf" & $typeOfPoints & "Create")

        $iArrPointsSize = UBound($points)
        For $i = 0 To $iArrPointsSize - 1
            Call("_VectorOf" & $typeOfPoints & "Push", $vectorPoints, $points[$i])
        Next

        $iArrPoints = Call("_cveInputArrayFromVectorOf" & $typeOfPoints, $vectorPoints)
    Else
        If $bPointsCreate Then
            $points = Call("_cve" & $typeOfPoints & "Create", $points)
        EndIf
        $iArrPoints = Call("_cveInputArrayFrom" & $typeOfPoints, $points)
    EndIf

    Local $iArrF, $vectorF, $iArrFSize
    Local $bFIsArray = IsArray($f)
    Local $bFCreate = IsDllStruct($f) And $typeOfF == "Scalar"

    If $typeOfF == Default Then
        $iArrF = $f
    ElseIf $bFIsArray Then
        $vectorF = Call("_VectorOf" & $typeOfF & "Create")

        $iArrFSize = UBound($f)
        For $i = 0 To $iArrFSize - 1
            Call("_VectorOf" & $typeOfF & "Push", $vectorF, $f[$i])
        Next

        $iArrF = Call("_cveInputArrayFromVectorOf" & $typeOfF, $vectorF)
    Else
        If $bFCreate Then
            $f = Call("_cve" & $typeOfF & "Create", $f)
        EndIf
        $iArrF = Call("_cveInputArrayFrom" & $typeOfF, $f)
    EndIf

    Local $oArrLines, $vectorLines, $iArrLinesSize
    Local $bLinesIsArray = IsArray($lines)
    Local $bLinesCreate = IsDllStruct($lines) And $typeOfLines == "Scalar"

    If $typeOfLines == Default Then
        $oArrLines = $lines
    ElseIf $bLinesIsArray Then
        $vectorLines = Call("_VectorOf" & $typeOfLines & "Create")

        $iArrLinesSize = UBound($lines)
        For $i = 0 To $iArrLinesSize - 1
            Call("_VectorOf" & $typeOfLines & "Push", $vectorLines, $lines[$i])
        Next

        $oArrLines = Call("_cveOutputArrayFromVectorOf" & $typeOfLines, $vectorLines)
    Else
        If $bLinesCreate Then
            $lines = Call("_cve" & $typeOfLines & "Create", $lines)
        EndIf
        $oArrLines = Call("_cveOutputArrayFrom" & $typeOfLines, $lines)
    EndIf

    _cveComputeCorrespondEpilines($iArrPoints, $whichImage, $iArrF, $oArrLines)

    If $bLinesIsArray Then
        Call("_VectorOf" & $typeOfLines & "Release", $vectorLines)
    EndIf

    If $typeOfLines <> Default Then
        _cveOutputArrayRelease($oArrLines)
        If $bLinesCreate Then
            Call("_cve" & $typeOfLines & "Release", $lines)
        EndIf
    EndIf

    If $bFIsArray Then
        Call("_VectorOf" & $typeOfF & "Release", $vectorF)
    EndIf

    If $typeOfF <> Default Then
        _cveInputArrayRelease($iArrF)
        If $bFCreate Then
            Call("_cve" & $typeOfF & "Release", $f)
        EndIf
    EndIf

    If $bPointsIsArray Then
        Call("_VectorOf" & $typeOfPoints & "Release", $vectorPoints)
    EndIf

    If $typeOfPoints <> Default Then
        _cveInputArrayRelease($iArrPoints)
        If $bPointsCreate Then
            Call("_cve" & $typeOfPoints & "Release", $points)
        EndIf
    EndIf
EndFunc   ;==>_cveComputeCorrespondEpilinesTyped

Func _cveComputeCorrespondEpilinesMat($points, $whichImage, $f, $lines)
    ; cveComputeCorrespondEpilines using cv::Mat instead of _*Array
    _cveComputeCorrespondEpilinesTyped("Mat", $points, $whichImage, "Mat", $f, "Mat", $lines)
EndFunc   ;==>_cveComputeCorrespondEpilinesMat

Func _cveProjectPoints($objPoints, $rvec, $tvec, $cameraMatrix, $distCoeffs, $imagePoints, $jacobian = _cveNoArray(), $aspectRatio = 0)
    ; CVAPI(void) cveProjectPoints(cv::_InputArray* objPoints, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* imagePoints, cv::_OutputArray* jacobian, double aspectRatio);

    Local $sObjPointsDllType
    If IsDllStruct($objPoints) Then
        $sObjPointsDllType = "struct*"
    Else
        $sObjPointsDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sJacobianDllType
    If IsDllStruct($jacobian) Then
        $sJacobianDllType = "struct*"
    Else
        $sJacobianDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveProjectPoints", $sObjPointsDllType, $objPoints, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sImagePointsDllType, $imagePoints, $sJacobianDllType, $jacobian, "double", $aspectRatio), "cveProjectPoints", @error)
EndFunc   ;==>_cveProjectPoints

Func _cveProjectPointsTyped($typeOfObjPoints, $objPoints, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfImagePoints, $imagePoints, $typeOfJacobian = Default, $jacobian = _cveNoArray(), $aspectRatio = 0)

    Local $iArrObjPoints, $vectorObjPoints, $iArrObjPointsSize
    Local $bObjPointsIsArray = IsArray($objPoints)
    Local $bObjPointsCreate = IsDllStruct($objPoints) And $typeOfObjPoints == "Scalar"

    If $typeOfObjPoints == Default Then
        $iArrObjPoints = $objPoints
    ElseIf $bObjPointsIsArray Then
        $vectorObjPoints = Call("_VectorOf" & $typeOfObjPoints & "Create")

        $iArrObjPointsSize = UBound($objPoints)
        For $i = 0 To $iArrObjPointsSize - 1
            Call("_VectorOf" & $typeOfObjPoints & "Push", $vectorObjPoints, $objPoints[$i])
        Next

        $iArrObjPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjPoints, $vectorObjPoints)
    Else
        If $bObjPointsCreate Then
            $objPoints = Call("_cve" & $typeOfObjPoints & "Create", $objPoints)
        EndIf
        $iArrObjPoints = Call("_cveInputArrayFrom" & $typeOfObjPoints, $objPoints)
    EndIf

    Local $iArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $iArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $iArrRvec = Call("_cveInputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $iArrRvec = Call("_cveInputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $iArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $iArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $iArrTvec = Call("_cveInputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $iArrTvec = Call("_cveInputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $oArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $oArrImagePoints = Call("_cveOutputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $oArrImagePoints = Call("_cveOutputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $oArrJacobian, $vectorJacobian, $iArrJacobianSize
    Local $bJacobianIsArray = IsArray($jacobian)
    Local $bJacobianCreate = IsDllStruct($jacobian) And $typeOfJacobian == "Scalar"

    If $typeOfJacobian == Default Then
        $oArrJacobian = $jacobian
    ElseIf $bJacobianIsArray Then
        $vectorJacobian = Call("_VectorOf" & $typeOfJacobian & "Create")

        $iArrJacobianSize = UBound($jacobian)
        For $i = 0 To $iArrJacobianSize - 1
            Call("_VectorOf" & $typeOfJacobian & "Push", $vectorJacobian, $jacobian[$i])
        Next

        $oArrJacobian = Call("_cveOutputArrayFromVectorOf" & $typeOfJacobian, $vectorJacobian)
    Else
        If $bJacobianCreate Then
            $jacobian = Call("_cve" & $typeOfJacobian & "Create", $jacobian)
        EndIf
        $oArrJacobian = Call("_cveOutputArrayFrom" & $typeOfJacobian, $jacobian)
    EndIf

    _cveProjectPoints($iArrObjPoints, $iArrRvec, $iArrTvec, $iArrCameraMatrix, $iArrDistCoeffs, $oArrImagePoints, $oArrJacobian, $aspectRatio)

    If $bJacobianIsArray Then
        Call("_VectorOf" & $typeOfJacobian & "Release", $vectorJacobian)
    EndIf

    If $typeOfJacobian <> Default Then
        _cveOutputArrayRelease($oArrJacobian)
        If $bJacobianCreate Then
            Call("_cve" & $typeOfJacobian & "Release", $jacobian)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveOutputArrayRelease($oArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputArrayRelease($iArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputArrayRelease($iArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bObjPointsIsArray Then
        Call("_VectorOf" & $typeOfObjPoints & "Release", $vectorObjPoints)
    EndIf

    If $typeOfObjPoints <> Default Then
        _cveInputArrayRelease($iArrObjPoints)
        If $bObjPointsCreate Then
            Call("_cve" & $typeOfObjPoints & "Release", $objPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveProjectPointsTyped

Func _cveProjectPointsMat($objPoints, $rvec, $tvec, $cameraMatrix, $distCoeffs, $imagePoints, $jacobian = _cveNoArrayMat(), $aspectRatio = 0)
    ; cveProjectPoints using cv::Mat instead of _*Array
    _cveProjectPointsTyped("Mat", $objPoints, "Mat", $rvec, "Mat", $tvec, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $imagePoints, "Mat", $jacobian, $aspectRatio)
EndFunc   ;==>_cveProjectPointsMat

Func _cveCalibrationMatrixValues($cameraMatrix, $imageSize, $apertureWidth, $apertureHeight, $fovx, $fovy, $focalLength, $principalPoint, $aspectRatio)
    ; CVAPI(void) cveCalibrationMatrixValues(cv::_InputArray* cameraMatrix, CvSize* imageSize, double apertureWidth, double apertureHeight, double* fovx, double* fovy, double* focalLength, CvPoint2D64f* principalPoint, double* aspectRatio);

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sFovxDllType
    If IsDllStruct($fovx) Then
        $sFovxDllType = "struct*"
    Else
        $sFovxDllType = "double*"
    EndIf

    Local $sFovyDllType
    If IsDllStruct($fovy) Then
        $sFovyDllType = "struct*"
    Else
        $sFovyDllType = "double*"
    EndIf

    Local $sFocalLengthDllType
    If IsDllStruct($focalLength) Then
        $sFocalLengthDllType = "struct*"
    Else
        $sFocalLengthDllType = "double*"
    EndIf

    Local $sPrincipalPointDllType
    If IsDllStruct($principalPoint) Then
        $sPrincipalPointDllType = "struct*"
    Else
        $sPrincipalPointDllType = "ptr"
    EndIf

    Local $sAspectRatioDllType
    If IsDllStruct($aspectRatio) Then
        $sAspectRatioDllType = "struct*"
    Else
        $sAspectRatioDllType = "double*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrationMatrixValues", $sCameraMatrixDllType, $cameraMatrix, $sImageSizeDllType, $imageSize, "double", $apertureWidth, "double", $apertureHeight, $sFovxDllType, $fovx, $sFovyDllType, $fovy, $sFocalLengthDllType, $focalLength, $sPrincipalPointDllType, $principalPoint, $sAspectRatioDllType, $aspectRatio), "cveCalibrationMatrixValues", @error)
EndFunc   ;==>_cveCalibrationMatrixValues

Func _cveCalibrationMatrixValuesTyped($typeOfCameraMatrix, $cameraMatrix, $imageSize, $apertureWidth, $apertureHeight, $fovx, $fovy, $focalLength, $principalPoint, $aspectRatio)

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    _cveCalibrationMatrixValues($iArrCameraMatrix, $imageSize, $apertureWidth, $apertureHeight, $fovx, $fovy, $focalLength, $principalPoint, $aspectRatio)

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf
EndFunc   ;==>_cveCalibrationMatrixValuesTyped

Func _cveCalibrationMatrixValuesMat($cameraMatrix, $imageSize, $apertureWidth, $apertureHeight, $fovx, $fovy, $focalLength, $principalPoint, $aspectRatio)
    ; cveCalibrationMatrixValues using cv::Mat instead of _*Array
    _cveCalibrationMatrixValuesTyped("Mat", $cameraMatrix, $imageSize, $apertureWidth, $apertureHeight, $fovx, $fovy, $focalLength, $principalPoint, $aspectRatio)
EndFunc   ;==>_cveCalibrationMatrixValuesMat

Func _cveStereoCalibrate($objectPoints, $imagePoints1, $imagePoints2, $cameraMatrix1, $distCoeffs1, $cameraMatrix2, $distCoeffs2, $imageSize, $r, $t, $e, $f, $flags = $CV_CALIB_FIX_INTRINSIC, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_COUNT+$CV_TERM_CRITERIA_EPS, 30, 1e-6))
    ; CVAPI(double) cveStereoCalibrate(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints1, cv::_InputArray* imagePoints2, cv::_InputOutputArray* cameraMatrix1, cv::_InputOutputArray* distCoeffs1, cv::_InputOutputArray* cameraMatrix2, cv::_InputOutputArray* distCoeffs2, CvSize* imageSize, cv::_OutputArray* r, cv::_OutputArray* t, cv::_OutputArray* e, cv::_OutputArray* f, int flags, CvTermCriteria* criteria);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePoints1DllType
    If IsDllStruct($imagePoints1) Then
        $sImagePoints1DllType = "struct*"
    Else
        $sImagePoints1DllType = "ptr"
    EndIf

    Local $sImagePoints2DllType
    If IsDllStruct($imagePoints2) Then
        $sImagePoints2DllType = "struct*"
    Else
        $sImagePoints2DllType = "ptr"
    EndIf

    Local $sCameraMatrix1DllType
    If IsDllStruct($cameraMatrix1) Then
        $sCameraMatrix1DllType = "struct*"
    Else
        $sCameraMatrix1DllType = "ptr"
    EndIf

    Local $sDistCoeffs1DllType
    If IsDllStruct($distCoeffs1) Then
        $sDistCoeffs1DllType = "struct*"
    Else
        $sDistCoeffs1DllType = "ptr"
    EndIf

    Local $sCameraMatrix2DllType
    If IsDllStruct($cameraMatrix2) Then
        $sCameraMatrix2DllType = "struct*"
    Else
        $sCameraMatrix2DllType = "ptr"
    EndIf

    Local $sDistCoeffs2DllType
    If IsDllStruct($distCoeffs2) Then
        $sDistCoeffs2DllType = "struct*"
    Else
        $sDistCoeffs2DllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($r) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sTDllType
    If IsDllStruct($t) Then
        $sTDllType = "struct*"
    Else
        $sTDllType = "ptr"
    EndIf

    Local $sEDllType
    If IsDllStruct($e) Then
        $sEDllType = "struct*"
    Else
        $sEDllType = "ptr"
    EndIf

    Local $sFDllType
    If IsDllStruct($f) Then
        $sFDllType = "struct*"
    Else
        $sFDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveStereoCalibrate", $sObjectPointsDllType, $objectPoints, $sImagePoints1DllType, $imagePoints1, $sImagePoints2DllType, $imagePoints2, $sCameraMatrix1DllType, $cameraMatrix1, $sDistCoeffs1DllType, $distCoeffs1, $sCameraMatrix2DllType, $cameraMatrix2, $sDistCoeffs2DllType, $distCoeffs2, $sImageSizeDllType, $imageSize, $sRDllType, $r, $sTDllType, $t, $sEDllType, $e, $sFDllType, $f, "int", $flags, $sCriteriaDllType, $criteria), "cveStereoCalibrate", @error)
EndFunc   ;==>_cveStereoCalibrate

Func _cveStereoCalibrateTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints1, $imagePoints1, $typeOfImagePoints2, $imagePoints2, $typeOfCameraMatrix1, $cameraMatrix1, $typeOfDistCoeffs1, $distCoeffs1, $typeOfCameraMatrix2, $cameraMatrix2, $typeOfDistCoeffs2, $distCoeffs2, $imageSize, $typeOfR, $r, $typeOfT, $t, $typeOfE, $e, $typeOfF, $f, $flags = $CV_CALIB_FIX_INTRINSIC, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_COUNT+$CV_TERM_CRITERIA_EPS, 30, 1e-6))

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints1, $vectorImagePoints1, $iArrImagePoints1Size
    Local $bImagePoints1IsArray = IsArray($imagePoints1)
    Local $bImagePoints1Create = IsDllStruct($imagePoints1) And $typeOfImagePoints1 == "Scalar"

    If $typeOfImagePoints1 == Default Then
        $iArrImagePoints1 = $imagePoints1
    ElseIf $bImagePoints1IsArray Then
        $vectorImagePoints1 = Call("_VectorOf" & $typeOfImagePoints1 & "Create")

        $iArrImagePoints1Size = UBound($imagePoints1)
        For $i = 0 To $iArrImagePoints1Size - 1
            Call("_VectorOf" & $typeOfImagePoints1 & "Push", $vectorImagePoints1, $imagePoints1[$i])
        Next

        $iArrImagePoints1 = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints1, $vectorImagePoints1)
    Else
        If $bImagePoints1Create Then
            $imagePoints1 = Call("_cve" & $typeOfImagePoints1 & "Create", $imagePoints1)
        EndIf
        $iArrImagePoints1 = Call("_cveInputArrayFrom" & $typeOfImagePoints1, $imagePoints1)
    EndIf

    Local $iArrImagePoints2, $vectorImagePoints2, $iArrImagePoints2Size
    Local $bImagePoints2IsArray = IsArray($imagePoints2)
    Local $bImagePoints2Create = IsDllStruct($imagePoints2) And $typeOfImagePoints2 == "Scalar"

    If $typeOfImagePoints2 == Default Then
        $iArrImagePoints2 = $imagePoints2
    ElseIf $bImagePoints2IsArray Then
        $vectorImagePoints2 = Call("_VectorOf" & $typeOfImagePoints2 & "Create")

        $iArrImagePoints2Size = UBound($imagePoints2)
        For $i = 0 To $iArrImagePoints2Size - 1
            Call("_VectorOf" & $typeOfImagePoints2 & "Push", $vectorImagePoints2, $imagePoints2[$i])
        Next

        $iArrImagePoints2 = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints2, $vectorImagePoints2)
    Else
        If $bImagePoints2Create Then
            $imagePoints2 = Call("_cve" & $typeOfImagePoints2 & "Create", $imagePoints2)
        EndIf
        $iArrImagePoints2 = Call("_cveInputArrayFrom" & $typeOfImagePoints2, $imagePoints2)
    EndIf

    Local $ioArrCameraMatrix1, $vectorCameraMatrix1, $iArrCameraMatrix1Size
    Local $bCameraMatrix1IsArray = IsArray($cameraMatrix1)
    Local $bCameraMatrix1Create = IsDllStruct($cameraMatrix1) And $typeOfCameraMatrix1 == "Scalar"

    If $typeOfCameraMatrix1 == Default Then
        $ioArrCameraMatrix1 = $cameraMatrix1
    ElseIf $bCameraMatrix1IsArray Then
        $vectorCameraMatrix1 = Call("_VectorOf" & $typeOfCameraMatrix1 & "Create")

        $iArrCameraMatrix1Size = UBound($cameraMatrix1)
        For $i = 0 To $iArrCameraMatrix1Size - 1
            Call("_VectorOf" & $typeOfCameraMatrix1 & "Push", $vectorCameraMatrix1, $cameraMatrix1[$i])
        Next

        $ioArrCameraMatrix1 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfCameraMatrix1, $vectorCameraMatrix1)
    Else
        If $bCameraMatrix1Create Then
            $cameraMatrix1 = Call("_cve" & $typeOfCameraMatrix1 & "Create", $cameraMatrix1)
        EndIf
        $ioArrCameraMatrix1 = Call("_cveInputOutputArrayFrom" & $typeOfCameraMatrix1, $cameraMatrix1)
    EndIf

    Local $ioArrDistCoeffs1, $vectorDistCoeffs1, $iArrDistCoeffs1Size
    Local $bDistCoeffs1IsArray = IsArray($distCoeffs1)
    Local $bDistCoeffs1Create = IsDllStruct($distCoeffs1) And $typeOfDistCoeffs1 == "Scalar"

    If $typeOfDistCoeffs1 == Default Then
        $ioArrDistCoeffs1 = $distCoeffs1
    ElseIf $bDistCoeffs1IsArray Then
        $vectorDistCoeffs1 = Call("_VectorOf" & $typeOfDistCoeffs1 & "Create")

        $iArrDistCoeffs1Size = UBound($distCoeffs1)
        For $i = 0 To $iArrDistCoeffs1Size - 1
            Call("_VectorOf" & $typeOfDistCoeffs1 & "Push", $vectorDistCoeffs1, $distCoeffs1[$i])
        Next

        $ioArrDistCoeffs1 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDistCoeffs1, $vectorDistCoeffs1)
    Else
        If $bDistCoeffs1Create Then
            $distCoeffs1 = Call("_cve" & $typeOfDistCoeffs1 & "Create", $distCoeffs1)
        EndIf
        $ioArrDistCoeffs1 = Call("_cveInputOutputArrayFrom" & $typeOfDistCoeffs1, $distCoeffs1)
    EndIf

    Local $ioArrCameraMatrix2, $vectorCameraMatrix2, $iArrCameraMatrix2Size
    Local $bCameraMatrix2IsArray = IsArray($cameraMatrix2)
    Local $bCameraMatrix2Create = IsDllStruct($cameraMatrix2) And $typeOfCameraMatrix2 == "Scalar"

    If $typeOfCameraMatrix2 == Default Then
        $ioArrCameraMatrix2 = $cameraMatrix2
    ElseIf $bCameraMatrix2IsArray Then
        $vectorCameraMatrix2 = Call("_VectorOf" & $typeOfCameraMatrix2 & "Create")

        $iArrCameraMatrix2Size = UBound($cameraMatrix2)
        For $i = 0 To $iArrCameraMatrix2Size - 1
            Call("_VectorOf" & $typeOfCameraMatrix2 & "Push", $vectorCameraMatrix2, $cameraMatrix2[$i])
        Next

        $ioArrCameraMatrix2 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfCameraMatrix2, $vectorCameraMatrix2)
    Else
        If $bCameraMatrix2Create Then
            $cameraMatrix2 = Call("_cve" & $typeOfCameraMatrix2 & "Create", $cameraMatrix2)
        EndIf
        $ioArrCameraMatrix2 = Call("_cveInputOutputArrayFrom" & $typeOfCameraMatrix2, $cameraMatrix2)
    EndIf

    Local $ioArrDistCoeffs2, $vectorDistCoeffs2, $iArrDistCoeffs2Size
    Local $bDistCoeffs2IsArray = IsArray($distCoeffs2)
    Local $bDistCoeffs2Create = IsDllStruct($distCoeffs2) And $typeOfDistCoeffs2 == "Scalar"

    If $typeOfDistCoeffs2 == Default Then
        $ioArrDistCoeffs2 = $distCoeffs2
    ElseIf $bDistCoeffs2IsArray Then
        $vectorDistCoeffs2 = Call("_VectorOf" & $typeOfDistCoeffs2 & "Create")

        $iArrDistCoeffs2Size = UBound($distCoeffs2)
        For $i = 0 To $iArrDistCoeffs2Size - 1
            Call("_VectorOf" & $typeOfDistCoeffs2 & "Push", $vectorDistCoeffs2, $distCoeffs2[$i])
        Next

        $ioArrDistCoeffs2 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfDistCoeffs2, $vectorDistCoeffs2)
    Else
        If $bDistCoeffs2Create Then
            $distCoeffs2 = Call("_cve" & $typeOfDistCoeffs2 & "Create", $distCoeffs2)
        EndIf
        $ioArrDistCoeffs2 = Call("_cveInputOutputArrayFrom" & $typeOfDistCoeffs2, $distCoeffs2)
    EndIf

    Local $oArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($r)
    Local $bRCreate = IsDllStruct($r) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $oArrR = $r
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($r)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $r[$i])
        Next

        $oArrR = Call("_cveOutputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $r = Call("_cve" & $typeOfR & "Create", $r)
        EndIf
        $oArrR = Call("_cveOutputArrayFrom" & $typeOfR, $r)
    EndIf

    Local $oArrT, $vectorT, $iArrTSize
    Local $bTIsArray = IsArray($t)
    Local $bTCreate = IsDllStruct($t) And $typeOfT == "Scalar"

    If $typeOfT == Default Then
        $oArrT = $t
    ElseIf $bTIsArray Then
        $vectorT = Call("_VectorOf" & $typeOfT & "Create")

        $iArrTSize = UBound($t)
        For $i = 0 To $iArrTSize - 1
            Call("_VectorOf" & $typeOfT & "Push", $vectorT, $t[$i])
        Next

        $oArrT = Call("_cveOutputArrayFromVectorOf" & $typeOfT, $vectorT)
    Else
        If $bTCreate Then
            $t = Call("_cve" & $typeOfT & "Create", $t)
        EndIf
        $oArrT = Call("_cveOutputArrayFrom" & $typeOfT, $t)
    EndIf

    Local $oArrE, $vectorE, $iArrESize
    Local $bEIsArray = IsArray($e)
    Local $bECreate = IsDllStruct($e) And $typeOfE == "Scalar"

    If $typeOfE == Default Then
        $oArrE = $e
    ElseIf $bEIsArray Then
        $vectorE = Call("_VectorOf" & $typeOfE & "Create")

        $iArrESize = UBound($e)
        For $i = 0 To $iArrESize - 1
            Call("_VectorOf" & $typeOfE & "Push", $vectorE, $e[$i])
        Next

        $oArrE = Call("_cveOutputArrayFromVectorOf" & $typeOfE, $vectorE)
    Else
        If $bECreate Then
            $e = Call("_cve" & $typeOfE & "Create", $e)
        EndIf
        $oArrE = Call("_cveOutputArrayFrom" & $typeOfE, $e)
    EndIf

    Local $oArrF, $vectorF, $iArrFSize
    Local $bFIsArray = IsArray($f)
    Local $bFCreate = IsDllStruct($f) And $typeOfF == "Scalar"

    If $typeOfF == Default Then
        $oArrF = $f
    ElseIf $bFIsArray Then
        $vectorF = Call("_VectorOf" & $typeOfF & "Create")

        $iArrFSize = UBound($f)
        For $i = 0 To $iArrFSize - 1
            Call("_VectorOf" & $typeOfF & "Push", $vectorF, $f[$i])
        Next

        $oArrF = Call("_cveOutputArrayFromVectorOf" & $typeOfF, $vectorF)
    Else
        If $bFCreate Then
            $f = Call("_cve" & $typeOfF & "Create", $f)
        EndIf
        $oArrF = Call("_cveOutputArrayFrom" & $typeOfF, $f)
    EndIf

    Local $retval = _cveStereoCalibrate($iArrObjectPoints, $iArrImagePoints1, $iArrImagePoints2, $ioArrCameraMatrix1, $ioArrDistCoeffs1, $ioArrCameraMatrix2, $ioArrDistCoeffs2, $imageSize, $oArrR, $oArrT, $oArrE, $oArrF, $flags, $criteria)

    If $bFIsArray Then
        Call("_VectorOf" & $typeOfF & "Release", $vectorF)
    EndIf

    If $typeOfF <> Default Then
        _cveOutputArrayRelease($oArrF)
        If $bFCreate Then
            Call("_cve" & $typeOfF & "Release", $f)
        EndIf
    EndIf

    If $bEIsArray Then
        Call("_VectorOf" & $typeOfE & "Release", $vectorE)
    EndIf

    If $typeOfE <> Default Then
        _cveOutputArrayRelease($oArrE)
        If $bECreate Then
            Call("_cve" & $typeOfE & "Release", $e)
        EndIf
    EndIf

    If $bTIsArray Then
        Call("_VectorOf" & $typeOfT & "Release", $vectorT)
    EndIf

    If $typeOfT <> Default Then
        _cveOutputArrayRelease($oArrT)
        If $bTCreate Then
            Call("_cve" & $typeOfT & "Release", $t)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveOutputArrayRelease($oArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $r)
        EndIf
    EndIf

    If $bDistCoeffs2IsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs2 & "Release", $vectorDistCoeffs2)
    EndIf

    If $typeOfDistCoeffs2 <> Default Then
        _cveInputOutputArrayRelease($ioArrDistCoeffs2)
        If $bDistCoeffs2Create Then
            Call("_cve" & $typeOfDistCoeffs2 & "Release", $distCoeffs2)
        EndIf
    EndIf

    If $bCameraMatrix2IsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix2 & "Release", $vectorCameraMatrix2)
    EndIf

    If $typeOfCameraMatrix2 <> Default Then
        _cveInputOutputArrayRelease($ioArrCameraMatrix2)
        If $bCameraMatrix2Create Then
            Call("_cve" & $typeOfCameraMatrix2 & "Release", $cameraMatrix2)
        EndIf
    EndIf

    If $bDistCoeffs1IsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs1 & "Release", $vectorDistCoeffs1)
    EndIf

    If $typeOfDistCoeffs1 <> Default Then
        _cveInputOutputArrayRelease($ioArrDistCoeffs1)
        If $bDistCoeffs1Create Then
            Call("_cve" & $typeOfDistCoeffs1 & "Release", $distCoeffs1)
        EndIf
    EndIf

    If $bCameraMatrix1IsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix1 & "Release", $vectorCameraMatrix1)
    EndIf

    If $typeOfCameraMatrix1 <> Default Then
        _cveInputOutputArrayRelease($ioArrCameraMatrix1)
        If $bCameraMatrix1Create Then
            Call("_cve" & $typeOfCameraMatrix1 & "Release", $cameraMatrix1)
        EndIf
    EndIf

    If $bImagePoints2IsArray Then
        Call("_VectorOf" & $typeOfImagePoints2 & "Release", $vectorImagePoints2)
    EndIf

    If $typeOfImagePoints2 <> Default Then
        _cveInputArrayRelease($iArrImagePoints2)
        If $bImagePoints2Create Then
            Call("_cve" & $typeOfImagePoints2 & "Release", $imagePoints2)
        EndIf
    EndIf

    If $bImagePoints1IsArray Then
        Call("_VectorOf" & $typeOfImagePoints1 & "Release", $vectorImagePoints1)
    EndIf

    If $typeOfImagePoints1 <> Default Then
        _cveInputArrayRelease($iArrImagePoints1)
        If $bImagePoints1Create Then
            Call("_cve" & $typeOfImagePoints1 & "Release", $imagePoints1)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveStereoCalibrateTyped

Func _cveStereoCalibrateMat($objectPoints, $imagePoints1, $imagePoints2, $cameraMatrix1, $distCoeffs1, $cameraMatrix2, $distCoeffs2, $imageSize, $r, $t, $e, $f, $flags = $CV_CALIB_FIX_INTRINSIC, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_COUNT+$CV_TERM_CRITERIA_EPS, 30, 1e-6))
    ; cveStereoCalibrate using cv::Mat instead of _*Array
    Local $retval = _cveStereoCalibrateTyped("Mat", $objectPoints, "Mat", $imagePoints1, "Mat", $imagePoints2, "Mat", $cameraMatrix1, "Mat", $distCoeffs1, "Mat", $cameraMatrix2, "Mat", $distCoeffs2, $imageSize, "Mat", $r, "Mat", $t, "Mat", $e, "Mat", $f, $flags, $criteria)

    Return $retval
EndFunc   ;==>_cveStereoCalibrateMat

Func _cveSolvePnP($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess = false, $flags = $CV_SOLVEPNP_ITERATIVE)
    ; CVAPI(bool) cveSolvePnP(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvec, cv::_OutputArray* tvec, bool useExtrinsicGuess, int flags);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSolvePnP", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecDllType, $rvec, $sTvecDllType, $tvec, "boolean", $useExtrinsicGuess, "int", $flags), "cveSolvePnP", @error)
EndFunc   ;==>_cveSolvePnP

Func _cveSolvePnPTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $useExtrinsicGuess = false, $flags = $CV_SOLVEPNP_ITERATIVE)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $oArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $oArrRvec = Call("_cveOutputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $oArrRvec = Call("_cveOutputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $oArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $oArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $oArrTvec = Call("_cveOutputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $oArrTvec = Call("_cveOutputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $retval = _cveSolvePnP($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvec, $oArrTvec, $useExtrinsicGuess, $flags)

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveOutputArrayRelease($oArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveOutputArrayRelease($oArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSolvePnPTyped

Func _cveSolvePnPMat($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess = false, $flags = $CV_SOLVEPNP_ITERATIVE)
    ; cveSolvePnP using cv::Mat instead of _*Array
    Local $retval = _cveSolvePnPTyped("Mat", $objectPoints, "Mat", $imagePoints, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvec, "Mat", $tvec, $useExtrinsicGuess, $flags)

    Return $retval
EndFunc   ;==>_cveSolvePnPMat

Func _cveSolvePnPRansac($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, $inliers = _cveNoArray(), $flags = $CV_SOLVEPNP_ITERATIVE)
    ; CVAPI(bool) cveSolvePnPRansac(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvec, cv::_OutputArray* tvec, bool useExtrinsicGuess, int iterationsCount, float reprojectionError, double confident, cv::_OutputArray* inliers, int flags);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sInliersDllType
    If IsDllStruct($inliers) Then
        $sInliersDllType = "struct*"
    Else
        $sInliersDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveSolvePnPRansac", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecDllType, $rvec, $sTvecDllType, $tvec, "boolean", $useExtrinsicGuess, "int", $iterationsCount, "float", $reprojectionError, "double", $confident, $sInliersDllType, $inliers, "int", $flags), "cveSolvePnPRansac", @error)
EndFunc   ;==>_cveSolvePnPRansac

Func _cveSolvePnPRansacTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, $typeOfInliers = Default, $inliers = _cveNoArray(), $flags = $CV_SOLVEPNP_ITERATIVE)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $oArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $oArrRvec = Call("_cveOutputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $oArrRvec = Call("_cveOutputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $oArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $oArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $oArrTvec = Call("_cveOutputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $oArrTvec = Call("_cveOutputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $oArrInliers, $vectorInliers, $iArrInliersSize
    Local $bInliersIsArray = IsArray($inliers)
    Local $bInliersCreate = IsDllStruct($inliers) And $typeOfInliers == "Scalar"

    If $typeOfInliers == Default Then
        $oArrInliers = $inliers
    ElseIf $bInliersIsArray Then
        $vectorInliers = Call("_VectorOf" & $typeOfInliers & "Create")

        $iArrInliersSize = UBound($inliers)
        For $i = 0 To $iArrInliersSize - 1
            Call("_VectorOf" & $typeOfInliers & "Push", $vectorInliers, $inliers[$i])
        Next

        $oArrInliers = Call("_cveOutputArrayFromVectorOf" & $typeOfInliers, $vectorInliers)
    Else
        If $bInliersCreate Then
            $inliers = Call("_cve" & $typeOfInliers & "Create", $inliers)
        EndIf
        $oArrInliers = Call("_cveOutputArrayFrom" & $typeOfInliers, $inliers)
    EndIf

    Local $retval = _cveSolvePnPRansac($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvec, $oArrTvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, $oArrInliers, $flags)

    If $bInliersIsArray Then
        Call("_VectorOf" & $typeOfInliers & "Release", $vectorInliers)
    EndIf

    If $typeOfInliers <> Default Then
        _cveOutputArrayRelease($oArrInliers)
        If $bInliersCreate Then
            Call("_cve" & $typeOfInliers & "Release", $inliers)
        EndIf
    EndIf

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveOutputArrayRelease($oArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveOutputArrayRelease($oArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSolvePnPRansacTyped

Func _cveSolvePnPRansacMat($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, $inliers = _cveNoArrayMat(), $flags = $CV_SOLVEPNP_ITERATIVE)
    ; cveSolvePnPRansac using cv::Mat instead of _*Array
    Local $retval = _cveSolvePnPRansacTyped("Mat", $objectPoints, "Mat", $imagePoints, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvec, "Mat", $tvec, $useExtrinsicGuess, $iterationsCount, $reprojectionError, $confident, "Mat", $inliers, $flags)

    Return $retval
EndFunc   ;==>_cveSolvePnPRansacMat

Func _cveSolveP3P($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $flags)
    ; CVAPI(int) cveSolveP3P(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, int flags);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecsDllType
    If IsDllStruct($rvecs) Then
        $sRvecsDllType = "struct*"
    Else
        $sRvecsDllType = "ptr"
    EndIf

    Local $sTvecsDllType
    If IsDllStruct($tvecs) Then
        $sTvecsDllType = "struct*"
    Else
        $sTvecsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolveP3P", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecsDllType, $rvecs, $sTvecsDllType, $tvecs, "int", $flags), "cveSolveP3P", @error)
EndFunc   ;==>_cveSolveP3P

Func _cveSolveP3PTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvecs, $rvecs, $typeOfTvecs, $tvecs, $flags)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvecs, $vectorRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = IsArray($rvecs)
    Local $bRvecsCreate = IsDllStruct($rvecs) And $typeOfRvecs == "Scalar"

    If $typeOfRvecs == Default Then
        $oArrRvecs = $rvecs
    ElseIf $bRvecsIsArray Then
        $vectorRvecs = Call("_VectorOf" & $typeOfRvecs & "Create")

        $iArrRvecsSize = UBound($rvecs)
        For $i = 0 To $iArrRvecsSize - 1
            Call("_VectorOf" & $typeOfRvecs & "Push", $vectorRvecs, $rvecs[$i])
        Next

        $oArrRvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfRvecs, $vectorRvecs)
    Else
        If $bRvecsCreate Then
            $rvecs = Call("_cve" & $typeOfRvecs & "Create", $rvecs)
        EndIf
        $oArrRvecs = Call("_cveOutputArrayFrom" & $typeOfRvecs, $rvecs)
    EndIf

    Local $oArrTvecs, $vectorTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = IsArray($tvecs)
    Local $bTvecsCreate = IsDllStruct($tvecs) And $typeOfTvecs == "Scalar"

    If $typeOfTvecs == Default Then
        $oArrTvecs = $tvecs
    ElseIf $bTvecsIsArray Then
        $vectorTvecs = Call("_VectorOf" & $typeOfTvecs & "Create")

        $iArrTvecsSize = UBound($tvecs)
        For $i = 0 To $iArrTvecsSize - 1
            Call("_VectorOf" & $typeOfTvecs & "Push", $vectorTvecs, $tvecs[$i])
        Next

        $oArrTvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfTvecs, $vectorTvecs)
    Else
        If $bTvecsCreate Then
            $tvecs = Call("_cve" & $typeOfTvecs & "Create", $tvecs)
        EndIf
        $oArrTvecs = Call("_cveOutputArrayFrom" & $typeOfTvecs, $tvecs)
    EndIf

    Local $retval = _cveSolveP3P($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvecs, $oArrTvecs, $flags)

    If $bTvecsIsArray Then
        Call("_VectorOf" & $typeOfTvecs & "Release", $vectorTvecs)
    EndIf

    If $typeOfTvecs <> Default Then
        _cveOutputArrayRelease($oArrTvecs)
        If $bTvecsCreate Then
            Call("_cve" & $typeOfTvecs & "Release", $tvecs)
        EndIf
    EndIf

    If $bRvecsIsArray Then
        Call("_VectorOf" & $typeOfRvecs & "Release", $vectorRvecs)
    EndIf

    If $typeOfRvecs <> Default Then
        _cveOutputArrayRelease($oArrRvecs)
        If $bRvecsCreate Then
            Call("_cve" & $typeOfRvecs & "Release", $rvecs)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSolveP3PTyped

Func _cveSolveP3PMat($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $flags)
    ; cveSolveP3P using cv::Mat instead of _*Array
    Local $retval = _cveSolveP3PTyped("Mat", $objectPoints, "Mat", $imagePoints, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvecs, "Mat", $tvecs, $flags)

    Return $retval
EndFunc   ;==>_cveSolveP3PMat

Func _cveSolvePnPRefineLM($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_EPS + $CV_TERM_CRITERIA_COUNT, 20, $CV_FLT_EPSILON))
    ; CVAPI(void) cveSolvePnPRefineLM(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, CvTermCriteria* criteria);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSolvePnPRefineLM", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sCriteriaDllType, $criteria), "cveSolvePnPRefineLM", @error)
EndFunc   ;==>_cveSolvePnPRefineLM

Func _cveSolvePnPRefineLMTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_EPS + $CV_TERM_CRITERIA_COUNT, 20, $CV_FLT_EPSILON))

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $ioArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $ioArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $ioArrRvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $ioArrRvec = Call("_cveInputOutputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $ioArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $ioArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $ioArrTvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $ioArrTvec = Call("_cveInputOutputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    _cveSolvePnPRefineLM($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $criteria)

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputOutputArrayRelease($ioArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputOutputArrayRelease($ioArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveSolvePnPRefineLMTyped

Func _cveSolvePnPRefineLMMat($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_EPS + $CV_TERM_CRITERIA_COUNT, 20, $CV_FLT_EPSILON))
    ; cveSolvePnPRefineLM using cv::Mat instead of _*Array
    _cveSolvePnPRefineLMTyped("Mat", $objectPoints, "Mat", $imagePoints, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvec, "Mat", $tvec, $criteria)
EndFunc   ;==>_cveSolvePnPRefineLMMat

Func _cveSolvePnPRefineVVS($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_EPS + $CV_TERM_CRITERIA_COUNT, 20, $CV_FLT_EPSILON), $VVSlambda = 1)
    ; CVAPI(void) cveSolvePnPRefineVVS(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputOutputArray* rvec, cv::_InputOutputArray* tvec, CvTermCriteria* criteria, double VVSlambda);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSolvePnPRefineVVS", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sCriteriaDllType, $criteria, "double", $VVSlambda), "cveSolvePnPRefineVVS", @error)
EndFunc   ;==>_cveSolvePnPRefineVVS

Func _cveSolvePnPRefineVVSTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_EPS + $CV_TERM_CRITERIA_COUNT, 20, $CV_FLT_EPSILON), $VVSlambda = 1)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $ioArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $ioArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $ioArrRvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $ioArrRvec = Call("_cveInputOutputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $ioArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $ioArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $ioArrTvec = Call("_cveInputOutputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $ioArrTvec = Call("_cveInputOutputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    _cveSolvePnPRefineVVS($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $ioArrRvec, $ioArrTvec, $criteria, $VVSlambda)

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputOutputArrayRelease($ioArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputOutputArrayRelease($ioArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveSolvePnPRefineVVSTyped

Func _cveSolvePnPRefineVVSMat($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvec, $tvec, $criteria = _cvTermCriteria($CV_TERM_CRITERIA_EPS + $CV_TERM_CRITERIA_COUNT, 20, $CV_FLT_EPSILON), $VVSlambda = 1)
    ; cveSolvePnPRefineVVS using cv::Mat instead of _*Array
    _cveSolvePnPRefineVVSTyped("Mat", $objectPoints, "Mat", $imagePoints, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvec, "Mat", $tvec, $criteria, $VVSlambda)
EndFunc   ;==>_cveSolvePnPRefineVVSMat

Func _cveSolvePnPGeneric($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $useExtrinsicGuess = false, $flags = $CV_SOLVEPNP_ITERATIVE, $rvec = _cveNoArray(), $tvec = _cveNoArray(), $reprojectionError = _cveNoArray())
    ; CVAPI(int) cveSolvePnPGeneric(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, bool useExtrinsicGuess, int flags, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_OutputArray* reprojectionError);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRvecsDllType
    If IsDllStruct($rvecs) Then
        $sRvecsDllType = "struct*"
    Else
        $sRvecsDllType = "ptr"
    EndIf

    Local $sTvecsDllType
    If IsDllStruct($tvecs) Then
        $sTvecsDllType = "struct*"
    Else
        $sTvecsDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sReprojectionErrorDllType
    If IsDllStruct($reprojectionError) Then
        $sReprojectionErrorDllType = "struct*"
    Else
        $sReprojectionErrorDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveSolvePnPGeneric", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRvecsDllType, $rvecs, $sTvecsDllType, $tvecs, "boolean", $useExtrinsicGuess, "int", $flags, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sReprojectionErrorDllType, $reprojectionError), "cveSolvePnPGeneric", @error)
EndFunc   ;==>_cveSolvePnPGeneric

Func _cveSolvePnPGenericTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfRvecs, $rvecs, $typeOfTvecs, $tvecs, $useExtrinsicGuess = false, $flags = $CV_SOLVEPNP_ITERATIVE, $typeOfRvec = Default, $rvec = _cveNoArray(), $typeOfTvec = Default, $tvec = _cveNoArray(), $typeOfReprojectionError = Default, $reprojectionError = _cveNoArray())

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $oArrRvecs, $vectorRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = IsArray($rvecs)
    Local $bRvecsCreate = IsDllStruct($rvecs) And $typeOfRvecs == "Scalar"

    If $typeOfRvecs == Default Then
        $oArrRvecs = $rvecs
    ElseIf $bRvecsIsArray Then
        $vectorRvecs = Call("_VectorOf" & $typeOfRvecs & "Create")

        $iArrRvecsSize = UBound($rvecs)
        For $i = 0 To $iArrRvecsSize - 1
            Call("_VectorOf" & $typeOfRvecs & "Push", $vectorRvecs, $rvecs[$i])
        Next

        $oArrRvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfRvecs, $vectorRvecs)
    Else
        If $bRvecsCreate Then
            $rvecs = Call("_cve" & $typeOfRvecs & "Create", $rvecs)
        EndIf
        $oArrRvecs = Call("_cveOutputArrayFrom" & $typeOfRvecs, $rvecs)
    EndIf

    Local $oArrTvecs, $vectorTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = IsArray($tvecs)
    Local $bTvecsCreate = IsDllStruct($tvecs) And $typeOfTvecs == "Scalar"

    If $typeOfTvecs == Default Then
        $oArrTvecs = $tvecs
    ElseIf $bTvecsIsArray Then
        $vectorTvecs = Call("_VectorOf" & $typeOfTvecs & "Create")

        $iArrTvecsSize = UBound($tvecs)
        For $i = 0 To $iArrTvecsSize - 1
            Call("_VectorOf" & $typeOfTvecs & "Push", $vectorTvecs, $tvecs[$i])
        Next

        $oArrTvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfTvecs, $vectorTvecs)
    Else
        If $bTvecsCreate Then
            $tvecs = Call("_cve" & $typeOfTvecs & "Create", $tvecs)
        EndIf
        $oArrTvecs = Call("_cveOutputArrayFrom" & $typeOfTvecs, $tvecs)
    EndIf

    Local $iArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $iArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $iArrRvec = Call("_cveInputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $iArrRvec = Call("_cveInputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $iArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $iArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $iArrTvec = Call("_cveInputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $iArrTvec = Call("_cveInputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $oArrReprojectionError, $vectorReprojectionError, $iArrReprojectionErrorSize
    Local $bReprojectionErrorIsArray = IsArray($reprojectionError)
    Local $bReprojectionErrorCreate = IsDllStruct($reprojectionError) And $typeOfReprojectionError == "Scalar"

    If $typeOfReprojectionError == Default Then
        $oArrReprojectionError = $reprojectionError
    ElseIf $bReprojectionErrorIsArray Then
        $vectorReprojectionError = Call("_VectorOf" & $typeOfReprojectionError & "Create")

        $iArrReprojectionErrorSize = UBound($reprojectionError)
        For $i = 0 To $iArrReprojectionErrorSize - 1
            Call("_VectorOf" & $typeOfReprojectionError & "Push", $vectorReprojectionError, $reprojectionError[$i])
        Next

        $oArrReprojectionError = Call("_cveOutputArrayFromVectorOf" & $typeOfReprojectionError, $vectorReprojectionError)
    Else
        If $bReprojectionErrorCreate Then
            $reprojectionError = Call("_cve" & $typeOfReprojectionError & "Create", $reprojectionError)
        EndIf
        $oArrReprojectionError = Call("_cveOutputArrayFrom" & $typeOfReprojectionError, $reprojectionError)
    EndIf

    Local $retval = _cveSolvePnPGeneric($iArrObjectPoints, $iArrImagePoints, $iArrCameraMatrix, $iArrDistCoeffs, $oArrRvecs, $oArrTvecs, $useExtrinsicGuess, $flags, $iArrRvec, $iArrTvec, $oArrReprojectionError)

    If $bReprojectionErrorIsArray Then
        Call("_VectorOf" & $typeOfReprojectionError & "Release", $vectorReprojectionError)
    EndIf

    If $typeOfReprojectionError <> Default Then
        _cveOutputArrayRelease($oArrReprojectionError)
        If $bReprojectionErrorCreate Then
            Call("_cve" & $typeOfReprojectionError & "Release", $reprojectionError)
        EndIf
    EndIf

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputArrayRelease($iArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputArrayRelease($iArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bTvecsIsArray Then
        Call("_VectorOf" & $typeOfTvecs & "Release", $vectorTvecs)
    EndIf

    If $typeOfTvecs <> Default Then
        _cveOutputArrayRelease($oArrTvecs)
        If $bTvecsCreate Then
            Call("_cve" & $typeOfTvecs & "Release", $tvecs)
        EndIf
    EndIf

    If $bRvecsIsArray Then
        Call("_VectorOf" & $typeOfRvecs & "Release", $vectorRvecs)
    EndIf

    If $typeOfRvecs <> Default Then
        _cveOutputArrayRelease($oArrRvecs)
        If $bRvecsCreate Then
            Call("_cve" & $typeOfRvecs & "Release", $rvecs)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveSolvePnPGenericTyped

Func _cveSolvePnPGenericMat($objectPoints, $imagePoints, $cameraMatrix, $distCoeffs, $rvecs, $tvecs, $useExtrinsicGuess = false, $flags = $CV_SOLVEPNP_ITERATIVE, $rvec = _cveNoArrayMat(), $tvec = _cveNoArrayMat(), $reprojectionError = _cveNoArrayMat())
    ; cveSolvePnPGeneric using cv::Mat instead of _*Array
    Local $retval = _cveSolvePnPGenericTyped("Mat", $objectPoints, "Mat", $imagePoints, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $rvecs, "Mat", $tvecs, $useExtrinsicGuess, $flags, "Mat", $rvec, "Mat", $tvec, "Mat", $reprojectionError)

    Return $retval
EndFunc   ;==>_cveSolvePnPGenericMat

Func _cveGetOptimalNewCameraMatrix($cameraMatrix, $distCoeffs, $imageSize, $alpha, $newImgSize, $validPixROI, $centerPrincipalPoint, $newCameraMatrix)
    ; CVAPI(void) cveGetOptimalNewCameraMatrix(cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, CvSize* imageSize, double alpha, CvSize* newImgSize, CvRect* validPixROI, bool centerPrincipalPoint, cv::Mat* newCameraMatrix);

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sNewImgSizeDllType
    If IsDllStruct($newImgSize) Then
        $sNewImgSizeDllType = "struct*"
    Else
        $sNewImgSizeDllType = "ptr"
    EndIf

    Local $sValidPixROIDllType
    If IsDllStruct($validPixROI) Then
        $sValidPixROIDllType = "struct*"
    Else
        $sValidPixROIDllType = "ptr"
    EndIf

    Local $sNewCameraMatrixDllType
    If IsDllStruct($newCameraMatrix) Then
        $sNewCameraMatrixDllType = "struct*"
    Else
        $sNewCameraMatrixDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetOptimalNewCameraMatrix", $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sImageSizeDllType, $imageSize, "double", $alpha, $sNewImgSizeDllType, $newImgSize, $sValidPixROIDllType, $validPixROI, "boolean", $centerPrincipalPoint, $sNewCameraMatrixDllType, $newCameraMatrix), "cveGetOptimalNewCameraMatrix", @error)
EndFunc   ;==>_cveGetOptimalNewCameraMatrix

Func _cveGetOptimalNewCameraMatrixTyped($typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $imageSize, $alpha, $newImgSize, $validPixROI, $centerPrincipalPoint, $newCameraMatrix)

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    _cveGetOptimalNewCameraMatrix($iArrCameraMatrix, $iArrDistCoeffs, $imageSize, $alpha, $newImgSize, $validPixROI, $centerPrincipalPoint, $newCameraMatrix)

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf
EndFunc   ;==>_cveGetOptimalNewCameraMatrixTyped

Func _cveGetOptimalNewCameraMatrixMat($cameraMatrix, $distCoeffs, $imageSize, $alpha, $newImgSize, $validPixROI, $centerPrincipalPoint, $newCameraMatrix)
    ; cveGetOptimalNewCameraMatrix using cv::Mat instead of _*Array
    _cveGetOptimalNewCameraMatrixTyped("Mat", $cameraMatrix, "Mat", $distCoeffs, $imageSize, $alpha, $newImgSize, $validPixROI, $centerPrincipalPoint, $newCameraMatrix)
EndFunc   ;==>_cveGetOptimalNewCameraMatrixMat

Func _cveInitCameraMatrix2D($objectPoints, $imagePoints, $imageSize, $aspectRatio, $cameraMatrix)
    ; CVAPI(void) cveInitCameraMatrix2D(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, CvSize* imageSize, double aspectRatio, cv::Mat* cameraMatrix);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInitCameraMatrix2D", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sImageSizeDllType, $imageSize, "double", $aspectRatio, $sCameraMatrixDllType, $cameraMatrix), "cveInitCameraMatrix2D", @error)
EndFunc   ;==>_cveInitCameraMatrix2D

Func _cveInitCameraMatrix2DTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $imageSize, $aspectRatio, $cameraMatrix)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    _cveInitCameraMatrix2D($iArrObjectPoints, $iArrImagePoints, $imageSize, $aspectRatio, $cameraMatrix)

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveInitCameraMatrix2DTyped

Func _cveInitCameraMatrix2DMat($objectPoints, $imagePoints, $imageSize, $aspectRatio, $cameraMatrix)
    ; cveInitCameraMatrix2D using cv::Mat instead of _*Array
    _cveInitCameraMatrix2DTyped("Mat", $objectPoints, "Mat", $imagePoints, $imageSize, $aspectRatio, $cameraMatrix)
EndFunc   ;==>_cveInitCameraMatrix2DMat

Func _cveFisheyeProjectPoints($objectPoints, $imagePoints, $rvec, $tvec, $K, $D, $alpha, $jacobian)
    ; CVAPI(void) cveFisheyeProjectPoints(cv::_InputArray* objectPoints, cv::_OutputArray* imagePoints, cv::_InputArray* rvec, cv::_InputArray* tvec, cv::_InputArray* K, cv::_InputArray* D, double alpha, cv::_OutputArray* jacobian);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sRvecDllType
    If IsDllStruct($rvec) Then
        $sRvecDllType = "struct*"
    Else
        $sRvecDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sDDllType
    If IsDllStruct($D) Then
        $sDDllType = "struct*"
    Else
        $sDDllType = "ptr"
    EndIf

    Local $sJacobianDllType
    If IsDllStruct($jacobian) Then
        $sJacobianDllType = "struct*"
    Else
        $sJacobianDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeProjectPoints", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sRvecDllType, $rvec, $sTvecDllType, $tvec, $sKDllType, $K, $sDDllType, $D, "double", $alpha, $sJacobianDllType, $jacobian), "cveFisheyeProjectPoints", @error)
EndFunc   ;==>_cveFisheyeProjectPoints

Func _cveFisheyeProjectPointsTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $typeOfRvec, $rvec, $typeOfTvec, $tvec, $typeOfK, $K, $typeOfD, $D, $alpha, $typeOfJacobian, $jacobian)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $oArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $oArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $oArrImagePoints = Call("_cveOutputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $oArrImagePoints = Call("_cveOutputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $iArrRvec, $vectorRvec, $iArrRvecSize
    Local $bRvecIsArray = IsArray($rvec)
    Local $bRvecCreate = IsDllStruct($rvec) And $typeOfRvec == "Scalar"

    If $typeOfRvec == Default Then
        $iArrRvec = $rvec
    ElseIf $bRvecIsArray Then
        $vectorRvec = Call("_VectorOf" & $typeOfRvec & "Create")

        $iArrRvecSize = UBound($rvec)
        For $i = 0 To $iArrRvecSize - 1
            Call("_VectorOf" & $typeOfRvec & "Push", $vectorRvec, $rvec[$i])
        Next

        $iArrRvec = Call("_cveInputArrayFromVectorOf" & $typeOfRvec, $vectorRvec)
    Else
        If $bRvecCreate Then
            $rvec = Call("_cve" & $typeOfRvec & "Create", $rvec)
        EndIf
        $iArrRvec = Call("_cveInputArrayFrom" & $typeOfRvec, $rvec)
    EndIf

    Local $iArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $iArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $iArrTvec = Call("_cveInputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $iArrTvec = Call("_cveInputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $iArrD, $vectorD, $iArrDSize
    Local $bDIsArray = IsArray($D)
    Local $bDCreate = IsDllStruct($D) And $typeOfD == "Scalar"

    If $typeOfD == Default Then
        $iArrD = $D
    ElseIf $bDIsArray Then
        $vectorD = Call("_VectorOf" & $typeOfD & "Create")

        $iArrDSize = UBound($D)
        For $i = 0 To $iArrDSize - 1
            Call("_VectorOf" & $typeOfD & "Push", $vectorD, $D[$i])
        Next

        $iArrD = Call("_cveInputArrayFromVectorOf" & $typeOfD, $vectorD)
    Else
        If $bDCreate Then
            $D = Call("_cve" & $typeOfD & "Create", $D)
        EndIf
        $iArrD = Call("_cveInputArrayFrom" & $typeOfD, $D)
    EndIf

    Local $oArrJacobian, $vectorJacobian, $iArrJacobianSize
    Local $bJacobianIsArray = IsArray($jacobian)
    Local $bJacobianCreate = IsDllStruct($jacobian) And $typeOfJacobian == "Scalar"

    If $typeOfJacobian == Default Then
        $oArrJacobian = $jacobian
    ElseIf $bJacobianIsArray Then
        $vectorJacobian = Call("_VectorOf" & $typeOfJacobian & "Create")

        $iArrJacobianSize = UBound($jacobian)
        For $i = 0 To $iArrJacobianSize - 1
            Call("_VectorOf" & $typeOfJacobian & "Push", $vectorJacobian, $jacobian[$i])
        Next

        $oArrJacobian = Call("_cveOutputArrayFromVectorOf" & $typeOfJacobian, $vectorJacobian)
    Else
        If $bJacobianCreate Then
            $jacobian = Call("_cve" & $typeOfJacobian & "Create", $jacobian)
        EndIf
        $oArrJacobian = Call("_cveOutputArrayFrom" & $typeOfJacobian, $jacobian)
    EndIf

    _cveFisheyeProjectPoints($iArrObjectPoints, $oArrImagePoints, $iArrRvec, $iArrTvec, $iArrK, $iArrD, $alpha, $oArrJacobian)

    If $bJacobianIsArray Then
        Call("_VectorOf" & $typeOfJacobian & "Release", $vectorJacobian)
    EndIf

    If $typeOfJacobian <> Default Then
        _cveOutputArrayRelease($oArrJacobian)
        If $bJacobianCreate Then
            Call("_cve" & $typeOfJacobian & "Release", $jacobian)
        EndIf
    EndIf

    If $bDIsArray Then
        Call("_VectorOf" & $typeOfD & "Release", $vectorD)
    EndIf

    If $typeOfD <> Default Then
        _cveInputArrayRelease($iArrD)
        If $bDCreate Then
            Call("_cve" & $typeOfD & "Release", $D)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputArrayRelease($iArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRvecIsArray Then
        Call("_VectorOf" & $typeOfRvec & "Release", $vectorRvec)
    EndIf

    If $typeOfRvec <> Default Then
        _cveInputArrayRelease($iArrRvec)
        If $bRvecCreate Then
            Call("_cve" & $typeOfRvec & "Release", $rvec)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveOutputArrayRelease($oArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeProjectPointsTyped

Func _cveFisheyeProjectPointsMat($objectPoints, $imagePoints, $rvec, $tvec, $K, $D, $alpha, $jacobian)
    ; cveFisheyeProjectPoints using cv::Mat instead of _*Array
    _cveFisheyeProjectPointsTyped("Mat", $objectPoints, "Mat", $imagePoints, "Mat", $rvec, "Mat", $tvec, "Mat", $K, "Mat", $D, $alpha, "Mat", $jacobian)
EndFunc   ;==>_cveFisheyeProjectPointsMat

Func _cveFisheyeDistortPoints($undistored, $distorted, $K, $D, $alpha)
    ; CVAPI(void) cveFisheyeDistortPoints(cv::_InputArray* undistored, cv::_OutputArray* distorted, cv::_InputArray* K, cv::_InputArray* D, double alpha);

    Local $sUndistoredDllType
    If IsDllStruct($undistored) Then
        $sUndistoredDllType = "struct*"
    Else
        $sUndistoredDllType = "ptr"
    EndIf

    Local $sDistortedDllType
    If IsDllStruct($distorted) Then
        $sDistortedDllType = "struct*"
    Else
        $sDistortedDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sDDllType
    If IsDllStruct($D) Then
        $sDDllType = "struct*"
    Else
        $sDDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeDistortPoints", $sUndistoredDllType, $undistored, $sDistortedDllType, $distorted, $sKDllType, $K, $sDDllType, $D, "double", $alpha), "cveFisheyeDistortPoints", @error)
EndFunc   ;==>_cveFisheyeDistortPoints

Func _cveFisheyeDistortPointsTyped($typeOfUndistored, $undistored, $typeOfDistorted, $distorted, $typeOfK, $K, $typeOfD, $D, $alpha)

    Local $iArrUndistored, $vectorUndistored, $iArrUndistoredSize
    Local $bUndistoredIsArray = IsArray($undistored)
    Local $bUndistoredCreate = IsDllStruct($undistored) And $typeOfUndistored == "Scalar"

    If $typeOfUndistored == Default Then
        $iArrUndistored = $undistored
    ElseIf $bUndistoredIsArray Then
        $vectorUndistored = Call("_VectorOf" & $typeOfUndistored & "Create")

        $iArrUndistoredSize = UBound($undistored)
        For $i = 0 To $iArrUndistoredSize - 1
            Call("_VectorOf" & $typeOfUndistored & "Push", $vectorUndistored, $undistored[$i])
        Next

        $iArrUndistored = Call("_cveInputArrayFromVectorOf" & $typeOfUndistored, $vectorUndistored)
    Else
        If $bUndistoredCreate Then
            $undistored = Call("_cve" & $typeOfUndistored & "Create", $undistored)
        EndIf
        $iArrUndistored = Call("_cveInputArrayFrom" & $typeOfUndistored, $undistored)
    EndIf

    Local $oArrDistorted, $vectorDistorted, $iArrDistortedSize
    Local $bDistortedIsArray = IsArray($distorted)
    Local $bDistortedCreate = IsDllStruct($distorted) And $typeOfDistorted == "Scalar"

    If $typeOfDistorted == Default Then
        $oArrDistorted = $distorted
    ElseIf $bDistortedIsArray Then
        $vectorDistorted = Call("_VectorOf" & $typeOfDistorted & "Create")

        $iArrDistortedSize = UBound($distorted)
        For $i = 0 To $iArrDistortedSize - 1
            Call("_VectorOf" & $typeOfDistorted & "Push", $vectorDistorted, $distorted[$i])
        Next

        $oArrDistorted = Call("_cveOutputArrayFromVectorOf" & $typeOfDistorted, $vectorDistorted)
    Else
        If $bDistortedCreate Then
            $distorted = Call("_cve" & $typeOfDistorted & "Create", $distorted)
        EndIf
        $oArrDistorted = Call("_cveOutputArrayFrom" & $typeOfDistorted, $distorted)
    EndIf

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $iArrD, $vectorD, $iArrDSize
    Local $bDIsArray = IsArray($D)
    Local $bDCreate = IsDllStruct($D) And $typeOfD == "Scalar"

    If $typeOfD == Default Then
        $iArrD = $D
    ElseIf $bDIsArray Then
        $vectorD = Call("_VectorOf" & $typeOfD & "Create")

        $iArrDSize = UBound($D)
        For $i = 0 To $iArrDSize - 1
            Call("_VectorOf" & $typeOfD & "Push", $vectorD, $D[$i])
        Next

        $iArrD = Call("_cveInputArrayFromVectorOf" & $typeOfD, $vectorD)
    Else
        If $bDCreate Then
            $D = Call("_cve" & $typeOfD & "Create", $D)
        EndIf
        $iArrD = Call("_cveInputArrayFrom" & $typeOfD, $D)
    EndIf

    _cveFisheyeDistortPoints($iArrUndistored, $oArrDistorted, $iArrK, $iArrD, $alpha)

    If $bDIsArray Then
        Call("_VectorOf" & $typeOfD & "Release", $vectorD)
    EndIf

    If $typeOfD <> Default Then
        _cveInputArrayRelease($iArrD)
        If $bDCreate Then
            Call("_cve" & $typeOfD & "Release", $D)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bDistortedIsArray Then
        Call("_VectorOf" & $typeOfDistorted & "Release", $vectorDistorted)
    EndIf

    If $typeOfDistorted <> Default Then
        _cveOutputArrayRelease($oArrDistorted)
        If $bDistortedCreate Then
            Call("_cve" & $typeOfDistorted & "Release", $distorted)
        EndIf
    EndIf

    If $bUndistoredIsArray Then
        Call("_VectorOf" & $typeOfUndistored & "Release", $vectorUndistored)
    EndIf

    If $typeOfUndistored <> Default Then
        _cveInputArrayRelease($iArrUndistored)
        If $bUndistoredCreate Then
            Call("_cve" & $typeOfUndistored & "Release", $undistored)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeDistortPointsTyped

Func _cveFisheyeDistortPointsMat($undistored, $distorted, $K, $D, $alpha)
    ; cveFisheyeDistortPoints using cv::Mat instead of _*Array
    _cveFisheyeDistortPointsTyped("Mat", $undistored, "Mat", $distorted, "Mat", $K, "Mat", $D, $alpha)
EndFunc   ;==>_cveFisheyeDistortPointsMat

Func _cveFisheyeUndistorPoints($distorted, $undistorted, $K, $D, $R, $P)
    ; CVAPI(void) cveFisheyeUndistorPoints(cv::_InputArray* distorted, cv::_OutputArray* undistorted, cv::_InputArray* K, cv::_InputArray* D, cv::_InputArray* R, cv::_InputArray* P);

    Local $sDistortedDllType
    If IsDllStruct($distorted) Then
        $sDistortedDllType = "struct*"
    Else
        $sDistortedDllType = "ptr"
    EndIf

    Local $sUndistortedDllType
    If IsDllStruct($undistorted) Then
        $sUndistortedDllType = "struct*"
    Else
        $sUndistortedDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sDDllType
    If IsDllStruct($D) Then
        $sDDllType = "struct*"
    Else
        $sDDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($R) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($P) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeUndistorPoints", $sDistortedDllType, $distorted, $sUndistortedDllType, $undistorted, $sKDllType, $K, $sDDllType, $D, $sRDllType, $R, $sPDllType, $P), "cveFisheyeUndistorPoints", @error)
EndFunc   ;==>_cveFisheyeUndistorPoints

Func _cveFisheyeUndistorPointsTyped($typeOfDistorted, $distorted, $typeOfUndistorted, $undistorted, $typeOfK, $K, $typeOfD, $D, $typeOfR, $R, $typeOfP, $P)

    Local $iArrDistorted, $vectorDistorted, $iArrDistortedSize
    Local $bDistortedIsArray = IsArray($distorted)
    Local $bDistortedCreate = IsDllStruct($distorted) And $typeOfDistorted == "Scalar"

    If $typeOfDistorted == Default Then
        $iArrDistorted = $distorted
    ElseIf $bDistortedIsArray Then
        $vectorDistorted = Call("_VectorOf" & $typeOfDistorted & "Create")

        $iArrDistortedSize = UBound($distorted)
        For $i = 0 To $iArrDistortedSize - 1
            Call("_VectorOf" & $typeOfDistorted & "Push", $vectorDistorted, $distorted[$i])
        Next

        $iArrDistorted = Call("_cveInputArrayFromVectorOf" & $typeOfDistorted, $vectorDistorted)
    Else
        If $bDistortedCreate Then
            $distorted = Call("_cve" & $typeOfDistorted & "Create", $distorted)
        EndIf
        $iArrDistorted = Call("_cveInputArrayFrom" & $typeOfDistorted, $distorted)
    EndIf

    Local $oArrUndistorted, $vectorUndistorted, $iArrUndistortedSize
    Local $bUndistortedIsArray = IsArray($undistorted)
    Local $bUndistortedCreate = IsDllStruct($undistorted) And $typeOfUndistorted == "Scalar"

    If $typeOfUndistorted == Default Then
        $oArrUndistorted = $undistorted
    ElseIf $bUndistortedIsArray Then
        $vectorUndistorted = Call("_VectorOf" & $typeOfUndistorted & "Create")

        $iArrUndistortedSize = UBound($undistorted)
        For $i = 0 To $iArrUndistortedSize - 1
            Call("_VectorOf" & $typeOfUndistorted & "Push", $vectorUndistorted, $undistorted[$i])
        Next

        $oArrUndistorted = Call("_cveOutputArrayFromVectorOf" & $typeOfUndistorted, $vectorUndistorted)
    Else
        If $bUndistortedCreate Then
            $undistorted = Call("_cve" & $typeOfUndistorted & "Create", $undistorted)
        EndIf
        $oArrUndistorted = Call("_cveOutputArrayFrom" & $typeOfUndistorted, $undistorted)
    EndIf

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $iArrD, $vectorD, $iArrDSize
    Local $bDIsArray = IsArray($D)
    Local $bDCreate = IsDllStruct($D) And $typeOfD == "Scalar"

    If $typeOfD == Default Then
        $iArrD = $D
    ElseIf $bDIsArray Then
        $vectorD = Call("_VectorOf" & $typeOfD & "Create")

        $iArrDSize = UBound($D)
        For $i = 0 To $iArrDSize - 1
            Call("_VectorOf" & $typeOfD & "Push", $vectorD, $D[$i])
        Next

        $iArrD = Call("_cveInputArrayFromVectorOf" & $typeOfD, $vectorD)
    Else
        If $bDCreate Then
            $D = Call("_cve" & $typeOfD & "Create", $D)
        EndIf
        $iArrD = Call("_cveInputArrayFrom" & $typeOfD, $D)
    EndIf

    Local $iArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($R)
    Local $bRCreate = IsDllStruct($R) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $iArrR = $R
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($R)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $R[$i])
        Next

        $iArrR = Call("_cveInputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $R = Call("_cve" & $typeOfR & "Create", $R)
        EndIf
        $iArrR = Call("_cveInputArrayFrom" & $typeOfR, $R)
    EndIf

    Local $iArrP, $vectorP, $iArrPSize
    Local $bPIsArray = IsArray($P)
    Local $bPCreate = IsDllStruct($P) And $typeOfP == "Scalar"

    If $typeOfP == Default Then
        $iArrP = $P
    ElseIf $bPIsArray Then
        $vectorP = Call("_VectorOf" & $typeOfP & "Create")

        $iArrPSize = UBound($P)
        For $i = 0 To $iArrPSize - 1
            Call("_VectorOf" & $typeOfP & "Push", $vectorP, $P[$i])
        Next

        $iArrP = Call("_cveInputArrayFromVectorOf" & $typeOfP, $vectorP)
    Else
        If $bPCreate Then
            $P = Call("_cve" & $typeOfP & "Create", $P)
        EndIf
        $iArrP = Call("_cveInputArrayFrom" & $typeOfP, $P)
    EndIf

    _cveFisheyeUndistorPoints($iArrDistorted, $oArrUndistorted, $iArrK, $iArrD, $iArrR, $iArrP)

    If $bPIsArray Then
        Call("_VectorOf" & $typeOfP & "Release", $vectorP)
    EndIf

    If $typeOfP <> Default Then
        _cveInputArrayRelease($iArrP)
        If $bPCreate Then
            Call("_cve" & $typeOfP & "Release", $P)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveInputArrayRelease($iArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $R)
        EndIf
    EndIf

    If $bDIsArray Then
        Call("_VectorOf" & $typeOfD & "Release", $vectorD)
    EndIf

    If $typeOfD <> Default Then
        _cveInputArrayRelease($iArrD)
        If $bDCreate Then
            Call("_cve" & $typeOfD & "Release", $D)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bUndistortedIsArray Then
        Call("_VectorOf" & $typeOfUndistorted & "Release", $vectorUndistorted)
    EndIf

    If $typeOfUndistorted <> Default Then
        _cveOutputArrayRelease($oArrUndistorted)
        If $bUndistortedCreate Then
            Call("_cve" & $typeOfUndistorted & "Release", $undistorted)
        EndIf
    EndIf

    If $bDistortedIsArray Then
        Call("_VectorOf" & $typeOfDistorted & "Release", $vectorDistorted)
    EndIf

    If $typeOfDistorted <> Default Then
        _cveInputArrayRelease($iArrDistorted)
        If $bDistortedCreate Then
            Call("_cve" & $typeOfDistorted & "Release", $distorted)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeUndistorPointsTyped

Func _cveFisheyeUndistorPointsMat($distorted, $undistorted, $K, $D, $R, $P)
    ; cveFisheyeUndistorPoints using cv::Mat instead of _*Array
    _cveFisheyeUndistorPointsTyped("Mat", $distorted, "Mat", $undistorted, "Mat", $K, "Mat", $D, "Mat", $R, "Mat", $P)
EndFunc   ;==>_cveFisheyeUndistorPointsMat

Func _cveFisheyeInitUndistorRectifyMap($K, $D, $R, $P, $size, $m1Type, $map1, $map2)
    ; CVAPI(void) cveFisheyeInitUndistorRectifyMap(cv::_InputArray* K, cv::_InputArray* D, cv::_InputArray* R, cv::_InputArray* P, CvSize* size, int m1Type, cv::_OutputArray* map1, cv::_OutputArray* map2);

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sDDllType
    If IsDllStruct($D) Then
        $sDDllType = "struct*"
    Else
        $sDDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($R) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($P) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    Local $sMap1DllType
    If IsDllStruct($map1) Then
        $sMap1DllType = "struct*"
    Else
        $sMap1DllType = "ptr"
    EndIf

    Local $sMap2DllType
    If IsDllStruct($map2) Then
        $sMap2DllType = "struct*"
    Else
        $sMap2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeInitUndistorRectifyMap", $sKDllType, $K, $sDDllType, $D, $sRDllType, $R, $sPDllType, $P, $sSizeDllType, $size, "int", $m1Type, $sMap1DllType, $map1, $sMap2DllType, $map2), "cveFisheyeInitUndistorRectifyMap", @error)
EndFunc   ;==>_cveFisheyeInitUndistorRectifyMap

Func _cveFisheyeInitUndistorRectifyMapTyped($typeOfK, $K, $typeOfD, $D, $typeOfR, $R, $typeOfP, $P, $size, $m1Type, $typeOfMap1, $map1, $typeOfMap2, $map2)

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $iArrD, $vectorD, $iArrDSize
    Local $bDIsArray = IsArray($D)
    Local $bDCreate = IsDllStruct($D) And $typeOfD == "Scalar"

    If $typeOfD == Default Then
        $iArrD = $D
    ElseIf $bDIsArray Then
        $vectorD = Call("_VectorOf" & $typeOfD & "Create")

        $iArrDSize = UBound($D)
        For $i = 0 To $iArrDSize - 1
            Call("_VectorOf" & $typeOfD & "Push", $vectorD, $D[$i])
        Next

        $iArrD = Call("_cveInputArrayFromVectorOf" & $typeOfD, $vectorD)
    Else
        If $bDCreate Then
            $D = Call("_cve" & $typeOfD & "Create", $D)
        EndIf
        $iArrD = Call("_cveInputArrayFrom" & $typeOfD, $D)
    EndIf

    Local $iArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($R)
    Local $bRCreate = IsDllStruct($R) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $iArrR = $R
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($R)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $R[$i])
        Next

        $iArrR = Call("_cveInputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $R = Call("_cve" & $typeOfR & "Create", $R)
        EndIf
        $iArrR = Call("_cveInputArrayFrom" & $typeOfR, $R)
    EndIf

    Local $iArrP, $vectorP, $iArrPSize
    Local $bPIsArray = IsArray($P)
    Local $bPCreate = IsDllStruct($P) And $typeOfP == "Scalar"

    If $typeOfP == Default Then
        $iArrP = $P
    ElseIf $bPIsArray Then
        $vectorP = Call("_VectorOf" & $typeOfP & "Create")

        $iArrPSize = UBound($P)
        For $i = 0 To $iArrPSize - 1
            Call("_VectorOf" & $typeOfP & "Push", $vectorP, $P[$i])
        Next

        $iArrP = Call("_cveInputArrayFromVectorOf" & $typeOfP, $vectorP)
    Else
        If $bPCreate Then
            $P = Call("_cve" & $typeOfP & "Create", $P)
        EndIf
        $iArrP = Call("_cveInputArrayFrom" & $typeOfP, $P)
    EndIf

    Local $oArrMap1, $vectorMap1, $iArrMap1Size
    Local $bMap1IsArray = IsArray($map1)
    Local $bMap1Create = IsDllStruct($map1) And $typeOfMap1 == "Scalar"

    If $typeOfMap1 == Default Then
        $oArrMap1 = $map1
    ElseIf $bMap1IsArray Then
        $vectorMap1 = Call("_VectorOf" & $typeOfMap1 & "Create")

        $iArrMap1Size = UBound($map1)
        For $i = 0 To $iArrMap1Size - 1
            Call("_VectorOf" & $typeOfMap1 & "Push", $vectorMap1, $map1[$i])
        Next

        $oArrMap1 = Call("_cveOutputArrayFromVectorOf" & $typeOfMap1, $vectorMap1)
    Else
        If $bMap1Create Then
            $map1 = Call("_cve" & $typeOfMap1 & "Create", $map1)
        EndIf
        $oArrMap1 = Call("_cveOutputArrayFrom" & $typeOfMap1, $map1)
    EndIf

    Local $oArrMap2, $vectorMap2, $iArrMap2Size
    Local $bMap2IsArray = IsArray($map2)
    Local $bMap2Create = IsDllStruct($map2) And $typeOfMap2 == "Scalar"

    If $typeOfMap2 == Default Then
        $oArrMap2 = $map2
    ElseIf $bMap2IsArray Then
        $vectorMap2 = Call("_VectorOf" & $typeOfMap2 & "Create")

        $iArrMap2Size = UBound($map2)
        For $i = 0 To $iArrMap2Size - 1
            Call("_VectorOf" & $typeOfMap2 & "Push", $vectorMap2, $map2[$i])
        Next

        $oArrMap2 = Call("_cveOutputArrayFromVectorOf" & $typeOfMap2, $vectorMap2)
    Else
        If $bMap2Create Then
            $map2 = Call("_cve" & $typeOfMap2 & "Create", $map2)
        EndIf
        $oArrMap2 = Call("_cveOutputArrayFrom" & $typeOfMap2, $map2)
    EndIf

    _cveFisheyeInitUndistorRectifyMap($iArrK, $iArrD, $iArrR, $iArrP, $size, $m1Type, $oArrMap1, $oArrMap2)

    If $bMap2IsArray Then
        Call("_VectorOf" & $typeOfMap2 & "Release", $vectorMap2)
    EndIf

    If $typeOfMap2 <> Default Then
        _cveOutputArrayRelease($oArrMap2)
        If $bMap2Create Then
            Call("_cve" & $typeOfMap2 & "Release", $map2)
        EndIf
    EndIf

    If $bMap1IsArray Then
        Call("_VectorOf" & $typeOfMap1 & "Release", $vectorMap1)
    EndIf

    If $typeOfMap1 <> Default Then
        _cveOutputArrayRelease($oArrMap1)
        If $bMap1Create Then
            Call("_cve" & $typeOfMap1 & "Release", $map1)
        EndIf
    EndIf

    If $bPIsArray Then
        Call("_VectorOf" & $typeOfP & "Release", $vectorP)
    EndIf

    If $typeOfP <> Default Then
        _cveInputArrayRelease($iArrP)
        If $bPCreate Then
            Call("_cve" & $typeOfP & "Release", $P)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveInputArrayRelease($iArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $R)
        EndIf
    EndIf

    If $bDIsArray Then
        Call("_VectorOf" & $typeOfD & "Release", $vectorD)
    EndIf

    If $typeOfD <> Default Then
        _cveInputArrayRelease($iArrD)
        If $bDCreate Then
            Call("_cve" & $typeOfD & "Release", $D)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeInitUndistorRectifyMapTyped

Func _cveFisheyeInitUndistorRectifyMapMat($K, $D, $R, $P, $size, $m1Type, $map1, $map2)
    ; cveFisheyeInitUndistorRectifyMap using cv::Mat instead of _*Array
    _cveFisheyeInitUndistorRectifyMapTyped("Mat", $K, "Mat", $D, "Mat", $R, "Mat", $P, $size, $m1Type, "Mat", $map1, "Mat", $map2)
EndFunc   ;==>_cveFisheyeInitUndistorRectifyMapMat

Func _cveFisheyeUndistorImage($distorted, $undistored, $K, $D, $Knew, $newSize)
    ; CVAPI(void) cveFisheyeUndistorImage(cv::_InputArray* distorted, cv::_OutputArray* undistored, cv::_InputArray* K, cv::_InputArray* D, cv::_InputArray* Knew, CvSize* newSize);

    Local $sDistortedDllType
    If IsDllStruct($distorted) Then
        $sDistortedDllType = "struct*"
    Else
        $sDistortedDllType = "ptr"
    EndIf

    Local $sUndistoredDllType
    If IsDllStruct($undistored) Then
        $sUndistoredDllType = "struct*"
    Else
        $sUndistoredDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sDDllType
    If IsDllStruct($D) Then
        $sDDllType = "struct*"
    Else
        $sDDllType = "ptr"
    EndIf

    Local $sKnewDllType
    If IsDllStruct($Knew) Then
        $sKnewDllType = "struct*"
    Else
        $sKnewDllType = "ptr"
    EndIf

    Local $sNewSizeDllType
    If IsDllStruct($newSize) Then
        $sNewSizeDllType = "struct*"
    Else
        $sNewSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeUndistorImage", $sDistortedDllType, $distorted, $sUndistoredDllType, $undistored, $sKDllType, $K, $sDDllType, $D, $sKnewDllType, $Knew, $sNewSizeDllType, $newSize), "cveFisheyeUndistorImage", @error)
EndFunc   ;==>_cveFisheyeUndistorImage

Func _cveFisheyeUndistorImageTyped($typeOfDistorted, $distorted, $typeOfUndistored, $undistored, $typeOfK, $K, $typeOfD, $D, $typeOfKnew, $Knew, $newSize)

    Local $iArrDistorted, $vectorDistorted, $iArrDistortedSize
    Local $bDistortedIsArray = IsArray($distorted)
    Local $bDistortedCreate = IsDllStruct($distorted) And $typeOfDistorted == "Scalar"

    If $typeOfDistorted == Default Then
        $iArrDistorted = $distorted
    ElseIf $bDistortedIsArray Then
        $vectorDistorted = Call("_VectorOf" & $typeOfDistorted & "Create")

        $iArrDistortedSize = UBound($distorted)
        For $i = 0 To $iArrDistortedSize - 1
            Call("_VectorOf" & $typeOfDistorted & "Push", $vectorDistorted, $distorted[$i])
        Next

        $iArrDistorted = Call("_cveInputArrayFromVectorOf" & $typeOfDistorted, $vectorDistorted)
    Else
        If $bDistortedCreate Then
            $distorted = Call("_cve" & $typeOfDistorted & "Create", $distorted)
        EndIf
        $iArrDistorted = Call("_cveInputArrayFrom" & $typeOfDistorted, $distorted)
    EndIf

    Local $oArrUndistored, $vectorUndistored, $iArrUndistoredSize
    Local $bUndistoredIsArray = IsArray($undistored)
    Local $bUndistoredCreate = IsDllStruct($undistored) And $typeOfUndistored == "Scalar"

    If $typeOfUndistored == Default Then
        $oArrUndistored = $undistored
    ElseIf $bUndistoredIsArray Then
        $vectorUndistored = Call("_VectorOf" & $typeOfUndistored & "Create")

        $iArrUndistoredSize = UBound($undistored)
        For $i = 0 To $iArrUndistoredSize - 1
            Call("_VectorOf" & $typeOfUndistored & "Push", $vectorUndistored, $undistored[$i])
        Next

        $oArrUndistored = Call("_cveOutputArrayFromVectorOf" & $typeOfUndistored, $vectorUndistored)
    Else
        If $bUndistoredCreate Then
            $undistored = Call("_cve" & $typeOfUndistored & "Create", $undistored)
        EndIf
        $oArrUndistored = Call("_cveOutputArrayFrom" & $typeOfUndistored, $undistored)
    EndIf

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $iArrD, $vectorD, $iArrDSize
    Local $bDIsArray = IsArray($D)
    Local $bDCreate = IsDllStruct($D) And $typeOfD == "Scalar"

    If $typeOfD == Default Then
        $iArrD = $D
    ElseIf $bDIsArray Then
        $vectorD = Call("_VectorOf" & $typeOfD & "Create")

        $iArrDSize = UBound($D)
        For $i = 0 To $iArrDSize - 1
            Call("_VectorOf" & $typeOfD & "Push", $vectorD, $D[$i])
        Next

        $iArrD = Call("_cveInputArrayFromVectorOf" & $typeOfD, $vectorD)
    Else
        If $bDCreate Then
            $D = Call("_cve" & $typeOfD & "Create", $D)
        EndIf
        $iArrD = Call("_cveInputArrayFrom" & $typeOfD, $D)
    EndIf

    Local $iArrKnew, $vectorKnew, $iArrKnewSize
    Local $bKnewIsArray = IsArray($Knew)
    Local $bKnewCreate = IsDllStruct($Knew) And $typeOfKnew == "Scalar"

    If $typeOfKnew == Default Then
        $iArrKnew = $Knew
    ElseIf $bKnewIsArray Then
        $vectorKnew = Call("_VectorOf" & $typeOfKnew & "Create")

        $iArrKnewSize = UBound($Knew)
        For $i = 0 To $iArrKnewSize - 1
            Call("_VectorOf" & $typeOfKnew & "Push", $vectorKnew, $Knew[$i])
        Next

        $iArrKnew = Call("_cveInputArrayFromVectorOf" & $typeOfKnew, $vectorKnew)
    Else
        If $bKnewCreate Then
            $Knew = Call("_cve" & $typeOfKnew & "Create", $Knew)
        EndIf
        $iArrKnew = Call("_cveInputArrayFrom" & $typeOfKnew, $Knew)
    EndIf

    _cveFisheyeUndistorImage($iArrDistorted, $oArrUndistored, $iArrK, $iArrD, $iArrKnew, $newSize)

    If $bKnewIsArray Then
        Call("_VectorOf" & $typeOfKnew & "Release", $vectorKnew)
    EndIf

    If $typeOfKnew <> Default Then
        _cveInputArrayRelease($iArrKnew)
        If $bKnewCreate Then
            Call("_cve" & $typeOfKnew & "Release", $Knew)
        EndIf
    EndIf

    If $bDIsArray Then
        Call("_VectorOf" & $typeOfD & "Release", $vectorD)
    EndIf

    If $typeOfD <> Default Then
        _cveInputArrayRelease($iArrD)
        If $bDCreate Then
            Call("_cve" & $typeOfD & "Release", $D)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bUndistoredIsArray Then
        Call("_VectorOf" & $typeOfUndistored & "Release", $vectorUndistored)
    EndIf

    If $typeOfUndistored <> Default Then
        _cveOutputArrayRelease($oArrUndistored)
        If $bUndistoredCreate Then
            Call("_cve" & $typeOfUndistored & "Release", $undistored)
        EndIf
    EndIf

    If $bDistortedIsArray Then
        Call("_VectorOf" & $typeOfDistorted & "Release", $vectorDistorted)
    EndIf

    If $typeOfDistorted <> Default Then
        _cveInputArrayRelease($iArrDistorted)
        If $bDistortedCreate Then
            Call("_cve" & $typeOfDistorted & "Release", $distorted)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeUndistorImageTyped

Func _cveFisheyeUndistorImageMat($distorted, $undistored, $K, $D, $Knew, $newSize)
    ; cveFisheyeUndistorImage using cv::Mat instead of _*Array
    _cveFisheyeUndistorImageTyped("Mat", $distorted, "Mat", $undistored, "Mat", $K, "Mat", $D, "Mat", $Knew, $newSize)
EndFunc   ;==>_cveFisheyeUndistorImageMat

Func _cveFisheyeEstimateNewCameraMatrixForUndistorRectify($K, $D, $imageSize, $R, $P, $balance, $newSize, $fovScale)
    ; CVAPI(void) cveFisheyeEstimateNewCameraMatrixForUndistorRectify(cv::_InputArray* K, cv::_InputArray* D, CvSize* imageSize, cv::_InputArray* R, cv::_OutputArray* P, double balance, CvSize* newSize, double fovScale);

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sDDllType
    If IsDllStruct($D) Then
        $sDDllType = "struct*"
    Else
        $sDDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($R) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($P) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    Local $sNewSizeDllType
    If IsDllStruct($newSize) Then
        $sNewSizeDllType = "struct*"
    Else
        $sNewSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeEstimateNewCameraMatrixForUndistorRectify", $sKDllType, $K, $sDDllType, $D, $sImageSizeDllType, $imageSize, $sRDllType, $R, $sPDllType, $P, "double", $balance, $sNewSizeDllType, $newSize, "double", $fovScale), "cveFisheyeEstimateNewCameraMatrixForUndistorRectify", @error)
EndFunc   ;==>_cveFisheyeEstimateNewCameraMatrixForUndistorRectify

Func _cveFisheyeEstimateNewCameraMatrixForUndistorRectifyTyped($typeOfK, $K, $typeOfD, $D, $imageSize, $typeOfR, $R, $typeOfP, $P, $balance, $newSize, $fovScale)

    Local $iArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $iArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $iArrK = Call("_cveInputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $iArrK = Call("_cveInputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $iArrD, $vectorD, $iArrDSize
    Local $bDIsArray = IsArray($D)
    Local $bDCreate = IsDllStruct($D) And $typeOfD == "Scalar"

    If $typeOfD == Default Then
        $iArrD = $D
    ElseIf $bDIsArray Then
        $vectorD = Call("_VectorOf" & $typeOfD & "Create")

        $iArrDSize = UBound($D)
        For $i = 0 To $iArrDSize - 1
            Call("_VectorOf" & $typeOfD & "Push", $vectorD, $D[$i])
        Next

        $iArrD = Call("_cveInputArrayFromVectorOf" & $typeOfD, $vectorD)
    Else
        If $bDCreate Then
            $D = Call("_cve" & $typeOfD & "Create", $D)
        EndIf
        $iArrD = Call("_cveInputArrayFrom" & $typeOfD, $D)
    EndIf

    Local $iArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($R)
    Local $bRCreate = IsDllStruct($R) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $iArrR = $R
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($R)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $R[$i])
        Next

        $iArrR = Call("_cveInputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $R = Call("_cve" & $typeOfR & "Create", $R)
        EndIf
        $iArrR = Call("_cveInputArrayFrom" & $typeOfR, $R)
    EndIf

    Local $oArrP, $vectorP, $iArrPSize
    Local $bPIsArray = IsArray($P)
    Local $bPCreate = IsDllStruct($P) And $typeOfP == "Scalar"

    If $typeOfP == Default Then
        $oArrP = $P
    ElseIf $bPIsArray Then
        $vectorP = Call("_VectorOf" & $typeOfP & "Create")

        $iArrPSize = UBound($P)
        For $i = 0 To $iArrPSize - 1
            Call("_VectorOf" & $typeOfP & "Push", $vectorP, $P[$i])
        Next

        $oArrP = Call("_cveOutputArrayFromVectorOf" & $typeOfP, $vectorP)
    Else
        If $bPCreate Then
            $P = Call("_cve" & $typeOfP & "Create", $P)
        EndIf
        $oArrP = Call("_cveOutputArrayFrom" & $typeOfP, $P)
    EndIf

    _cveFisheyeEstimateNewCameraMatrixForUndistorRectify($iArrK, $iArrD, $imageSize, $iArrR, $oArrP, $balance, $newSize, $fovScale)

    If $bPIsArray Then
        Call("_VectorOf" & $typeOfP & "Release", $vectorP)
    EndIf

    If $typeOfP <> Default Then
        _cveOutputArrayRelease($oArrP)
        If $bPCreate Then
            Call("_cve" & $typeOfP & "Release", $P)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveInputArrayRelease($iArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $R)
        EndIf
    EndIf

    If $bDIsArray Then
        Call("_VectorOf" & $typeOfD & "Release", $vectorD)
    EndIf

    If $typeOfD <> Default Then
        _cveInputArrayRelease($iArrD)
        If $bDCreate Then
            Call("_cve" & $typeOfD & "Release", $D)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputArrayRelease($iArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeEstimateNewCameraMatrixForUndistorRectifyTyped

Func _cveFisheyeEstimateNewCameraMatrixForUndistorRectifyMat($K, $D, $imageSize, $R, $P, $balance, $newSize, $fovScale)
    ; cveFisheyeEstimateNewCameraMatrixForUndistorRectify using cv::Mat instead of _*Array
    _cveFisheyeEstimateNewCameraMatrixForUndistorRectifyTyped("Mat", $K, "Mat", $D, $imageSize, "Mat", $R, "Mat", $P, $balance, $newSize, $fovScale)
EndFunc   ;==>_cveFisheyeEstimateNewCameraMatrixForUndistorRectifyMat

Func _cveFisheyeStereoRectify($K1, $D1, $K2, $D2, $imageSize, $R, $tvec, $R1, $R2, $P1, $P2, $Q, $flags, $newImageSize, $balance, $fovScale)
    ; CVAPI(void) cveFisheyeStereoRectify(cv::_InputArray* K1, cv::_InputArray* D1, cv::_InputArray* K2, cv::_InputArray* D2, CvSize* imageSize, cv::_InputArray* R, cv::_InputArray* tvec, cv::_OutputArray* R1, cv::_OutputArray* R2, cv::_OutputArray* P1, cv::_OutputArray* P2, cv::_OutputArray* Q, int flags, CvSize* newImageSize, double balance, double fovScale);

    Local $sK1DllType
    If IsDllStruct($K1) Then
        $sK1DllType = "struct*"
    Else
        $sK1DllType = "ptr"
    EndIf

    Local $sD1DllType
    If IsDllStruct($D1) Then
        $sD1DllType = "struct*"
    Else
        $sD1DllType = "ptr"
    EndIf

    Local $sK2DllType
    If IsDllStruct($K2) Then
        $sK2DllType = "struct*"
    Else
        $sK2DllType = "ptr"
    EndIf

    Local $sD2DllType
    If IsDllStruct($D2) Then
        $sD2DllType = "struct*"
    Else
        $sD2DllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($R) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sTvecDllType
    If IsDllStruct($tvec) Then
        $sTvecDllType = "struct*"
    Else
        $sTvecDllType = "ptr"
    EndIf

    Local $sR1DllType
    If IsDllStruct($R1) Then
        $sR1DllType = "struct*"
    Else
        $sR1DllType = "ptr"
    EndIf

    Local $sR2DllType
    If IsDllStruct($R2) Then
        $sR2DllType = "struct*"
    Else
        $sR2DllType = "ptr"
    EndIf

    Local $sP1DllType
    If IsDllStruct($P1) Then
        $sP1DllType = "struct*"
    Else
        $sP1DllType = "ptr"
    EndIf

    Local $sP2DllType
    If IsDllStruct($P2) Then
        $sP2DllType = "struct*"
    Else
        $sP2DllType = "ptr"
    EndIf

    Local $sQDllType
    If IsDllStruct($Q) Then
        $sQDllType = "struct*"
    Else
        $sQDllType = "ptr"
    EndIf

    Local $sNewImageSizeDllType
    If IsDllStruct($newImageSize) Then
        $sNewImageSizeDllType = "struct*"
    Else
        $sNewImageSizeDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeStereoRectify", $sK1DllType, $K1, $sD1DllType, $D1, $sK2DllType, $K2, $sD2DllType, $D2, $sImageSizeDllType, $imageSize, $sRDllType, $R, $sTvecDllType, $tvec, $sR1DllType, $R1, $sR2DllType, $R2, $sP1DllType, $P1, $sP2DllType, $P2, $sQDllType, $Q, "int", $flags, $sNewImageSizeDllType, $newImageSize, "double", $balance, "double", $fovScale), "cveFisheyeStereoRectify", @error)
EndFunc   ;==>_cveFisheyeStereoRectify

Func _cveFisheyeStereoRectifyTyped($typeOfK1, $K1, $typeOfD1, $D1, $typeOfK2, $K2, $typeOfD2, $D2, $imageSize, $typeOfR, $R, $typeOfTvec, $tvec, $typeOfR1, $R1, $typeOfR2, $R2, $typeOfP1, $P1, $typeOfP2, $P2, $typeOfQ, $Q, $flags, $newImageSize, $balance, $fovScale)

    Local $iArrK1, $vectorK1, $iArrK1Size
    Local $bK1IsArray = IsArray($K1)
    Local $bK1Create = IsDllStruct($K1) And $typeOfK1 == "Scalar"

    If $typeOfK1 == Default Then
        $iArrK1 = $K1
    ElseIf $bK1IsArray Then
        $vectorK1 = Call("_VectorOf" & $typeOfK1 & "Create")

        $iArrK1Size = UBound($K1)
        For $i = 0 To $iArrK1Size - 1
            Call("_VectorOf" & $typeOfK1 & "Push", $vectorK1, $K1[$i])
        Next

        $iArrK1 = Call("_cveInputArrayFromVectorOf" & $typeOfK1, $vectorK1)
    Else
        If $bK1Create Then
            $K1 = Call("_cve" & $typeOfK1 & "Create", $K1)
        EndIf
        $iArrK1 = Call("_cveInputArrayFrom" & $typeOfK1, $K1)
    EndIf

    Local $iArrD1, $vectorD1, $iArrD1Size
    Local $bD1IsArray = IsArray($D1)
    Local $bD1Create = IsDllStruct($D1) And $typeOfD1 == "Scalar"

    If $typeOfD1 == Default Then
        $iArrD1 = $D1
    ElseIf $bD1IsArray Then
        $vectorD1 = Call("_VectorOf" & $typeOfD1 & "Create")

        $iArrD1Size = UBound($D1)
        For $i = 0 To $iArrD1Size - 1
            Call("_VectorOf" & $typeOfD1 & "Push", $vectorD1, $D1[$i])
        Next

        $iArrD1 = Call("_cveInputArrayFromVectorOf" & $typeOfD1, $vectorD1)
    Else
        If $bD1Create Then
            $D1 = Call("_cve" & $typeOfD1 & "Create", $D1)
        EndIf
        $iArrD1 = Call("_cveInputArrayFrom" & $typeOfD1, $D1)
    EndIf

    Local $iArrK2, $vectorK2, $iArrK2Size
    Local $bK2IsArray = IsArray($K2)
    Local $bK2Create = IsDllStruct($K2) And $typeOfK2 == "Scalar"

    If $typeOfK2 == Default Then
        $iArrK2 = $K2
    ElseIf $bK2IsArray Then
        $vectorK2 = Call("_VectorOf" & $typeOfK2 & "Create")

        $iArrK2Size = UBound($K2)
        For $i = 0 To $iArrK2Size - 1
            Call("_VectorOf" & $typeOfK2 & "Push", $vectorK2, $K2[$i])
        Next

        $iArrK2 = Call("_cveInputArrayFromVectorOf" & $typeOfK2, $vectorK2)
    Else
        If $bK2Create Then
            $K2 = Call("_cve" & $typeOfK2 & "Create", $K2)
        EndIf
        $iArrK2 = Call("_cveInputArrayFrom" & $typeOfK2, $K2)
    EndIf

    Local $iArrD2, $vectorD2, $iArrD2Size
    Local $bD2IsArray = IsArray($D2)
    Local $bD2Create = IsDllStruct($D2) And $typeOfD2 == "Scalar"

    If $typeOfD2 == Default Then
        $iArrD2 = $D2
    ElseIf $bD2IsArray Then
        $vectorD2 = Call("_VectorOf" & $typeOfD2 & "Create")

        $iArrD2Size = UBound($D2)
        For $i = 0 To $iArrD2Size - 1
            Call("_VectorOf" & $typeOfD2 & "Push", $vectorD2, $D2[$i])
        Next

        $iArrD2 = Call("_cveInputArrayFromVectorOf" & $typeOfD2, $vectorD2)
    Else
        If $bD2Create Then
            $D2 = Call("_cve" & $typeOfD2 & "Create", $D2)
        EndIf
        $iArrD2 = Call("_cveInputArrayFrom" & $typeOfD2, $D2)
    EndIf

    Local $iArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($R)
    Local $bRCreate = IsDllStruct($R) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $iArrR = $R
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($R)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $R[$i])
        Next

        $iArrR = Call("_cveInputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $R = Call("_cve" & $typeOfR & "Create", $R)
        EndIf
        $iArrR = Call("_cveInputArrayFrom" & $typeOfR, $R)
    EndIf

    Local $iArrTvec, $vectorTvec, $iArrTvecSize
    Local $bTvecIsArray = IsArray($tvec)
    Local $bTvecCreate = IsDllStruct($tvec) And $typeOfTvec == "Scalar"

    If $typeOfTvec == Default Then
        $iArrTvec = $tvec
    ElseIf $bTvecIsArray Then
        $vectorTvec = Call("_VectorOf" & $typeOfTvec & "Create")

        $iArrTvecSize = UBound($tvec)
        For $i = 0 To $iArrTvecSize - 1
            Call("_VectorOf" & $typeOfTvec & "Push", $vectorTvec, $tvec[$i])
        Next

        $iArrTvec = Call("_cveInputArrayFromVectorOf" & $typeOfTvec, $vectorTvec)
    Else
        If $bTvecCreate Then
            $tvec = Call("_cve" & $typeOfTvec & "Create", $tvec)
        EndIf
        $iArrTvec = Call("_cveInputArrayFrom" & $typeOfTvec, $tvec)
    EndIf

    Local $oArrR1, $vectorR1, $iArrR1Size
    Local $bR1IsArray = IsArray($R1)
    Local $bR1Create = IsDllStruct($R1) And $typeOfR1 == "Scalar"

    If $typeOfR1 == Default Then
        $oArrR1 = $R1
    ElseIf $bR1IsArray Then
        $vectorR1 = Call("_VectorOf" & $typeOfR1 & "Create")

        $iArrR1Size = UBound($R1)
        For $i = 0 To $iArrR1Size - 1
            Call("_VectorOf" & $typeOfR1 & "Push", $vectorR1, $R1[$i])
        Next

        $oArrR1 = Call("_cveOutputArrayFromVectorOf" & $typeOfR1, $vectorR1)
    Else
        If $bR1Create Then
            $R1 = Call("_cve" & $typeOfR1 & "Create", $R1)
        EndIf
        $oArrR1 = Call("_cveOutputArrayFrom" & $typeOfR1, $R1)
    EndIf

    Local $oArrR2, $vectorR2, $iArrR2Size
    Local $bR2IsArray = IsArray($R2)
    Local $bR2Create = IsDllStruct($R2) And $typeOfR2 == "Scalar"

    If $typeOfR2 == Default Then
        $oArrR2 = $R2
    ElseIf $bR2IsArray Then
        $vectorR2 = Call("_VectorOf" & $typeOfR2 & "Create")

        $iArrR2Size = UBound($R2)
        For $i = 0 To $iArrR2Size - 1
            Call("_VectorOf" & $typeOfR2 & "Push", $vectorR2, $R2[$i])
        Next

        $oArrR2 = Call("_cveOutputArrayFromVectorOf" & $typeOfR2, $vectorR2)
    Else
        If $bR2Create Then
            $R2 = Call("_cve" & $typeOfR2 & "Create", $R2)
        EndIf
        $oArrR2 = Call("_cveOutputArrayFrom" & $typeOfR2, $R2)
    EndIf

    Local $oArrP1, $vectorP1, $iArrP1Size
    Local $bP1IsArray = IsArray($P1)
    Local $bP1Create = IsDllStruct($P1) And $typeOfP1 == "Scalar"

    If $typeOfP1 == Default Then
        $oArrP1 = $P1
    ElseIf $bP1IsArray Then
        $vectorP1 = Call("_VectorOf" & $typeOfP1 & "Create")

        $iArrP1Size = UBound($P1)
        For $i = 0 To $iArrP1Size - 1
            Call("_VectorOf" & $typeOfP1 & "Push", $vectorP1, $P1[$i])
        Next

        $oArrP1 = Call("_cveOutputArrayFromVectorOf" & $typeOfP1, $vectorP1)
    Else
        If $bP1Create Then
            $P1 = Call("_cve" & $typeOfP1 & "Create", $P1)
        EndIf
        $oArrP1 = Call("_cveOutputArrayFrom" & $typeOfP1, $P1)
    EndIf

    Local $oArrP2, $vectorP2, $iArrP2Size
    Local $bP2IsArray = IsArray($P2)
    Local $bP2Create = IsDllStruct($P2) And $typeOfP2 == "Scalar"

    If $typeOfP2 == Default Then
        $oArrP2 = $P2
    ElseIf $bP2IsArray Then
        $vectorP2 = Call("_VectorOf" & $typeOfP2 & "Create")

        $iArrP2Size = UBound($P2)
        For $i = 0 To $iArrP2Size - 1
            Call("_VectorOf" & $typeOfP2 & "Push", $vectorP2, $P2[$i])
        Next

        $oArrP2 = Call("_cveOutputArrayFromVectorOf" & $typeOfP2, $vectorP2)
    Else
        If $bP2Create Then
            $P2 = Call("_cve" & $typeOfP2 & "Create", $P2)
        EndIf
        $oArrP2 = Call("_cveOutputArrayFrom" & $typeOfP2, $P2)
    EndIf

    Local $oArrQ, $vectorQ, $iArrQSize
    Local $bQIsArray = IsArray($Q)
    Local $bQCreate = IsDllStruct($Q) And $typeOfQ == "Scalar"

    If $typeOfQ == Default Then
        $oArrQ = $Q
    ElseIf $bQIsArray Then
        $vectorQ = Call("_VectorOf" & $typeOfQ & "Create")

        $iArrQSize = UBound($Q)
        For $i = 0 To $iArrQSize - 1
            Call("_VectorOf" & $typeOfQ & "Push", $vectorQ, $Q[$i])
        Next

        $oArrQ = Call("_cveOutputArrayFromVectorOf" & $typeOfQ, $vectorQ)
    Else
        If $bQCreate Then
            $Q = Call("_cve" & $typeOfQ & "Create", $Q)
        EndIf
        $oArrQ = Call("_cveOutputArrayFrom" & $typeOfQ, $Q)
    EndIf

    _cveFisheyeStereoRectify($iArrK1, $iArrD1, $iArrK2, $iArrD2, $imageSize, $iArrR, $iArrTvec, $oArrR1, $oArrR2, $oArrP1, $oArrP2, $oArrQ, $flags, $newImageSize, $balance, $fovScale)

    If $bQIsArray Then
        Call("_VectorOf" & $typeOfQ & "Release", $vectorQ)
    EndIf

    If $typeOfQ <> Default Then
        _cveOutputArrayRelease($oArrQ)
        If $bQCreate Then
            Call("_cve" & $typeOfQ & "Release", $Q)
        EndIf
    EndIf

    If $bP2IsArray Then
        Call("_VectorOf" & $typeOfP2 & "Release", $vectorP2)
    EndIf

    If $typeOfP2 <> Default Then
        _cveOutputArrayRelease($oArrP2)
        If $bP2Create Then
            Call("_cve" & $typeOfP2 & "Release", $P2)
        EndIf
    EndIf

    If $bP1IsArray Then
        Call("_VectorOf" & $typeOfP1 & "Release", $vectorP1)
    EndIf

    If $typeOfP1 <> Default Then
        _cveOutputArrayRelease($oArrP1)
        If $bP1Create Then
            Call("_cve" & $typeOfP1 & "Release", $P1)
        EndIf
    EndIf

    If $bR2IsArray Then
        Call("_VectorOf" & $typeOfR2 & "Release", $vectorR2)
    EndIf

    If $typeOfR2 <> Default Then
        _cveOutputArrayRelease($oArrR2)
        If $bR2Create Then
            Call("_cve" & $typeOfR2 & "Release", $R2)
        EndIf
    EndIf

    If $bR1IsArray Then
        Call("_VectorOf" & $typeOfR1 & "Release", $vectorR1)
    EndIf

    If $typeOfR1 <> Default Then
        _cveOutputArrayRelease($oArrR1)
        If $bR1Create Then
            Call("_cve" & $typeOfR1 & "Release", $R1)
        EndIf
    EndIf

    If $bTvecIsArray Then
        Call("_VectorOf" & $typeOfTvec & "Release", $vectorTvec)
    EndIf

    If $typeOfTvec <> Default Then
        _cveInputArrayRelease($iArrTvec)
        If $bTvecCreate Then
            Call("_cve" & $typeOfTvec & "Release", $tvec)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveInputArrayRelease($iArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $R)
        EndIf
    EndIf

    If $bD2IsArray Then
        Call("_VectorOf" & $typeOfD2 & "Release", $vectorD2)
    EndIf

    If $typeOfD2 <> Default Then
        _cveInputArrayRelease($iArrD2)
        If $bD2Create Then
            Call("_cve" & $typeOfD2 & "Release", $D2)
        EndIf
    EndIf

    If $bK2IsArray Then
        Call("_VectorOf" & $typeOfK2 & "Release", $vectorK2)
    EndIf

    If $typeOfK2 <> Default Then
        _cveInputArrayRelease($iArrK2)
        If $bK2Create Then
            Call("_cve" & $typeOfK2 & "Release", $K2)
        EndIf
    EndIf

    If $bD1IsArray Then
        Call("_VectorOf" & $typeOfD1 & "Release", $vectorD1)
    EndIf

    If $typeOfD1 <> Default Then
        _cveInputArrayRelease($iArrD1)
        If $bD1Create Then
            Call("_cve" & $typeOfD1 & "Release", $D1)
        EndIf
    EndIf

    If $bK1IsArray Then
        Call("_VectorOf" & $typeOfK1 & "Release", $vectorK1)
    EndIf

    If $typeOfK1 <> Default Then
        _cveInputArrayRelease($iArrK1)
        If $bK1Create Then
            Call("_cve" & $typeOfK1 & "Release", $K1)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeStereoRectifyTyped

Func _cveFisheyeStereoRectifyMat($K1, $D1, $K2, $D2, $imageSize, $R, $tvec, $R1, $R2, $P1, $P2, $Q, $flags, $newImageSize, $balance, $fovScale)
    ; cveFisheyeStereoRectify using cv::Mat instead of _*Array
    _cveFisheyeStereoRectifyTyped("Mat", $K1, "Mat", $D1, "Mat", $K2, "Mat", $D2, $imageSize, "Mat", $R, "Mat", $tvec, "Mat", $R1, "Mat", $R2, "Mat", $P1, "Mat", $P2, "Mat", $Q, $flags, $newImageSize, $balance, $fovScale)
EndFunc   ;==>_cveFisheyeStereoRectifyMat

Func _cveFisheyeCalibrate($objectPoints, $imagePoints, $imageSize, $K, $D, $rvecs, $tvecs, $flags, $criteria)
    ; CVAPI(void) cveFisheyeCalibrate(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints, CvSize* imageSize, cv::_InputOutputArray* K, cv::_InputOutputArray* D, cv::_OutputArray* rvecs, cv::_OutputArray* tvecs, int flags, CvTermCriteria* criteria);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePointsDllType
    If IsDllStruct($imagePoints) Then
        $sImagePointsDllType = "struct*"
    Else
        $sImagePointsDllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sKDllType
    If IsDllStruct($K) Then
        $sKDllType = "struct*"
    Else
        $sKDllType = "ptr"
    EndIf

    Local $sDDllType
    If IsDllStruct($D) Then
        $sDDllType = "struct*"
    Else
        $sDDllType = "ptr"
    EndIf

    Local $sRvecsDllType
    If IsDllStruct($rvecs) Then
        $sRvecsDllType = "struct*"
    Else
        $sRvecsDllType = "ptr"
    EndIf

    Local $sTvecsDllType
    If IsDllStruct($tvecs) Then
        $sTvecsDllType = "struct*"
    Else
        $sTvecsDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeCalibrate", $sObjectPointsDllType, $objectPoints, $sImagePointsDllType, $imagePoints, $sImageSizeDllType, $imageSize, $sKDllType, $K, $sDDllType, $D, $sRvecsDllType, $rvecs, $sTvecsDllType, $tvecs, "int", $flags, $sCriteriaDllType, $criteria), "cveFisheyeCalibrate", @error)
EndFunc   ;==>_cveFisheyeCalibrate

Func _cveFisheyeCalibrateTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints, $imagePoints, $imageSize, $typeOfK, $K, $typeOfD, $D, $typeOfRvecs, $rvecs, $typeOfTvecs, $tvecs, $flags, $criteria)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints, $vectorImagePoints, $iArrImagePointsSize
    Local $bImagePointsIsArray = IsArray($imagePoints)
    Local $bImagePointsCreate = IsDllStruct($imagePoints) And $typeOfImagePoints == "Scalar"

    If $typeOfImagePoints == Default Then
        $iArrImagePoints = $imagePoints
    ElseIf $bImagePointsIsArray Then
        $vectorImagePoints = Call("_VectorOf" & $typeOfImagePoints & "Create")

        $iArrImagePointsSize = UBound($imagePoints)
        For $i = 0 To $iArrImagePointsSize - 1
            Call("_VectorOf" & $typeOfImagePoints & "Push", $vectorImagePoints, $imagePoints[$i])
        Next

        $iArrImagePoints = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints, $vectorImagePoints)
    Else
        If $bImagePointsCreate Then
            $imagePoints = Call("_cve" & $typeOfImagePoints & "Create", $imagePoints)
        EndIf
        $iArrImagePoints = Call("_cveInputArrayFrom" & $typeOfImagePoints, $imagePoints)
    EndIf

    Local $ioArrK, $vectorK, $iArrKSize
    Local $bKIsArray = IsArray($K)
    Local $bKCreate = IsDllStruct($K) And $typeOfK == "Scalar"

    If $typeOfK == Default Then
        $ioArrK = $K
    ElseIf $bKIsArray Then
        $vectorK = Call("_VectorOf" & $typeOfK & "Create")

        $iArrKSize = UBound($K)
        For $i = 0 To $iArrKSize - 1
            Call("_VectorOf" & $typeOfK & "Push", $vectorK, $K[$i])
        Next

        $ioArrK = Call("_cveInputOutputArrayFromVectorOf" & $typeOfK, $vectorK)
    Else
        If $bKCreate Then
            $K = Call("_cve" & $typeOfK & "Create", $K)
        EndIf
        $ioArrK = Call("_cveInputOutputArrayFrom" & $typeOfK, $K)
    EndIf

    Local $ioArrD, $vectorD, $iArrDSize
    Local $bDIsArray = IsArray($D)
    Local $bDCreate = IsDllStruct($D) And $typeOfD == "Scalar"

    If $typeOfD == Default Then
        $ioArrD = $D
    ElseIf $bDIsArray Then
        $vectorD = Call("_VectorOf" & $typeOfD & "Create")

        $iArrDSize = UBound($D)
        For $i = 0 To $iArrDSize - 1
            Call("_VectorOf" & $typeOfD & "Push", $vectorD, $D[$i])
        Next

        $ioArrD = Call("_cveInputOutputArrayFromVectorOf" & $typeOfD, $vectorD)
    Else
        If $bDCreate Then
            $D = Call("_cve" & $typeOfD & "Create", $D)
        EndIf
        $ioArrD = Call("_cveInputOutputArrayFrom" & $typeOfD, $D)
    EndIf

    Local $oArrRvecs, $vectorRvecs, $iArrRvecsSize
    Local $bRvecsIsArray = IsArray($rvecs)
    Local $bRvecsCreate = IsDllStruct($rvecs) And $typeOfRvecs == "Scalar"

    If $typeOfRvecs == Default Then
        $oArrRvecs = $rvecs
    ElseIf $bRvecsIsArray Then
        $vectorRvecs = Call("_VectorOf" & $typeOfRvecs & "Create")

        $iArrRvecsSize = UBound($rvecs)
        For $i = 0 To $iArrRvecsSize - 1
            Call("_VectorOf" & $typeOfRvecs & "Push", $vectorRvecs, $rvecs[$i])
        Next

        $oArrRvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfRvecs, $vectorRvecs)
    Else
        If $bRvecsCreate Then
            $rvecs = Call("_cve" & $typeOfRvecs & "Create", $rvecs)
        EndIf
        $oArrRvecs = Call("_cveOutputArrayFrom" & $typeOfRvecs, $rvecs)
    EndIf

    Local $oArrTvecs, $vectorTvecs, $iArrTvecsSize
    Local $bTvecsIsArray = IsArray($tvecs)
    Local $bTvecsCreate = IsDllStruct($tvecs) And $typeOfTvecs == "Scalar"

    If $typeOfTvecs == Default Then
        $oArrTvecs = $tvecs
    ElseIf $bTvecsIsArray Then
        $vectorTvecs = Call("_VectorOf" & $typeOfTvecs & "Create")

        $iArrTvecsSize = UBound($tvecs)
        For $i = 0 To $iArrTvecsSize - 1
            Call("_VectorOf" & $typeOfTvecs & "Push", $vectorTvecs, $tvecs[$i])
        Next

        $oArrTvecs = Call("_cveOutputArrayFromVectorOf" & $typeOfTvecs, $vectorTvecs)
    Else
        If $bTvecsCreate Then
            $tvecs = Call("_cve" & $typeOfTvecs & "Create", $tvecs)
        EndIf
        $oArrTvecs = Call("_cveOutputArrayFrom" & $typeOfTvecs, $tvecs)
    EndIf

    _cveFisheyeCalibrate($iArrObjectPoints, $iArrImagePoints, $imageSize, $ioArrK, $ioArrD, $oArrRvecs, $oArrTvecs, $flags, $criteria)

    If $bTvecsIsArray Then
        Call("_VectorOf" & $typeOfTvecs & "Release", $vectorTvecs)
    EndIf

    If $typeOfTvecs <> Default Then
        _cveOutputArrayRelease($oArrTvecs)
        If $bTvecsCreate Then
            Call("_cve" & $typeOfTvecs & "Release", $tvecs)
        EndIf
    EndIf

    If $bRvecsIsArray Then
        Call("_VectorOf" & $typeOfRvecs & "Release", $vectorRvecs)
    EndIf

    If $typeOfRvecs <> Default Then
        _cveOutputArrayRelease($oArrRvecs)
        If $bRvecsCreate Then
            Call("_cve" & $typeOfRvecs & "Release", $rvecs)
        EndIf
    EndIf

    If $bDIsArray Then
        Call("_VectorOf" & $typeOfD & "Release", $vectorD)
    EndIf

    If $typeOfD <> Default Then
        _cveInputOutputArrayRelease($ioArrD)
        If $bDCreate Then
            Call("_cve" & $typeOfD & "Release", $D)
        EndIf
    EndIf

    If $bKIsArray Then
        Call("_VectorOf" & $typeOfK & "Release", $vectorK)
    EndIf

    If $typeOfK <> Default Then
        _cveInputOutputArrayRelease($ioArrK)
        If $bKCreate Then
            Call("_cve" & $typeOfK & "Release", $K)
        EndIf
    EndIf

    If $bImagePointsIsArray Then
        Call("_VectorOf" & $typeOfImagePoints & "Release", $vectorImagePoints)
    EndIf

    If $typeOfImagePoints <> Default Then
        _cveInputArrayRelease($iArrImagePoints)
        If $bImagePointsCreate Then
            Call("_cve" & $typeOfImagePoints & "Release", $imagePoints)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeCalibrateTyped

Func _cveFisheyeCalibrateMat($objectPoints, $imagePoints, $imageSize, $K, $D, $rvecs, $tvecs, $flags, $criteria)
    ; cveFisheyeCalibrate using cv::Mat instead of _*Array
    _cveFisheyeCalibrateTyped("Mat", $objectPoints, "Mat", $imagePoints, $imageSize, "Mat", $K, "Mat", $D, "Mat", $rvecs, "Mat", $tvecs, $flags, $criteria)
EndFunc   ;==>_cveFisheyeCalibrateMat

Func _cveFisheyeStereoCalibrate($objectPoints, $imagePoints1, $imagePoints2, $K1, $D1, $K2, $D2, $imageSize, $R, $T, $flags, $criteria)
    ; CVAPI(void) cveFisheyeStereoCalibrate(cv::_InputArray* objectPoints, cv::_InputArray* imagePoints1, cv::_InputArray* imagePoints2, cv::_InputOutputArray* K1, cv::_InputOutputArray* D1, cv::_InputOutputArray* K2, cv::_InputOutputArray* D2, CvSize* imageSize, cv::_OutputArray* R, cv::_OutputArray* T, int flags, CvTermCriteria* criteria);

    Local $sObjectPointsDllType
    If IsDllStruct($objectPoints) Then
        $sObjectPointsDllType = "struct*"
    Else
        $sObjectPointsDllType = "ptr"
    EndIf

    Local $sImagePoints1DllType
    If IsDllStruct($imagePoints1) Then
        $sImagePoints1DllType = "struct*"
    Else
        $sImagePoints1DllType = "ptr"
    EndIf

    Local $sImagePoints2DllType
    If IsDllStruct($imagePoints2) Then
        $sImagePoints2DllType = "struct*"
    Else
        $sImagePoints2DllType = "ptr"
    EndIf

    Local $sK1DllType
    If IsDllStruct($K1) Then
        $sK1DllType = "struct*"
    Else
        $sK1DllType = "ptr"
    EndIf

    Local $sD1DllType
    If IsDllStruct($D1) Then
        $sD1DllType = "struct*"
    Else
        $sD1DllType = "ptr"
    EndIf

    Local $sK2DllType
    If IsDllStruct($K2) Then
        $sK2DllType = "struct*"
    Else
        $sK2DllType = "ptr"
    EndIf

    Local $sD2DllType
    If IsDllStruct($D2) Then
        $sD2DllType = "struct*"
    Else
        $sD2DllType = "ptr"
    EndIf

    Local $sImageSizeDllType
    If IsDllStruct($imageSize) Then
        $sImageSizeDllType = "struct*"
    Else
        $sImageSizeDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($R) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sTDllType
    If IsDllStruct($T) Then
        $sTDllType = "struct*"
    Else
        $sTDllType = "ptr"
    EndIf

    Local $sCriteriaDllType
    If IsDllStruct($criteria) Then
        $sCriteriaDllType = "struct*"
    Else
        $sCriteriaDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFisheyeStereoCalibrate", $sObjectPointsDllType, $objectPoints, $sImagePoints1DllType, $imagePoints1, $sImagePoints2DllType, $imagePoints2, $sK1DllType, $K1, $sD1DllType, $D1, $sK2DllType, $K2, $sD2DllType, $D2, $sImageSizeDllType, $imageSize, $sRDllType, $R, $sTDllType, $T, "int", $flags, $sCriteriaDllType, $criteria), "cveFisheyeStereoCalibrate", @error)
EndFunc   ;==>_cveFisheyeStereoCalibrate

Func _cveFisheyeStereoCalibrateTyped($typeOfObjectPoints, $objectPoints, $typeOfImagePoints1, $imagePoints1, $typeOfImagePoints2, $imagePoints2, $typeOfK1, $K1, $typeOfD1, $D1, $typeOfK2, $K2, $typeOfD2, $D2, $imageSize, $typeOfR, $R, $typeOfT, $T, $flags, $criteria)

    Local $iArrObjectPoints, $vectorObjectPoints, $iArrObjectPointsSize
    Local $bObjectPointsIsArray = IsArray($objectPoints)
    Local $bObjectPointsCreate = IsDllStruct($objectPoints) And $typeOfObjectPoints == "Scalar"

    If $typeOfObjectPoints == Default Then
        $iArrObjectPoints = $objectPoints
    ElseIf $bObjectPointsIsArray Then
        $vectorObjectPoints = Call("_VectorOf" & $typeOfObjectPoints & "Create")

        $iArrObjectPointsSize = UBound($objectPoints)
        For $i = 0 To $iArrObjectPointsSize - 1
            Call("_VectorOf" & $typeOfObjectPoints & "Push", $vectorObjectPoints, $objectPoints[$i])
        Next

        $iArrObjectPoints = Call("_cveInputArrayFromVectorOf" & $typeOfObjectPoints, $vectorObjectPoints)
    Else
        If $bObjectPointsCreate Then
            $objectPoints = Call("_cve" & $typeOfObjectPoints & "Create", $objectPoints)
        EndIf
        $iArrObjectPoints = Call("_cveInputArrayFrom" & $typeOfObjectPoints, $objectPoints)
    EndIf

    Local $iArrImagePoints1, $vectorImagePoints1, $iArrImagePoints1Size
    Local $bImagePoints1IsArray = IsArray($imagePoints1)
    Local $bImagePoints1Create = IsDllStruct($imagePoints1) And $typeOfImagePoints1 == "Scalar"

    If $typeOfImagePoints1 == Default Then
        $iArrImagePoints1 = $imagePoints1
    ElseIf $bImagePoints1IsArray Then
        $vectorImagePoints1 = Call("_VectorOf" & $typeOfImagePoints1 & "Create")

        $iArrImagePoints1Size = UBound($imagePoints1)
        For $i = 0 To $iArrImagePoints1Size - 1
            Call("_VectorOf" & $typeOfImagePoints1 & "Push", $vectorImagePoints1, $imagePoints1[$i])
        Next

        $iArrImagePoints1 = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints1, $vectorImagePoints1)
    Else
        If $bImagePoints1Create Then
            $imagePoints1 = Call("_cve" & $typeOfImagePoints1 & "Create", $imagePoints1)
        EndIf
        $iArrImagePoints1 = Call("_cveInputArrayFrom" & $typeOfImagePoints1, $imagePoints1)
    EndIf

    Local $iArrImagePoints2, $vectorImagePoints2, $iArrImagePoints2Size
    Local $bImagePoints2IsArray = IsArray($imagePoints2)
    Local $bImagePoints2Create = IsDllStruct($imagePoints2) And $typeOfImagePoints2 == "Scalar"

    If $typeOfImagePoints2 == Default Then
        $iArrImagePoints2 = $imagePoints2
    ElseIf $bImagePoints2IsArray Then
        $vectorImagePoints2 = Call("_VectorOf" & $typeOfImagePoints2 & "Create")

        $iArrImagePoints2Size = UBound($imagePoints2)
        For $i = 0 To $iArrImagePoints2Size - 1
            Call("_VectorOf" & $typeOfImagePoints2 & "Push", $vectorImagePoints2, $imagePoints2[$i])
        Next

        $iArrImagePoints2 = Call("_cveInputArrayFromVectorOf" & $typeOfImagePoints2, $vectorImagePoints2)
    Else
        If $bImagePoints2Create Then
            $imagePoints2 = Call("_cve" & $typeOfImagePoints2 & "Create", $imagePoints2)
        EndIf
        $iArrImagePoints2 = Call("_cveInputArrayFrom" & $typeOfImagePoints2, $imagePoints2)
    EndIf

    Local $ioArrK1, $vectorK1, $iArrK1Size
    Local $bK1IsArray = IsArray($K1)
    Local $bK1Create = IsDllStruct($K1) And $typeOfK1 == "Scalar"

    If $typeOfK1 == Default Then
        $ioArrK1 = $K1
    ElseIf $bK1IsArray Then
        $vectorK1 = Call("_VectorOf" & $typeOfK1 & "Create")

        $iArrK1Size = UBound($K1)
        For $i = 0 To $iArrK1Size - 1
            Call("_VectorOf" & $typeOfK1 & "Push", $vectorK1, $K1[$i])
        Next

        $ioArrK1 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfK1, $vectorK1)
    Else
        If $bK1Create Then
            $K1 = Call("_cve" & $typeOfK1 & "Create", $K1)
        EndIf
        $ioArrK1 = Call("_cveInputOutputArrayFrom" & $typeOfK1, $K1)
    EndIf

    Local $ioArrD1, $vectorD1, $iArrD1Size
    Local $bD1IsArray = IsArray($D1)
    Local $bD1Create = IsDllStruct($D1) And $typeOfD1 == "Scalar"

    If $typeOfD1 == Default Then
        $ioArrD1 = $D1
    ElseIf $bD1IsArray Then
        $vectorD1 = Call("_VectorOf" & $typeOfD1 & "Create")

        $iArrD1Size = UBound($D1)
        For $i = 0 To $iArrD1Size - 1
            Call("_VectorOf" & $typeOfD1 & "Push", $vectorD1, $D1[$i])
        Next

        $ioArrD1 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfD1, $vectorD1)
    Else
        If $bD1Create Then
            $D1 = Call("_cve" & $typeOfD1 & "Create", $D1)
        EndIf
        $ioArrD1 = Call("_cveInputOutputArrayFrom" & $typeOfD1, $D1)
    EndIf

    Local $ioArrK2, $vectorK2, $iArrK2Size
    Local $bK2IsArray = IsArray($K2)
    Local $bK2Create = IsDllStruct($K2) And $typeOfK2 == "Scalar"

    If $typeOfK2 == Default Then
        $ioArrK2 = $K2
    ElseIf $bK2IsArray Then
        $vectorK2 = Call("_VectorOf" & $typeOfK2 & "Create")

        $iArrK2Size = UBound($K2)
        For $i = 0 To $iArrK2Size - 1
            Call("_VectorOf" & $typeOfK2 & "Push", $vectorK2, $K2[$i])
        Next

        $ioArrK2 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfK2, $vectorK2)
    Else
        If $bK2Create Then
            $K2 = Call("_cve" & $typeOfK2 & "Create", $K2)
        EndIf
        $ioArrK2 = Call("_cveInputOutputArrayFrom" & $typeOfK2, $K2)
    EndIf

    Local $ioArrD2, $vectorD2, $iArrD2Size
    Local $bD2IsArray = IsArray($D2)
    Local $bD2Create = IsDllStruct($D2) And $typeOfD2 == "Scalar"

    If $typeOfD2 == Default Then
        $ioArrD2 = $D2
    ElseIf $bD2IsArray Then
        $vectorD2 = Call("_VectorOf" & $typeOfD2 & "Create")

        $iArrD2Size = UBound($D2)
        For $i = 0 To $iArrD2Size - 1
            Call("_VectorOf" & $typeOfD2 & "Push", $vectorD2, $D2[$i])
        Next

        $ioArrD2 = Call("_cveInputOutputArrayFromVectorOf" & $typeOfD2, $vectorD2)
    Else
        If $bD2Create Then
            $D2 = Call("_cve" & $typeOfD2 & "Create", $D2)
        EndIf
        $ioArrD2 = Call("_cveInputOutputArrayFrom" & $typeOfD2, $D2)
    EndIf

    Local $oArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($R)
    Local $bRCreate = IsDllStruct($R) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $oArrR = $R
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($R)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $R[$i])
        Next

        $oArrR = Call("_cveOutputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $R = Call("_cve" & $typeOfR & "Create", $R)
        EndIf
        $oArrR = Call("_cveOutputArrayFrom" & $typeOfR, $R)
    EndIf

    Local $oArrT, $vectorT, $iArrTSize
    Local $bTIsArray = IsArray($T)
    Local $bTCreate = IsDllStruct($T) And $typeOfT == "Scalar"

    If $typeOfT == Default Then
        $oArrT = $T
    ElseIf $bTIsArray Then
        $vectorT = Call("_VectorOf" & $typeOfT & "Create")

        $iArrTSize = UBound($T)
        For $i = 0 To $iArrTSize - 1
            Call("_VectorOf" & $typeOfT & "Push", $vectorT, $T[$i])
        Next

        $oArrT = Call("_cveOutputArrayFromVectorOf" & $typeOfT, $vectorT)
    Else
        If $bTCreate Then
            $T = Call("_cve" & $typeOfT & "Create", $T)
        EndIf
        $oArrT = Call("_cveOutputArrayFrom" & $typeOfT, $T)
    EndIf

    _cveFisheyeStereoCalibrate($iArrObjectPoints, $iArrImagePoints1, $iArrImagePoints2, $ioArrK1, $ioArrD1, $ioArrK2, $ioArrD2, $imageSize, $oArrR, $oArrT, $flags, $criteria)

    If $bTIsArray Then
        Call("_VectorOf" & $typeOfT & "Release", $vectorT)
    EndIf

    If $typeOfT <> Default Then
        _cveOutputArrayRelease($oArrT)
        If $bTCreate Then
            Call("_cve" & $typeOfT & "Release", $T)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveOutputArrayRelease($oArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $R)
        EndIf
    EndIf

    If $bD2IsArray Then
        Call("_VectorOf" & $typeOfD2 & "Release", $vectorD2)
    EndIf

    If $typeOfD2 <> Default Then
        _cveInputOutputArrayRelease($ioArrD2)
        If $bD2Create Then
            Call("_cve" & $typeOfD2 & "Release", $D2)
        EndIf
    EndIf

    If $bK2IsArray Then
        Call("_VectorOf" & $typeOfK2 & "Release", $vectorK2)
    EndIf

    If $typeOfK2 <> Default Then
        _cveInputOutputArrayRelease($ioArrK2)
        If $bK2Create Then
            Call("_cve" & $typeOfK2 & "Release", $K2)
        EndIf
    EndIf

    If $bD1IsArray Then
        Call("_VectorOf" & $typeOfD1 & "Release", $vectorD1)
    EndIf

    If $typeOfD1 <> Default Then
        _cveInputOutputArrayRelease($ioArrD1)
        If $bD1Create Then
            Call("_cve" & $typeOfD1 & "Release", $D1)
        EndIf
    EndIf

    If $bK1IsArray Then
        Call("_VectorOf" & $typeOfK1 & "Release", $vectorK1)
    EndIf

    If $typeOfK1 <> Default Then
        _cveInputOutputArrayRelease($ioArrK1)
        If $bK1Create Then
            Call("_cve" & $typeOfK1 & "Release", $K1)
        EndIf
    EndIf

    If $bImagePoints2IsArray Then
        Call("_VectorOf" & $typeOfImagePoints2 & "Release", $vectorImagePoints2)
    EndIf

    If $typeOfImagePoints2 <> Default Then
        _cveInputArrayRelease($iArrImagePoints2)
        If $bImagePoints2Create Then
            Call("_cve" & $typeOfImagePoints2 & "Release", $imagePoints2)
        EndIf
    EndIf

    If $bImagePoints1IsArray Then
        Call("_VectorOf" & $typeOfImagePoints1 & "Release", $vectorImagePoints1)
    EndIf

    If $typeOfImagePoints1 <> Default Then
        _cveInputArrayRelease($iArrImagePoints1)
        If $bImagePoints1Create Then
            Call("_cve" & $typeOfImagePoints1 & "Release", $imagePoints1)
        EndIf
    EndIf

    If $bObjectPointsIsArray Then
        Call("_VectorOf" & $typeOfObjectPoints & "Release", $vectorObjectPoints)
    EndIf

    If $typeOfObjectPoints <> Default Then
        _cveInputArrayRelease($iArrObjectPoints)
        If $bObjectPointsCreate Then
            Call("_cve" & $typeOfObjectPoints & "Release", $objectPoints)
        EndIf
    EndIf
EndFunc   ;==>_cveFisheyeStereoCalibrateTyped

Func _cveFisheyeStereoCalibrateMat($objectPoints, $imagePoints1, $imagePoints2, $K1, $D1, $K2, $D2, $imageSize, $R, $T, $flags, $criteria)
    ; cveFisheyeStereoCalibrate using cv::Mat instead of _*Array
    _cveFisheyeStereoCalibrateTyped("Mat", $objectPoints, "Mat", $imagePoints1, "Mat", $imagePoints2, "Mat", $K1, "Mat", $D1, "Mat", $K2, "Mat", $D2, $imageSize, "Mat", $R, "Mat", $T, $flags, $criteria)
EndFunc   ;==>_cveFisheyeStereoCalibrateMat

Func _cveInitUndistortRectifyMap($cameraMatrix, $distCoeffs, $r, $newCameraMatrix, $size, $m1type, $map1, $map2)
    ; CVAPI(void) cveInitUndistortRectifyMap(cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputArray* r, cv::_InputArray* newCameraMatrix, CvSize* size, int m1type, cv::_OutputArray* map1, cv::_OutputArray* map2);

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($r) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sNewCameraMatrixDllType
    If IsDllStruct($newCameraMatrix) Then
        $sNewCameraMatrixDllType = "struct*"
    Else
        $sNewCameraMatrixDllType = "ptr"
    EndIf

    Local $sSizeDllType
    If IsDllStruct($size) Then
        $sSizeDllType = "struct*"
    Else
        $sSizeDllType = "ptr"
    EndIf

    Local $sMap1DllType
    If IsDllStruct($map1) Then
        $sMap1DllType = "struct*"
    Else
        $sMap1DllType = "ptr"
    EndIf

    Local $sMap2DllType
    If IsDllStruct($map2) Then
        $sMap2DllType = "struct*"
    Else
        $sMap2DllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveInitUndistortRectifyMap", $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRDllType, $r, $sNewCameraMatrixDllType, $newCameraMatrix, $sSizeDllType, $size, "int", $m1type, $sMap1DllType, $map1, $sMap2DllType, $map2), "cveInitUndistortRectifyMap", @error)
EndFunc   ;==>_cveInitUndistortRectifyMap

Func _cveInitUndistortRectifyMapTyped($typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfR, $r, $typeOfNewCameraMatrix, $newCameraMatrix, $size, $m1type, $typeOfMap1, $map1, $typeOfMap2, $map2)

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $iArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($r)
    Local $bRCreate = IsDllStruct($r) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $iArrR = $r
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($r)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $r[$i])
        Next

        $iArrR = Call("_cveInputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $r = Call("_cve" & $typeOfR & "Create", $r)
        EndIf
        $iArrR = Call("_cveInputArrayFrom" & $typeOfR, $r)
    EndIf

    Local $iArrNewCameraMatrix, $vectorNewCameraMatrix, $iArrNewCameraMatrixSize
    Local $bNewCameraMatrixIsArray = IsArray($newCameraMatrix)
    Local $bNewCameraMatrixCreate = IsDllStruct($newCameraMatrix) And $typeOfNewCameraMatrix == "Scalar"

    If $typeOfNewCameraMatrix == Default Then
        $iArrNewCameraMatrix = $newCameraMatrix
    ElseIf $bNewCameraMatrixIsArray Then
        $vectorNewCameraMatrix = Call("_VectorOf" & $typeOfNewCameraMatrix & "Create")

        $iArrNewCameraMatrixSize = UBound($newCameraMatrix)
        For $i = 0 To $iArrNewCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfNewCameraMatrix & "Push", $vectorNewCameraMatrix, $newCameraMatrix[$i])
        Next

        $iArrNewCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfNewCameraMatrix, $vectorNewCameraMatrix)
    Else
        If $bNewCameraMatrixCreate Then
            $newCameraMatrix = Call("_cve" & $typeOfNewCameraMatrix & "Create", $newCameraMatrix)
        EndIf
        $iArrNewCameraMatrix = Call("_cveInputArrayFrom" & $typeOfNewCameraMatrix, $newCameraMatrix)
    EndIf

    Local $oArrMap1, $vectorMap1, $iArrMap1Size
    Local $bMap1IsArray = IsArray($map1)
    Local $bMap1Create = IsDllStruct($map1) And $typeOfMap1 == "Scalar"

    If $typeOfMap1 == Default Then
        $oArrMap1 = $map1
    ElseIf $bMap1IsArray Then
        $vectorMap1 = Call("_VectorOf" & $typeOfMap1 & "Create")

        $iArrMap1Size = UBound($map1)
        For $i = 0 To $iArrMap1Size - 1
            Call("_VectorOf" & $typeOfMap1 & "Push", $vectorMap1, $map1[$i])
        Next

        $oArrMap1 = Call("_cveOutputArrayFromVectorOf" & $typeOfMap1, $vectorMap1)
    Else
        If $bMap1Create Then
            $map1 = Call("_cve" & $typeOfMap1 & "Create", $map1)
        EndIf
        $oArrMap1 = Call("_cveOutputArrayFrom" & $typeOfMap1, $map1)
    EndIf

    Local $oArrMap2, $vectorMap2, $iArrMap2Size
    Local $bMap2IsArray = IsArray($map2)
    Local $bMap2Create = IsDllStruct($map2) And $typeOfMap2 == "Scalar"

    If $typeOfMap2 == Default Then
        $oArrMap2 = $map2
    ElseIf $bMap2IsArray Then
        $vectorMap2 = Call("_VectorOf" & $typeOfMap2 & "Create")

        $iArrMap2Size = UBound($map2)
        For $i = 0 To $iArrMap2Size - 1
            Call("_VectorOf" & $typeOfMap2 & "Push", $vectorMap2, $map2[$i])
        Next

        $oArrMap2 = Call("_cveOutputArrayFromVectorOf" & $typeOfMap2, $vectorMap2)
    Else
        If $bMap2Create Then
            $map2 = Call("_cve" & $typeOfMap2 & "Create", $map2)
        EndIf
        $oArrMap2 = Call("_cveOutputArrayFrom" & $typeOfMap2, $map2)
    EndIf

    _cveInitUndistortRectifyMap($iArrCameraMatrix, $iArrDistCoeffs, $iArrR, $iArrNewCameraMatrix, $size, $m1type, $oArrMap1, $oArrMap2)

    If $bMap2IsArray Then
        Call("_VectorOf" & $typeOfMap2 & "Release", $vectorMap2)
    EndIf

    If $typeOfMap2 <> Default Then
        _cveOutputArrayRelease($oArrMap2)
        If $bMap2Create Then
            Call("_cve" & $typeOfMap2 & "Release", $map2)
        EndIf
    EndIf

    If $bMap1IsArray Then
        Call("_VectorOf" & $typeOfMap1 & "Release", $vectorMap1)
    EndIf

    If $typeOfMap1 <> Default Then
        _cveOutputArrayRelease($oArrMap1)
        If $bMap1Create Then
            Call("_cve" & $typeOfMap1 & "Release", $map1)
        EndIf
    EndIf

    If $bNewCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfNewCameraMatrix & "Release", $vectorNewCameraMatrix)
    EndIf

    If $typeOfNewCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrNewCameraMatrix)
        If $bNewCameraMatrixCreate Then
            Call("_cve" & $typeOfNewCameraMatrix & "Release", $newCameraMatrix)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveInputArrayRelease($iArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $r)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf
EndFunc   ;==>_cveInitUndistortRectifyMapTyped

Func _cveInitUndistortRectifyMapMat($cameraMatrix, $distCoeffs, $r, $newCameraMatrix, $size, $m1type, $map1, $map2)
    ; cveInitUndistortRectifyMap using cv::Mat instead of _*Array
    _cveInitUndistortRectifyMapTyped("Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $r, "Mat", $newCameraMatrix, $size, $m1type, "Mat", $map1, "Mat", $map2)
EndFunc   ;==>_cveInitUndistortRectifyMapMat

Func _cveUndistort($src, $dst, $cameraMatrix, $distorCoeffs, $newCameraMatrix = _cveNoArray())
    ; CVAPI(void) cveUndistort(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* cameraMatrix, cv::_InputArray* distorCoeffs, cv::_InputArray* newCameraMatrix);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistorCoeffsDllType
    If IsDllStruct($distorCoeffs) Then
        $sDistorCoeffsDllType = "struct*"
    Else
        $sDistorCoeffsDllType = "ptr"
    EndIf

    Local $sNewCameraMatrixDllType
    If IsDllStruct($newCameraMatrix) Then
        $sNewCameraMatrixDllType = "struct*"
    Else
        $sNewCameraMatrixDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUndistort", $sSrcDllType, $src, $sDstDllType, $dst, $sCameraMatrixDllType, $cameraMatrix, $sDistorCoeffsDllType, $distorCoeffs, $sNewCameraMatrixDllType, $newCameraMatrix), "cveUndistort", @error)
EndFunc   ;==>_cveUndistort

Func _cveUndistortTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistorCoeffs, $distorCoeffs, $typeOfNewCameraMatrix = Default, $newCameraMatrix = _cveNoArray())

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistorCoeffs, $vectorDistorCoeffs, $iArrDistorCoeffsSize
    Local $bDistorCoeffsIsArray = IsArray($distorCoeffs)
    Local $bDistorCoeffsCreate = IsDllStruct($distorCoeffs) And $typeOfDistorCoeffs == "Scalar"

    If $typeOfDistorCoeffs == Default Then
        $iArrDistorCoeffs = $distorCoeffs
    ElseIf $bDistorCoeffsIsArray Then
        $vectorDistorCoeffs = Call("_VectorOf" & $typeOfDistorCoeffs & "Create")

        $iArrDistorCoeffsSize = UBound($distorCoeffs)
        For $i = 0 To $iArrDistorCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistorCoeffs & "Push", $vectorDistorCoeffs, $distorCoeffs[$i])
        Next

        $iArrDistorCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistorCoeffs, $vectorDistorCoeffs)
    Else
        If $bDistorCoeffsCreate Then
            $distorCoeffs = Call("_cve" & $typeOfDistorCoeffs & "Create", $distorCoeffs)
        EndIf
        $iArrDistorCoeffs = Call("_cveInputArrayFrom" & $typeOfDistorCoeffs, $distorCoeffs)
    EndIf

    Local $iArrNewCameraMatrix, $vectorNewCameraMatrix, $iArrNewCameraMatrixSize
    Local $bNewCameraMatrixIsArray = IsArray($newCameraMatrix)
    Local $bNewCameraMatrixCreate = IsDllStruct($newCameraMatrix) And $typeOfNewCameraMatrix == "Scalar"

    If $typeOfNewCameraMatrix == Default Then
        $iArrNewCameraMatrix = $newCameraMatrix
    ElseIf $bNewCameraMatrixIsArray Then
        $vectorNewCameraMatrix = Call("_VectorOf" & $typeOfNewCameraMatrix & "Create")

        $iArrNewCameraMatrixSize = UBound($newCameraMatrix)
        For $i = 0 To $iArrNewCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfNewCameraMatrix & "Push", $vectorNewCameraMatrix, $newCameraMatrix[$i])
        Next

        $iArrNewCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfNewCameraMatrix, $vectorNewCameraMatrix)
    Else
        If $bNewCameraMatrixCreate Then
            $newCameraMatrix = Call("_cve" & $typeOfNewCameraMatrix & "Create", $newCameraMatrix)
        EndIf
        $iArrNewCameraMatrix = Call("_cveInputArrayFrom" & $typeOfNewCameraMatrix, $newCameraMatrix)
    EndIf

    _cveUndistort($iArrSrc, $oArrDst, $iArrCameraMatrix, $iArrDistorCoeffs, $iArrNewCameraMatrix)

    If $bNewCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfNewCameraMatrix & "Release", $vectorNewCameraMatrix)
    EndIf

    If $typeOfNewCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrNewCameraMatrix)
        If $bNewCameraMatrixCreate Then
            Call("_cve" & $typeOfNewCameraMatrix & "Release", $newCameraMatrix)
        EndIf
    EndIf

    If $bDistorCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistorCoeffs & "Release", $vectorDistorCoeffs)
    EndIf

    If $typeOfDistorCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistorCoeffs)
        If $bDistorCoeffsCreate Then
            Call("_cve" & $typeOfDistorCoeffs & "Release", $distorCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveUndistortTyped

Func _cveUndistortMat($src, $dst, $cameraMatrix, $distorCoeffs, $newCameraMatrix = _cveNoArrayMat())
    ; cveUndistort using cv::Mat instead of _*Array
    _cveUndistortTyped("Mat", $src, "Mat", $dst, "Mat", $cameraMatrix, "Mat", $distorCoeffs, "Mat", $newCameraMatrix)
EndFunc   ;==>_cveUndistortMat

Func _cveUndistortPoints($src, $dst, $cameraMatrix, $distCoeffs, $r, $p)
    ; CVAPI(void) cveUndistortPoints(cv::_InputArray* src, cv::_OutputArray* dst, cv::_InputArray* cameraMatrix, cv::_InputArray* distCoeffs, cv::_InputArray* r, cv::_InputArray* p);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sDstDllType
    If IsDllStruct($dst) Then
        $sDstDllType = "struct*"
    Else
        $sDstDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sDistCoeffsDllType
    If IsDllStruct($distCoeffs) Then
        $sDistCoeffsDllType = "struct*"
    Else
        $sDistCoeffsDllType = "ptr"
    EndIf

    Local $sRDllType
    If IsDllStruct($r) Then
        $sRDllType = "struct*"
    Else
        $sRDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveUndistortPoints", $sSrcDllType, $src, $sDstDllType, $dst, $sCameraMatrixDllType, $cameraMatrix, $sDistCoeffsDllType, $distCoeffs, $sRDllType, $r, $sPDllType, $p), "cveUndistortPoints", @error)
EndFunc   ;==>_cveUndistortPoints

Func _cveUndistortPointsTyped($typeOfSrc, $src, $typeOfDst, $dst, $typeOfCameraMatrix, $cameraMatrix, $typeOfDistCoeffs, $distCoeffs, $typeOfR, $r, $typeOfP, $p)

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrDst, $vectorDst, $iArrDstSize
    Local $bDstIsArray = IsArray($dst)
    Local $bDstCreate = IsDllStruct($dst) And $typeOfDst == "Scalar"

    If $typeOfDst == Default Then
        $oArrDst = $dst
    ElseIf $bDstIsArray Then
        $vectorDst = Call("_VectorOf" & $typeOfDst & "Create")

        $iArrDstSize = UBound($dst)
        For $i = 0 To $iArrDstSize - 1
            Call("_VectorOf" & $typeOfDst & "Push", $vectorDst, $dst[$i])
        Next

        $oArrDst = Call("_cveOutputArrayFromVectorOf" & $typeOfDst, $vectorDst)
    Else
        If $bDstCreate Then
            $dst = Call("_cve" & $typeOfDst & "Create", $dst)
        EndIf
        $oArrDst = Call("_cveOutputArrayFrom" & $typeOfDst, $dst)
    EndIf

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $iArrDistCoeffs, $vectorDistCoeffs, $iArrDistCoeffsSize
    Local $bDistCoeffsIsArray = IsArray($distCoeffs)
    Local $bDistCoeffsCreate = IsDllStruct($distCoeffs) And $typeOfDistCoeffs == "Scalar"

    If $typeOfDistCoeffs == Default Then
        $iArrDistCoeffs = $distCoeffs
    ElseIf $bDistCoeffsIsArray Then
        $vectorDistCoeffs = Call("_VectorOf" & $typeOfDistCoeffs & "Create")

        $iArrDistCoeffsSize = UBound($distCoeffs)
        For $i = 0 To $iArrDistCoeffsSize - 1
            Call("_VectorOf" & $typeOfDistCoeffs & "Push", $vectorDistCoeffs, $distCoeffs[$i])
        Next

        $iArrDistCoeffs = Call("_cveInputArrayFromVectorOf" & $typeOfDistCoeffs, $vectorDistCoeffs)
    Else
        If $bDistCoeffsCreate Then
            $distCoeffs = Call("_cve" & $typeOfDistCoeffs & "Create", $distCoeffs)
        EndIf
        $iArrDistCoeffs = Call("_cveInputArrayFrom" & $typeOfDistCoeffs, $distCoeffs)
    EndIf

    Local $iArrR, $vectorR, $iArrRSize
    Local $bRIsArray = IsArray($r)
    Local $bRCreate = IsDllStruct($r) And $typeOfR == "Scalar"

    If $typeOfR == Default Then
        $iArrR = $r
    ElseIf $bRIsArray Then
        $vectorR = Call("_VectorOf" & $typeOfR & "Create")

        $iArrRSize = UBound($r)
        For $i = 0 To $iArrRSize - 1
            Call("_VectorOf" & $typeOfR & "Push", $vectorR, $r[$i])
        Next

        $iArrR = Call("_cveInputArrayFromVectorOf" & $typeOfR, $vectorR)
    Else
        If $bRCreate Then
            $r = Call("_cve" & $typeOfR & "Create", $r)
        EndIf
        $iArrR = Call("_cveInputArrayFrom" & $typeOfR, $r)
    EndIf

    Local $iArrP, $vectorP, $iArrPSize
    Local $bPIsArray = IsArray($p)
    Local $bPCreate = IsDllStruct($p) And $typeOfP == "Scalar"

    If $typeOfP == Default Then
        $iArrP = $p
    ElseIf $bPIsArray Then
        $vectorP = Call("_VectorOf" & $typeOfP & "Create")

        $iArrPSize = UBound($p)
        For $i = 0 To $iArrPSize - 1
            Call("_VectorOf" & $typeOfP & "Push", $vectorP, $p[$i])
        Next

        $iArrP = Call("_cveInputArrayFromVectorOf" & $typeOfP, $vectorP)
    Else
        If $bPCreate Then
            $p = Call("_cve" & $typeOfP & "Create", $p)
        EndIf
        $iArrP = Call("_cveInputArrayFrom" & $typeOfP, $p)
    EndIf

    _cveUndistortPoints($iArrSrc, $oArrDst, $iArrCameraMatrix, $iArrDistCoeffs, $iArrR, $iArrP)

    If $bPIsArray Then
        Call("_VectorOf" & $typeOfP & "Release", $vectorP)
    EndIf

    If $typeOfP <> Default Then
        _cveInputArrayRelease($iArrP)
        If $bPCreate Then
            Call("_cve" & $typeOfP & "Release", $p)
        EndIf
    EndIf

    If $bRIsArray Then
        Call("_VectorOf" & $typeOfR & "Release", $vectorR)
    EndIf

    If $typeOfR <> Default Then
        _cveInputArrayRelease($iArrR)
        If $bRCreate Then
            Call("_cve" & $typeOfR & "Release", $r)
        EndIf
    EndIf

    If $bDistCoeffsIsArray Then
        Call("_VectorOf" & $typeOfDistCoeffs & "Release", $vectorDistCoeffs)
    EndIf

    If $typeOfDistCoeffs <> Default Then
        _cveInputArrayRelease($iArrDistCoeffs)
        If $bDistCoeffsCreate Then
            Call("_cve" & $typeOfDistCoeffs & "Release", $distCoeffs)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bDstIsArray Then
        Call("_VectorOf" & $typeOfDst & "Release", $vectorDst)
    EndIf

    If $typeOfDst <> Default Then
        _cveOutputArrayRelease($oArrDst)
        If $bDstCreate Then
            Call("_cve" & $typeOfDst & "Release", $dst)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveUndistortPointsTyped

Func _cveUndistortPointsMat($src, $dst, $cameraMatrix, $distCoeffs, $r, $p)
    ; cveUndistortPoints using cv::Mat instead of _*Array
    _cveUndistortPointsTyped("Mat", $src, "Mat", $dst, "Mat", $cameraMatrix, "Mat", $distCoeffs, "Mat", $r, "Mat", $p)
EndFunc   ;==>_cveUndistortPointsMat

Func _cveGetDefaultNewCameraMatrix($cameraMatrix, $imgsize, $centerPrincipalPoint, $cm)
    ; CVAPI(void) cveGetDefaultNewCameraMatrix(cv::_InputArray* cameraMatrix, CvSize* imgsize, bool centerPrincipalPoint, cv::Mat* cm);

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sImgsizeDllType
    If IsDllStruct($imgsize) Then
        $sImgsizeDllType = "struct*"
    Else
        $sImgsizeDllType = "ptr"
    EndIf

    Local $sCmDllType
    If IsDllStruct($cm) Then
        $sCmDllType = "struct*"
    Else
        $sCmDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveGetDefaultNewCameraMatrix", $sCameraMatrixDllType, $cameraMatrix, $sImgsizeDllType, $imgsize, "boolean", $centerPrincipalPoint, $sCmDllType, $cm), "cveGetDefaultNewCameraMatrix", @error)
EndFunc   ;==>_cveGetDefaultNewCameraMatrix

Func _cveGetDefaultNewCameraMatrixTyped($typeOfCameraMatrix, $cameraMatrix, $imgsize, $centerPrincipalPoint, $cm)

    Local $iArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $iArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $iArrCameraMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $iArrCameraMatrix = Call("_cveInputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    _cveGetDefaultNewCameraMatrix($iArrCameraMatrix, $imgsize, $centerPrincipalPoint, $cm)

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveInputArrayRelease($iArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf
EndFunc   ;==>_cveGetDefaultNewCameraMatrixTyped

Func _cveGetDefaultNewCameraMatrixMat($cameraMatrix, $imgsize, $centerPrincipalPoint, $cm)
    ; cveGetDefaultNewCameraMatrix using cv::Mat instead of _*Array
    _cveGetDefaultNewCameraMatrixTyped("Mat", $cameraMatrix, $imgsize, $centerPrincipalPoint, $cm)
EndFunc   ;==>_cveGetDefaultNewCameraMatrixMat

Func _cveEstimateAffine2D($from, $to, $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)
    ; CVAPI(void) cveEstimateAffine2D(cv::_InputArray* from, cv::_InputArray* to, cv::_OutputArray* inliers, int method, double ransacReprojThreshold, int maxIters, double confidence, int refineIters, cv::Mat* affine);

    Local $sFromDllType
    If IsDllStruct($from) Then
        $sFromDllType = "struct*"
    Else
        $sFromDllType = "ptr"
    EndIf

    Local $sToDllType
    If IsDllStruct($to) Then
        $sToDllType = "struct*"
    Else
        $sToDllType = "ptr"
    EndIf

    Local $sInliersDllType
    If IsDllStruct($inliers) Then
        $sInliersDllType = "struct*"
    Else
        $sInliersDllType = "ptr"
    EndIf

    Local $sAffineDllType
    If IsDllStruct($affine) Then
        $sAffineDllType = "struct*"
    Else
        $sAffineDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEstimateAffine2D", $sFromDllType, $from, $sToDllType, $to, $sInliersDllType, $inliers, "int", $method, "double", $ransacReprojThreshold, "int", $maxIters, "double", $confidence, "int", $refineIters, $sAffineDllType, $affine), "cveEstimateAffine2D", @error)
EndFunc   ;==>_cveEstimateAffine2D

Func _cveEstimateAffine2DTyped($typeOfFrom, $from, $typeOfTo, $to, $typeOfInliers, $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)

    Local $iArrFrom, $vectorFrom, $iArrFromSize
    Local $bFromIsArray = IsArray($from)
    Local $bFromCreate = IsDllStruct($from) And $typeOfFrom == "Scalar"

    If $typeOfFrom == Default Then
        $iArrFrom = $from
    ElseIf $bFromIsArray Then
        $vectorFrom = Call("_VectorOf" & $typeOfFrom & "Create")

        $iArrFromSize = UBound($from)
        For $i = 0 To $iArrFromSize - 1
            Call("_VectorOf" & $typeOfFrom & "Push", $vectorFrom, $from[$i])
        Next

        $iArrFrom = Call("_cveInputArrayFromVectorOf" & $typeOfFrom, $vectorFrom)
    Else
        If $bFromCreate Then
            $from = Call("_cve" & $typeOfFrom & "Create", $from)
        EndIf
        $iArrFrom = Call("_cveInputArrayFrom" & $typeOfFrom, $from)
    EndIf

    Local $iArrTo, $vectorTo, $iArrToSize
    Local $bToIsArray = IsArray($to)
    Local $bToCreate = IsDllStruct($to) And $typeOfTo == "Scalar"

    If $typeOfTo == Default Then
        $iArrTo = $to
    ElseIf $bToIsArray Then
        $vectorTo = Call("_VectorOf" & $typeOfTo & "Create")

        $iArrToSize = UBound($to)
        For $i = 0 To $iArrToSize - 1
            Call("_VectorOf" & $typeOfTo & "Push", $vectorTo, $to[$i])
        Next

        $iArrTo = Call("_cveInputArrayFromVectorOf" & $typeOfTo, $vectorTo)
    Else
        If $bToCreate Then
            $to = Call("_cve" & $typeOfTo & "Create", $to)
        EndIf
        $iArrTo = Call("_cveInputArrayFrom" & $typeOfTo, $to)
    EndIf

    Local $oArrInliers, $vectorInliers, $iArrInliersSize
    Local $bInliersIsArray = IsArray($inliers)
    Local $bInliersCreate = IsDllStruct($inliers) And $typeOfInliers == "Scalar"

    If $typeOfInliers == Default Then
        $oArrInliers = $inliers
    ElseIf $bInliersIsArray Then
        $vectorInliers = Call("_VectorOf" & $typeOfInliers & "Create")

        $iArrInliersSize = UBound($inliers)
        For $i = 0 To $iArrInliersSize - 1
            Call("_VectorOf" & $typeOfInliers & "Push", $vectorInliers, $inliers[$i])
        Next

        $oArrInliers = Call("_cveOutputArrayFromVectorOf" & $typeOfInliers, $vectorInliers)
    Else
        If $bInliersCreate Then
            $inliers = Call("_cve" & $typeOfInliers & "Create", $inliers)
        EndIf
        $oArrInliers = Call("_cveOutputArrayFrom" & $typeOfInliers, $inliers)
    EndIf

    _cveEstimateAffine2D($iArrFrom, $iArrTo, $oArrInliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)

    If $bInliersIsArray Then
        Call("_VectorOf" & $typeOfInliers & "Release", $vectorInliers)
    EndIf

    If $typeOfInliers <> Default Then
        _cveOutputArrayRelease($oArrInliers)
        If $bInliersCreate Then
            Call("_cve" & $typeOfInliers & "Release", $inliers)
        EndIf
    EndIf

    If $bToIsArray Then
        Call("_VectorOf" & $typeOfTo & "Release", $vectorTo)
    EndIf

    If $typeOfTo <> Default Then
        _cveInputArrayRelease($iArrTo)
        If $bToCreate Then
            Call("_cve" & $typeOfTo & "Release", $to)
        EndIf
    EndIf

    If $bFromIsArray Then
        Call("_VectorOf" & $typeOfFrom & "Release", $vectorFrom)
    EndIf

    If $typeOfFrom <> Default Then
        _cveInputArrayRelease($iArrFrom)
        If $bFromCreate Then
            Call("_cve" & $typeOfFrom & "Release", $from)
        EndIf
    EndIf
EndFunc   ;==>_cveEstimateAffine2DTyped

Func _cveEstimateAffine2DMat($from, $to, $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)
    ; cveEstimateAffine2D using cv::Mat instead of _*Array
    _cveEstimateAffine2DTyped("Mat", $from, "Mat", $to, "Mat", $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)
EndFunc   ;==>_cveEstimateAffine2DMat

Func _cveEstimateAffinePartial2D($from, $to, $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)
    ; CVAPI(void) cveEstimateAffinePartial2D(cv::_InputArray* from, cv::_InputArray* to, cv::_OutputArray* inliers, int method, double ransacReprojThreshold, int maxIters, double confidence, int refineIters, cv::Mat* affine);

    Local $sFromDllType
    If IsDllStruct($from) Then
        $sFromDllType = "struct*"
    Else
        $sFromDllType = "ptr"
    EndIf

    Local $sToDllType
    If IsDllStruct($to) Then
        $sToDllType = "struct*"
    Else
        $sToDllType = "ptr"
    EndIf

    Local $sInliersDllType
    If IsDllStruct($inliers) Then
        $sInliersDllType = "struct*"
    Else
        $sInliersDllType = "ptr"
    EndIf

    Local $sAffineDllType
    If IsDllStruct($affine) Then
        $sAffineDllType = "struct*"
    Else
        $sAffineDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveEstimateAffinePartial2D", $sFromDllType, $from, $sToDllType, $to, $sInliersDllType, $inliers, "int", $method, "double", $ransacReprojThreshold, "int", $maxIters, "double", $confidence, "int", $refineIters, $sAffineDllType, $affine), "cveEstimateAffinePartial2D", @error)
EndFunc   ;==>_cveEstimateAffinePartial2D

Func _cveEstimateAffinePartial2DTyped($typeOfFrom, $from, $typeOfTo, $to, $typeOfInliers, $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)

    Local $iArrFrom, $vectorFrom, $iArrFromSize
    Local $bFromIsArray = IsArray($from)
    Local $bFromCreate = IsDllStruct($from) And $typeOfFrom == "Scalar"

    If $typeOfFrom == Default Then
        $iArrFrom = $from
    ElseIf $bFromIsArray Then
        $vectorFrom = Call("_VectorOf" & $typeOfFrom & "Create")

        $iArrFromSize = UBound($from)
        For $i = 0 To $iArrFromSize - 1
            Call("_VectorOf" & $typeOfFrom & "Push", $vectorFrom, $from[$i])
        Next

        $iArrFrom = Call("_cveInputArrayFromVectorOf" & $typeOfFrom, $vectorFrom)
    Else
        If $bFromCreate Then
            $from = Call("_cve" & $typeOfFrom & "Create", $from)
        EndIf
        $iArrFrom = Call("_cveInputArrayFrom" & $typeOfFrom, $from)
    EndIf

    Local $iArrTo, $vectorTo, $iArrToSize
    Local $bToIsArray = IsArray($to)
    Local $bToCreate = IsDllStruct($to) And $typeOfTo == "Scalar"

    If $typeOfTo == Default Then
        $iArrTo = $to
    ElseIf $bToIsArray Then
        $vectorTo = Call("_VectorOf" & $typeOfTo & "Create")

        $iArrToSize = UBound($to)
        For $i = 0 To $iArrToSize - 1
            Call("_VectorOf" & $typeOfTo & "Push", $vectorTo, $to[$i])
        Next

        $iArrTo = Call("_cveInputArrayFromVectorOf" & $typeOfTo, $vectorTo)
    Else
        If $bToCreate Then
            $to = Call("_cve" & $typeOfTo & "Create", $to)
        EndIf
        $iArrTo = Call("_cveInputArrayFrom" & $typeOfTo, $to)
    EndIf

    Local $oArrInliers, $vectorInliers, $iArrInliersSize
    Local $bInliersIsArray = IsArray($inliers)
    Local $bInliersCreate = IsDllStruct($inliers) And $typeOfInliers == "Scalar"

    If $typeOfInliers == Default Then
        $oArrInliers = $inliers
    ElseIf $bInliersIsArray Then
        $vectorInliers = Call("_VectorOf" & $typeOfInliers & "Create")

        $iArrInliersSize = UBound($inliers)
        For $i = 0 To $iArrInliersSize - 1
            Call("_VectorOf" & $typeOfInliers & "Push", $vectorInliers, $inliers[$i])
        Next

        $oArrInliers = Call("_cveOutputArrayFromVectorOf" & $typeOfInliers, $vectorInliers)
    Else
        If $bInliersCreate Then
            $inliers = Call("_cve" & $typeOfInliers & "Create", $inliers)
        EndIf
        $oArrInliers = Call("_cveOutputArrayFrom" & $typeOfInliers, $inliers)
    EndIf

    _cveEstimateAffinePartial2D($iArrFrom, $iArrTo, $oArrInliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)

    If $bInliersIsArray Then
        Call("_VectorOf" & $typeOfInliers & "Release", $vectorInliers)
    EndIf

    If $typeOfInliers <> Default Then
        _cveOutputArrayRelease($oArrInliers)
        If $bInliersCreate Then
            Call("_cve" & $typeOfInliers & "Release", $inliers)
        EndIf
    EndIf

    If $bToIsArray Then
        Call("_VectorOf" & $typeOfTo & "Release", $vectorTo)
    EndIf

    If $typeOfTo <> Default Then
        _cveInputArrayRelease($iArrTo)
        If $bToCreate Then
            Call("_cve" & $typeOfTo & "Release", $to)
        EndIf
    EndIf

    If $bFromIsArray Then
        Call("_VectorOf" & $typeOfFrom & "Release", $vectorFrom)
    EndIf

    If $typeOfFrom <> Default Then
        _cveInputArrayRelease($iArrFrom)
        If $bFromCreate Then
            Call("_cve" & $typeOfFrom & "Release", $from)
        EndIf
    EndIf
EndFunc   ;==>_cveEstimateAffinePartial2DTyped

Func _cveEstimateAffinePartial2DMat($from, $to, $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)
    ; cveEstimateAffinePartial2D using cv::Mat instead of _*Array
    _cveEstimateAffinePartial2DTyped("Mat", $from, "Mat", $to, "Mat", $inliers, $method, $ransacReprojThreshold, $maxIters, $confidence, $refineIters, $affine)
EndFunc   ;==>_cveEstimateAffinePartial2DMat

Func _cveCalibrateHandEye($R_gripper2base, $t_gripper2base, $R_target2cam, $t_target2cam, $R_cam2gripper, $t_cam2gripper, $method = $CV_CALIB_HAND_EYE_TSAI)
    ; CVAPI(void) cveCalibrateHandEye(cv::_InputArray* R_gripper2base, cv::_InputArray* t_gripper2base, cv::_InputArray* R_target2cam, cv::_InputArray* t_target2cam, cv::_OutputArray* R_cam2gripper, cv::_OutputArray* t_cam2gripper, int method);

    Local $sR_gripper2baseDllType
    If IsDllStruct($R_gripper2base) Then
        $sR_gripper2baseDllType = "struct*"
    Else
        $sR_gripper2baseDllType = "ptr"
    EndIf

    Local $sT_gripper2baseDllType
    If IsDllStruct($t_gripper2base) Then
        $sT_gripper2baseDllType = "struct*"
    Else
        $sT_gripper2baseDllType = "ptr"
    EndIf

    Local $sR_target2camDllType
    If IsDllStruct($R_target2cam) Then
        $sR_target2camDllType = "struct*"
    Else
        $sR_target2camDllType = "ptr"
    EndIf

    Local $sT_target2camDllType
    If IsDllStruct($t_target2cam) Then
        $sT_target2camDllType = "struct*"
    Else
        $sT_target2camDllType = "ptr"
    EndIf

    Local $sR_cam2gripperDllType
    If IsDllStruct($R_cam2gripper) Then
        $sR_cam2gripperDllType = "struct*"
    Else
        $sR_cam2gripperDllType = "ptr"
    EndIf

    Local $sT_cam2gripperDllType
    If IsDllStruct($t_cam2gripper) Then
        $sT_cam2gripperDllType = "struct*"
    Else
        $sT_cam2gripperDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCalibrateHandEye", $sR_gripper2baseDllType, $R_gripper2base, $sT_gripper2baseDllType, $t_gripper2base, $sR_target2camDllType, $R_target2cam, $sT_target2camDllType, $t_target2cam, $sR_cam2gripperDllType, $R_cam2gripper, $sT_cam2gripperDllType, $t_cam2gripper, "int", $method), "cveCalibrateHandEye", @error)
EndFunc   ;==>_cveCalibrateHandEye

Func _cveCalibrateHandEyeTyped($typeOfR_gripper2base, $R_gripper2base, $typeOfT_gripper2base, $t_gripper2base, $typeOfR_target2cam, $R_target2cam, $typeOfT_target2cam, $t_target2cam, $typeOfR_cam2gripper, $R_cam2gripper, $typeOfT_cam2gripper, $t_cam2gripper, $method = $CV_CALIB_HAND_EYE_TSAI)

    Local $iArrR_gripper2base, $vectorR_gripper2base, $iArrR_gripper2baseSize
    Local $bR_gripper2baseIsArray = IsArray($R_gripper2base)
    Local $bR_gripper2baseCreate = IsDllStruct($R_gripper2base) And $typeOfR_gripper2base == "Scalar"

    If $typeOfR_gripper2base == Default Then
        $iArrR_gripper2base = $R_gripper2base
    ElseIf $bR_gripper2baseIsArray Then
        $vectorR_gripper2base = Call("_VectorOf" & $typeOfR_gripper2base & "Create")

        $iArrR_gripper2baseSize = UBound($R_gripper2base)
        For $i = 0 To $iArrR_gripper2baseSize - 1
            Call("_VectorOf" & $typeOfR_gripper2base & "Push", $vectorR_gripper2base, $R_gripper2base[$i])
        Next

        $iArrR_gripper2base = Call("_cveInputArrayFromVectorOf" & $typeOfR_gripper2base, $vectorR_gripper2base)
    Else
        If $bR_gripper2baseCreate Then
            $R_gripper2base = Call("_cve" & $typeOfR_gripper2base & "Create", $R_gripper2base)
        EndIf
        $iArrR_gripper2base = Call("_cveInputArrayFrom" & $typeOfR_gripper2base, $R_gripper2base)
    EndIf

    Local $iArrT_gripper2base, $vectorT_gripper2base, $iArrT_gripper2baseSize
    Local $bT_gripper2baseIsArray = IsArray($t_gripper2base)
    Local $bT_gripper2baseCreate = IsDllStruct($t_gripper2base) And $typeOfT_gripper2base == "Scalar"

    If $typeOfT_gripper2base == Default Then
        $iArrT_gripper2base = $t_gripper2base
    ElseIf $bT_gripper2baseIsArray Then
        $vectorT_gripper2base = Call("_VectorOf" & $typeOfT_gripper2base & "Create")

        $iArrT_gripper2baseSize = UBound($t_gripper2base)
        For $i = 0 To $iArrT_gripper2baseSize - 1
            Call("_VectorOf" & $typeOfT_gripper2base & "Push", $vectorT_gripper2base, $t_gripper2base[$i])
        Next

        $iArrT_gripper2base = Call("_cveInputArrayFromVectorOf" & $typeOfT_gripper2base, $vectorT_gripper2base)
    Else
        If $bT_gripper2baseCreate Then
            $t_gripper2base = Call("_cve" & $typeOfT_gripper2base & "Create", $t_gripper2base)
        EndIf
        $iArrT_gripper2base = Call("_cveInputArrayFrom" & $typeOfT_gripper2base, $t_gripper2base)
    EndIf

    Local $iArrR_target2cam, $vectorR_target2cam, $iArrR_target2camSize
    Local $bR_target2camIsArray = IsArray($R_target2cam)
    Local $bR_target2camCreate = IsDllStruct($R_target2cam) And $typeOfR_target2cam == "Scalar"

    If $typeOfR_target2cam == Default Then
        $iArrR_target2cam = $R_target2cam
    ElseIf $bR_target2camIsArray Then
        $vectorR_target2cam = Call("_VectorOf" & $typeOfR_target2cam & "Create")

        $iArrR_target2camSize = UBound($R_target2cam)
        For $i = 0 To $iArrR_target2camSize - 1
            Call("_VectorOf" & $typeOfR_target2cam & "Push", $vectorR_target2cam, $R_target2cam[$i])
        Next

        $iArrR_target2cam = Call("_cveInputArrayFromVectorOf" & $typeOfR_target2cam, $vectorR_target2cam)
    Else
        If $bR_target2camCreate Then
            $R_target2cam = Call("_cve" & $typeOfR_target2cam & "Create", $R_target2cam)
        EndIf
        $iArrR_target2cam = Call("_cveInputArrayFrom" & $typeOfR_target2cam, $R_target2cam)
    EndIf

    Local $iArrT_target2cam, $vectorT_target2cam, $iArrT_target2camSize
    Local $bT_target2camIsArray = IsArray($t_target2cam)
    Local $bT_target2camCreate = IsDllStruct($t_target2cam) And $typeOfT_target2cam == "Scalar"

    If $typeOfT_target2cam == Default Then
        $iArrT_target2cam = $t_target2cam
    ElseIf $bT_target2camIsArray Then
        $vectorT_target2cam = Call("_VectorOf" & $typeOfT_target2cam & "Create")

        $iArrT_target2camSize = UBound($t_target2cam)
        For $i = 0 To $iArrT_target2camSize - 1
            Call("_VectorOf" & $typeOfT_target2cam & "Push", $vectorT_target2cam, $t_target2cam[$i])
        Next

        $iArrT_target2cam = Call("_cveInputArrayFromVectorOf" & $typeOfT_target2cam, $vectorT_target2cam)
    Else
        If $bT_target2camCreate Then
            $t_target2cam = Call("_cve" & $typeOfT_target2cam & "Create", $t_target2cam)
        EndIf
        $iArrT_target2cam = Call("_cveInputArrayFrom" & $typeOfT_target2cam, $t_target2cam)
    EndIf

    Local $oArrR_cam2gripper, $vectorR_cam2gripper, $iArrR_cam2gripperSize
    Local $bR_cam2gripperIsArray = IsArray($R_cam2gripper)
    Local $bR_cam2gripperCreate = IsDllStruct($R_cam2gripper) And $typeOfR_cam2gripper == "Scalar"

    If $typeOfR_cam2gripper == Default Then
        $oArrR_cam2gripper = $R_cam2gripper
    ElseIf $bR_cam2gripperIsArray Then
        $vectorR_cam2gripper = Call("_VectorOf" & $typeOfR_cam2gripper & "Create")

        $iArrR_cam2gripperSize = UBound($R_cam2gripper)
        For $i = 0 To $iArrR_cam2gripperSize - 1
            Call("_VectorOf" & $typeOfR_cam2gripper & "Push", $vectorR_cam2gripper, $R_cam2gripper[$i])
        Next

        $oArrR_cam2gripper = Call("_cveOutputArrayFromVectorOf" & $typeOfR_cam2gripper, $vectorR_cam2gripper)
    Else
        If $bR_cam2gripperCreate Then
            $R_cam2gripper = Call("_cve" & $typeOfR_cam2gripper & "Create", $R_cam2gripper)
        EndIf
        $oArrR_cam2gripper = Call("_cveOutputArrayFrom" & $typeOfR_cam2gripper, $R_cam2gripper)
    EndIf

    Local $oArrT_cam2gripper, $vectorT_cam2gripper, $iArrT_cam2gripperSize
    Local $bT_cam2gripperIsArray = IsArray($t_cam2gripper)
    Local $bT_cam2gripperCreate = IsDllStruct($t_cam2gripper) And $typeOfT_cam2gripper == "Scalar"

    If $typeOfT_cam2gripper == Default Then
        $oArrT_cam2gripper = $t_cam2gripper
    ElseIf $bT_cam2gripperIsArray Then
        $vectorT_cam2gripper = Call("_VectorOf" & $typeOfT_cam2gripper & "Create")

        $iArrT_cam2gripperSize = UBound($t_cam2gripper)
        For $i = 0 To $iArrT_cam2gripperSize - 1
            Call("_VectorOf" & $typeOfT_cam2gripper & "Push", $vectorT_cam2gripper, $t_cam2gripper[$i])
        Next

        $oArrT_cam2gripper = Call("_cveOutputArrayFromVectorOf" & $typeOfT_cam2gripper, $vectorT_cam2gripper)
    Else
        If $bT_cam2gripperCreate Then
            $t_cam2gripper = Call("_cve" & $typeOfT_cam2gripper & "Create", $t_cam2gripper)
        EndIf
        $oArrT_cam2gripper = Call("_cveOutputArrayFrom" & $typeOfT_cam2gripper, $t_cam2gripper)
    EndIf

    _cveCalibrateHandEye($iArrR_gripper2base, $iArrT_gripper2base, $iArrR_target2cam, $iArrT_target2cam, $oArrR_cam2gripper, $oArrT_cam2gripper, $method)

    If $bT_cam2gripperIsArray Then
        Call("_VectorOf" & $typeOfT_cam2gripper & "Release", $vectorT_cam2gripper)
    EndIf

    If $typeOfT_cam2gripper <> Default Then
        _cveOutputArrayRelease($oArrT_cam2gripper)
        If $bT_cam2gripperCreate Then
            Call("_cve" & $typeOfT_cam2gripper & "Release", $t_cam2gripper)
        EndIf
    EndIf

    If $bR_cam2gripperIsArray Then
        Call("_VectorOf" & $typeOfR_cam2gripper & "Release", $vectorR_cam2gripper)
    EndIf

    If $typeOfR_cam2gripper <> Default Then
        _cveOutputArrayRelease($oArrR_cam2gripper)
        If $bR_cam2gripperCreate Then
            Call("_cve" & $typeOfR_cam2gripper & "Release", $R_cam2gripper)
        EndIf
    EndIf

    If $bT_target2camIsArray Then
        Call("_VectorOf" & $typeOfT_target2cam & "Release", $vectorT_target2cam)
    EndIf

    If $typeOfT_target2cam <> Default Then
        _cveInputArrayRelease($iArrT_target2cam)
        If $bT_target2camCreate Then
            Call("_cve" & $typeOfT_target2cam & "Release", $t_target2cam)
        EndIf
    EndIf

    If $bR_target2camIsArray Then
        Call("_VectorOf" & $typeOfR_target2cam & "Release", $vectorR_target2cam)
    EndIf

    If $typeOfR_target2cam <> Default Then
        _cveInputArrayRelease($iArrR_target2cam)
        If $bR_target2camCreate Then
            Call("_cve" & $typeOfR_target2cam & "Release", $R_target2cam)
        EndIf
    EndIf

    If $bT_gripper2baseIsArray Then
        Call("_VectorOf" & $typeOfT_gripper2base & "Release", $vectorT_gripper2base)
    EndIf

    If $typeOfT_gripper2base <> Default Then
        _cveInputArrayRelease($iArrT_gripper2base)
        If $bT_gripper2baseCreate Then
            Call("_cve" & $typeOfT_gripper2base & "Release", $t_gripper2base)
        EndIf
    EndIf

    If $bR_gripper2baseIsArray Then
        Call("_VectorOf" & $typeOfR_gripper2base & "Release", $vectorR_gripper2base)
    EndIf

    If $typeOfR_gripper2base <> Default Then
        _cveInputArrayRelease($iArrR_gripper2base)
        If $bR_gripper2baseCreate Then
            Call("_cve" & $typeOfR_gripper2base & "Release", $R_gripper2base)
        EndIf
    EndIf
EndFunc   ;==>_cveCalibrateHandEyeTyped

Func _cveCalibrateHandEyeMat($R_gripper2base, $t_gripper2base, $R_target2cam, $t_target2cam, $R_cam2gripper, $t_cam2gripper, $method = $CV_CALIB_HAND_EYE_TSAI)
    ; cveCalibrateHandEye using cv::Mat instead of _*Array
    _cveCalibrateHandEyeTyped("Mat", $R_gripper2base, "Mat", $t_gripper2base, "Mat", $R_target2cam, "Mat", $t_target2cam, "Mat", $R_cam2gripper, "Mat", $t_cam2gripper, $method)
EndFunc   ;==>_cveCalibrateHandEyeMat

Func _cveRQDecomp3x3($src, $out, $mtxR, $mtxQ, $Qx = _cveNoArray(), $Qy = _cveNoArray(), $Qz = _cveNoArray())
    ; CVAPI(void) cveRQDecomp3x3(cv::_InputArray* src, CvPoint3D64f* out, cv::_OutputArray* mtxR, cv::_OutputArray* mtxQ, cv::_OutputArray* Qx, cv::_OutputArray* Qy, cv::_OutputArray* Qz);

    Local $sSrcDllType
    If IsDllStruct($src) Then
        $sSrcDllType = "struct*"
    Else
        $sSrcDllType = "ptr"
    EndIf

    Local $sOutDllType
    If IsDllStruct($out) Then
        $sOutDllType = "struct*"
    Else
        $sOutDllType = "ptr"
    EndIf

    Local $sMtxRDllType
    If IsDllStruct($mtxR) Then
        $sMtxRDllType = "struct*"
    Else
        $sMtxRDllType = "ptr"
    EndIf

    Local $sMtxQDllType
    If IsDllStruct($mtxQ) Then
        $sMtxQDllType = "struct*"
    Else
        $sMtxQDllType = "ptr"
    EndIf

    Local $sQxDllType
    If IsDllStruct($Qx) Then
        $sQxDllType = "struct*"
    Else
        $sQxDllType = "ptr"
    EndIf

    Local $sQyDllType
    If IsDllStruct($Qy) Then
        $sQyDllType = "struct*"
    Else
        $sQyDllType = "ptr"
    EndIf

    Local $sQzDllType
    If IsDllStruct($Qz) Then
        $sQzDllType = "struct*"
    Else
        $sQzDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveRQDecomp3x3", $sSrcDllType, $src, $sOutDllType, $out, $sMtxRDllType, $mtxR, $sMtxQDllType, $mtxQ, $sQxDllType, $Qx, $sQyDllType, $Qy, $sQzDllType, $Qz), "cveRQDecomp3x3", @error)
EndFunc   ;==>_cveRQDecomp3x3

Func _cveRQDecomp3x3Typed($typeOfSrc, $src, $out, $typeOfMtxR, $mtxR, $typeOfMtxQ, $mtxQ, $typeOfQx = Default, $Qx = _cveNoArray(), $typeOfQy = Default, $Qy = _cveNoArray(), $typeOfQz = Default, $Qz = _cveNoArray())

    Local $iArrSrc, $vectorSrc, $iArrSrcSize
    Local $bSrcIsArray = IsArray($src)
    Local $bSrcCreate = IsDllStruct($src) And $typeOfSrc == "Scalar"

    If $typeOfSrc == Default Then
        $iArrSrc = $src
    ElseIf $bSrcIsArray Then
        $vectorSrc = Call("_VectorOf" & $typeOfSrc & "Create")

        $iArrSrcSize = UBound($src)
        For $i = 0 To $iArrSrcSize - 1
            Call("_VectorOf" & $typeOfSrc & "Push", $vectorSrc, $src[$i])
        Next

        $iArrSrc = Call("_cveInputArrayFromVectorOf" & $typeOfSrc, $vectorSrc)
    Else
        If $bSrcCreate Then
            $src = Call("_cve" & $typeOfSrc & "Create", $src)
        EndIf
        $iArrSrc = Call("_cveInputArrayFrom" & $typeOfSrc, $src)
    EndIf

    Local $oArrMtxR, $vectorMtxR, $iArrMtxRSize
    Local $bMtxRIsArray = IsArray($mtxR)
    Local $bMtxRCreate = IsDllStruct($mtxR) And $typeOfMtxR == "Scalar"

    If $typeOfMtxR == Default Then
        $oArrMtxR = $mtxR
    ElseIf $bMtxRIsArray Then
        $vectorMtxR = Call("_VectorOf" & $typeOfMtxR & "Create")

        $iArrMtxRSize = UBound($mtxR)
        For $i = 0 To $iArrMtxRSize - 1
            Call("_VectorOf" & $typeOfMtxR & "Push", $vectorMtxR, $mtxR[$i])
        Next

        $oArrMtxR = Call("_cveOutputArrayFromVectorOf" & $typeOfMtxR, $vectorMtxR)
    Else
        If $bMtxRCreate Then
            $mtxR = Call("_cve" & $typeOfMtxR & "Create", $mtxR)
        EndIf
        $oArrMtxR = Call("_cveOutputArrayFrom" & $typeOfMtxR, $mtxR)
    EndIf

    Local $oArrMtxQ, $vectorMtxQ, $iArrMtxQSize
    Local $bMtxQIsArray = IsArray($mtxQ)
    Local $bMtxQCreate = IsDllStruct($mtxQ) And $typeOfMtxQ == "Scalar"

    If $typeOfMtxQ == Default Then
        $oArrMtxQ = $mtxQ
    ElseIf $bMtxQIsArray Then
        $vectorMtxQ = Call("_VectorOf" & $typeOfMtxQ & "Create")

        $iArrMtxQSize = UBound($mtxQ)
        For $i = 0 To $iArrMtxQSize - 1
            Call("_VectorOf" & $typeOfMtxQ & "Push", $vectorMtxQ, $mtxQ[$i])
        Next

        $oArrMtxQ = Call("_cveOutputArrayFromVectorOf" & $typeOfMtxQ, $vectorMtxQ)
    Else
        If $bMtxQCreate Then
            $mtxQ = Call("_cve" & $typeOfMtxQ & "Create", $mtxQ)
        EndIf
        $oArrMtxQ = Call("_cveOutputArrayFrom" & $typeOfMtxQ, $mtxQ)
    EndIf

    Local $oArrQx, $vectorQx, $iArrQxSize
    Local $bQxIsArray = IsArray($Qx)
    Local $bQxCreate = IsDllStruct($Qx) And $typeOfQx == "Scalar"

    If $typeOfQx == Default Then
        $oArrQx = $Qx
    ElseIf $bQxIsArray Then
        $vectorQx = Call("_VectorOf" & $typeOfQx & "Create")

        $iArrQxSize = UBound($Qx)
        For $i = 0 To $iArrQxSize - 1
            Call("_VectorOf" & $typeOfQx & "Push", $vectorQx, $Qx[$i])
        Next

        $oArrQx = Call("_cveOutputArrayFromVectorOf" & $typeOfQx, $vectorQx)
    Else
        If $bQxCreate Then
            $Qx = Call("_cve" & $typeOfQx & "Create", $Qx)
        EndIf
        $oArrQx = Call("_cveOutputArrayFrom" & $typeOfQx, $Qx)
    EndIf

    Local $oArrQy, $vectorQy, $iArrQySize
    Local $bQyIsArray = IsArray($Qy)
    Local $bQyCreate = IsDllStruct($Qy) And $typeOfQy == "Scalar"

    If $typeOfQy == Default Then
        $oArrQy = $Qy
    ElseIf $bQyIsArray Then
        $vectorQy = Call("_VectorOf" & $typeOfQy & "Create")

        $iArrQySize = UBound($Qy)
        For $i = 0 To $iArrQySize - 1
            Call("_VectorOf" & $typeOfQy & "Push", $vectorQy, $Qy[$i])
        Next

        $oArrQy = Call("_cveOutputArrayFromVectorOf" & $typeOfQy, $vectorQy)
    Else
        If $bQyCreate Then
            $Qy = Call("_cve" & $typeOfQy & "Create", $Qy)
        EndIf
        $oArrQy = Call("_cveOutputArrayFrom" & $typeOfQy, $Qy)
    EndIf

    Local $oArrQz, $vectorQz, $iArrQzSize
    Local $bQzIsArray = IsArray($Qz)
    Local $bQzCreate = IsDllStruct($Qz) And $typeOfQz == "Scalar"

    If $typeOfQz == Default Then
        $oArrQz = $Qz
    ElseIf $bQzIsArray Then
        $vectorQz = Call("_VectorOf" & $typeOfQz & "Create")

        $iArrQzSize = UBound($Qz)
        For $i = 0 To $iArrQzSize - 1
            Call("_VectorOf" & $typeOfQz & "Push", $vectorQz, $Qz[$i])
        Next

        $oArrQz = Call("_cveOutputArrayFromVectorOf" & $typeOfQz, $vectorQz)
    Else
        If $bQzCreate Then
            $Qz = Call("_cve" & $typeOfQz & "Create", $Qz)
        EndIf
        $oArrQz = Call("_cveOutputArrayFrom" & $typeOfQz, $Qz)
    EndIf

    _cveRQDecomp3x3($iArrSrc, $out, $oArrMtxR, $oArrMtxQ, $oArrQx, $oArrQy, $oArrQz)

    If $bQzIsArray Then
        Call("_VectorOf" & $typeOfQz & "Release", $vectorQz)
    EndIf

    If $typeOfQz <> Default Then
        _cveOutputArrayRelease($oArrQz)
        If $bQzCreate Then
            Call("_cve" & $typeOfQz & "Release", $Qz)
        EndIf
    EndIf

    If $bQyIsArray Then
        Call("_VectorOf" & $typeOfQy & "Release", $vectorQy)
    EndIf

    If $typeOfQy <> Default Then
        _cveOutputArrayRelease($oArrQy)
        If $bQyCreate Then
            Call("_cve" & $typeOfQy & "Release", $Qy)
        EndIf
    EndIf

    If $bQxIsArray Then
        Call("_VectorOf" & $typeOfQx & "Release", $vectorQx)
    EndIf

    If $typeOfQx <> Default Then
        _cveOutputArrayRelease($oArrQx)
        If $bQxCreate Then
            Call("_cve" & $typeOfQx & "Release", $Qx)
        EndIf
    EndIf

    If $bMtxQIsArray Then
        Call("_VectorOf" & $typeOfMtxQ & "Release", $vectorMtxQ)
    EndIf

    If $typeOfMtxQ <> Default Then
        _cveOutputArrayRelease($oArrMtxQ)
        If $bMtxQCreate Then
            Call("_cve" & $typeOfMtxQ & "Release", $mtxQ)
        EndIf
    EndIf

    If $bMtxRIsArray Then
        Call("_VectorOf" & $typeOfMtxR & "Release", $vectorMtxR)
    EndIf

    If $typeOfMtxR <> Default Then
        _cveOutputArrayRelease($oArrMtxR)
        If $bMtxRCreate Then
            Call("_cve" & $typeOfMtxR & "Release", $mtxR)
        EndIf
    EndIf

    If $bSrcIsArray Then
        Call("_VectorOf" & $typeOfSrc & "Release", $vectorSrc)
    EndIf

    If $typeOfSrc <> Default Then
        _cveInputArrayRelease($iArrSrc)
        If $bSrcCreate Then
            Call("_cve" & $typeOfSrc & "Release", $src)
        EndIf
    EndIf
EndFunc   ;==>_cveRQDecomp3x3Typed

Func _cveRQDecomp3x3Mat($src, $out, $mtxR, $mtxQ, $Qx = _cveNoArrayMat(), $Qy = _cveNoArrayMat(), $Qz = _cveNoArrayMat())
    ; cveRQDecomp3x3 using cv::Mat instead of _*Array
    _cveRQDecomp3x3Typed("Mat", $src, $out, "Mat", $mtxR, "Mat", $mtxQ, "Mat", $Qx, "Mat", $Qy, "Mat", $Qz)
EndFunc   ;==>_cveRQDecomp3x3Mat

Func _cveDecomposeProjectionMatrix($projMatrix, $cameraMatrix, $rotMatrix, $transVect, $rotMatrixX = _cveNoArray(), $rotMatrixY = _cveNoArray(), $rotMatrixZ = _cveNoArray(), $eulerAngles = _cveNoArray())
    ; CVAPI(void) cveDecomposeProjectionMatrix(cv::_InputArray* projMatrix, cv::_OutputArray* cameraMatrix, cv::_OutputArray* rotMatrix, cv::_OutputArray* transVect, cv::_OutputArray* rotMatrixX, cv::_OutputArray* rotMatrixY, cv::_OutputArray* rotMatrixZ, cv::_OutputArray* eulerAngles);

    Local $sProjMatrixDllType
    If IsDllStruct($projMatrix) Then
        $sProjMatrixDllType = "struct*"
    Else
        $sProjMatrixDllType = "ptr"
    EndIf

    Local $sCameraMatrixDllType
    If IsDllStruct($cameraMatrix) Then
        $sCameraMatrixDllType = "struct*"
    Else
        $sCameraMatrixDllType = "ptr"
    EndIf

    Local $sRotMatrixDllType
    If IsDllStruct($rotMatrix) Then
        $sRotMatrixDllType = "struct*"
    Else
        $sRotMatrixDllType = "ptr"
    EndIf

    Local $sTransVectDllType
    If IsDllStruct($transVect) Then
        $sTransVectDllType = "struct*"
    Else
        $sTransVectDllType = "ptr"
    EndIf

    Local $sRotMatrixXDllType
    If IsDllStruct($rotMatrixX) Then
        $sRotMatrixXDllType = "struct*"
    Else
        $sRotMatrixXDllType = "ptr"
    EndIf

    Local $sRotMatrixYDllType
    If IsDllStruct($rotMatrixY) Then
        $sRotMatrixYDllType = "struct*"
    Else
        $sRotMatrixYDllType = "ptr"
    EndIf

    Local $sRotMatrixZDllType
    If IsDllStruct($rotMatrixZ) Then
        $sRotMatrixZDllType = "struct*"
    Else
        $sRotMatrixZDllType = "ptr"
    EndIf

    Local $sEulerAnglesDllType
    If IsDllStruct($eulerAngles) Then
        $sEulerAnglesDllType = "struct*"
    Else
        $sEulerAnglesDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDecomposeProjectionMatrix", $sProjMatrixDllType, $projMatrix, $sCameraMatrixDllType, $cameraMatrix, $sRotMatrixDllType, $rotMatrix, $sTransVectDllType, $transVect, $sRotMatrixXDllType, $rotMatrixX, $sRotMatrixYDllType, $rotMatrixY, $sRotMatrixZDllType, $rotMatrixZ, $sEulerAnglesDllType, $eulerAngles), "cveDecomposeProjectionMatrix", @error)
EndFunc   ;==>_cveDecomposeProjectionMatrix

Func _cveDecomposeProjectionMatrixTyped($typeOfProjMatrix, $projMatrix, $typeOfCameraMatrix, $cameraMatrix, $typeOfRotMatrix, $rotMatrix, $typeOfTransVect, $transVect, $typeOfRotMatrixX = Default, $rotMatrixX = _cveNoArray(), $typeOfRotMatrixY = Default, $rotMatrixY = _cveNoArray(), $typeOfRotMatrixZ = Default, $rotMatrixZ = _cveNoArray(), $typeOfEulerAngles = Default, $eulerAngles = _cveNoArray())

    Local $iArrProjMatrix, $vectorProjMatrix, $iArrProjMatrixSize
    Local $bProjMatrixIsArray = IsArray($projMatrix)
    Local $bProjMatrixCreate = IsDllStruct($projMatrix) And $typeOfProjMatrix == "Scalar"

    If $typeOfProjMatrix == Default Then
        $iArrProjMatrix = $projMatrix
    ElseIf $bProjMatrixIsArray Then
        $vectorProjMatrix = Call("_VectorOf" & $typeOfProjMatrix & "Create")

        $iArrProjMatrixSize = UBound($projMatrix)
        For $i = 0 To $iArrProjMatrixSize - 1
            Call("_VectorOf" & $typeOfProjMatrix & "Push", $vectorProjMatrix, $projMatrix[$i])
        Next

        $iArrProjMatrix = Call("_cveInputArrayFromVectorOf" & $typeOfProjMatrix, $vectorProjMatrix)
    Else
        If $bProjMatrixCreate Then
            $projMatrix = Call("_cve" & $typeOfProjMatrix & "Create", $projMatrix)
        EndIf
        $iArrProjMatrix = Call("_cveInputArrayFrom" & $typeOfProjMatrix, $projMatrix)
    EndIf

    Local $oArrCameraMatrix, $vectorCameraMatrix, $iArrCameraMatrixSize
    Local $bCameraMatrixIsArray = IsArray($cameraMatrix)
    Local $bCameraMatrixCreate = IsDllStruct($cameraMatrix) And $typeOfCameraMatrix == "Scalar"

    If $typeOfCameraMatrix == Default Then
        $oArrCameraMatrix = $cameraMatrix
    ElseIf $bCameraMatrixIsArray Then
        $vectorCameraMatrix = Call("_VectorOf" & $typeOfCameraMatrix & "Create")

        $iArrCameraMatrixSize = UBound($cameraMatrix)
        For $i = 0 To $iArrCameraMatrixSize - 1
            Call("_VectorOf" & $typeOfCameraMatrix & "Push", $vectorCameraMatrix, $cameraMatrix[$i])
        Next

        $oArrCameraMatrix = Call("_cveOutputArrayFromVectorOf" & $typeOfCameraMatrix, $vectorCameraMatrix)
    Else
        If $bCameraMatrixCreate Then
            $cameraMatrix = Call("_cve" & $typeOfCameraMatrix & "Create", $cameraMatrix)
        EndIf
        $oArrCameraMatrix = Call("_cveOutputArrayFrom" & $typeOfCameraMatrix, $cameraMatrix)
    EndIf

    Local $oArrRotMatrix, $vectorRotMatrix, $iArrRotMatrixSize
    Local $bRotMatrixIsArray = IsArray($rotMatrix)
    Local $bRotMatrixCreate = IsDllStruct($rotMatrix) And $typeOfRotMatrix == "Scalar"

    If $typeOfRotMatrix == Default Then
        $oArrRotMatrix = $rotMatrix
    ElseIf $bRotMatrixIsArray Then
        $vectorRotMatrix = Call("_VectorOf" & $typeOfRotMatrix & "Create")

        $iArrRotMatrixSize = UBound($rotMatrix)
        For $i = 0 To $iArrRotMatrixSize - 1
            Call("_VectorOf" & $typeOfRotMatrix & "Push", $vectorRotMatrix, $rotMatrix[$i])
        Next

        $oArrRotMatrix = Call("_cveOutputArrayFromVectorOf" & $typeOfRotMatrix, $vectorRotMatrix)
    Else
        If $bRotMatrixCreate Then
            $rotMatrix = Call("_cve" & $typeOfRotMatrix & "Create", $rotMatrix)
        EndIf
        $oArrRotMatrix = Call("_cveOutputArrayFrom" & $typeOfRotMatrix, $rotMatrix)
    EndIf

    Local $oArrTransVect, $vectorTransVect, $iArrTransVectSize
    Local $bTransVectIsArray = IsArray($transVect)
    Local $bTransVectCreate = IsDllStruct($transVect) And $typeOfTransVect == "Scalar"

    If $typeOfTransVect == Default Then
        $oArrTransVect = $transVect
    ElseIf $bTransVectIsArray Then
        $vectorTransVect = Call("_VectorOf" & $typeOfTransVect & "Create")

        $iArrTransVectSize = UBound($transVect)
        For $i = 0 To $iArrTransVectSize - 1
            Call("_VectorOf" & $typeOfTransVect & "Push", $vectorTransVect, $transVect[$i])
        Next

        $oArrTransVect = Call("_cveOutputArrayFromVectorOf" & $typeOfTransVect, $vectorTransVect)
    Else
        If $bTransVectCreate Then
            $transVect = Call("_cve" & $typeOfTransVect & "Create", $transVect)
        EndIf
        $oArrTransVect = Call("_cveOutputArrayFrom" & $typeOfTransVect, $transVect)
    EndIf

    Local $oArrRotMatrixX, $vectorRotMatrixX, $iArrRotMatrixXSize
    Local $bRotMatrixXIsArray = IsArray($rotMatrixX)
    Local $bRotMatrixXCreate = IsDllStruct($rotMatrixX) And $typeOfRotMatrixX == "Scalar"

    If $typeOfRotMatrixX == Default Then
        $oArrRotMatrixX = $rotMatrixX
    ElseIf $bRotMatrixXIsArray Then
        $vectorRotMatrixX = Call("_VectorOf" & $typeOfRotMatrixX & "Create")

        $iArrRotMatrixXSize = UBound($rotMatrixX)
        For $i = 0 To $iArrRotMatrixXSize - 1
            Call("_VectorOf" & $typeOfRotMatrixX & "Push", $vectorRotMatrixX, $rotMatrixX[$i])
        Next

        $oArrRotMatrixX = Call("_cveOutputArrayFromVectorOf" & $typeOfRotMatrixX, $vectorRotMatrixX)
    Else
        If $bRotMatrixXCreate Then
            $rotMatrixX = Call("_cve" & $typeOfRotMatrixX & "Create", $rotMatrixX)
        EndIf
        $oArrRotMatrixX = Call("_cveOutputArrayFrom" & $typeOfRotMatrixX, $rotMatrixX)
    EndIf

    Local $oArrRotMatrixY, $vectorRotMatrixY, $iArrRotMatrixYSize
    Local $bRotMatrixYIsArray = IsArray($rotMatrixY)
    Local $bRotMatrixYCreate = IsDllStruct($rotMatrixY) And $typeOfRotMatrixY == "Scalar"

    If $typeOfRotMatrixY == Default Then
        $oArrRotMatrixY = $rotMatrixY
    ElseIf $bRotMatrixYIsArray Then
        $vectorRotMatrixY = Call("_VectorOf" & $typeOfRotMatrixY & "Create")

        $iArrRotMatrixYSize = UBound($rotMatrixY)
        For $i = 0 To $iArrRotMatrixYSize - 1
            Call("_VectorOf" & $typeOfRotMatrixY & "Push", $vectorRotMatrixY, $rotMatrixY[$i])
        Next

        $oArrRotMatrixY = Call("_cveOutputArrayFromVectorOf" & $typeOfRotMatrixY, $vectorRotMatrixY)
    Else
        If $bRotMatrixYCreate Then
            $rotMatrixY = Call("_cve" & $typeOfRotMatrixY & "Create", $rotMatrixY)
        EndIf
        $oArrRotMatrixY = Call("_cveOutputArrayFrom" & $typeOfRotMatrixY, $rotMatrixY)
    EndIf

    Local $oArrRotMatrixZ, $vectorRotMatrixZ, $iArrRotMatrixZSize
    Local $bRotMatrixZIsArray = IsArray($rotMatrixZ)
    Local $bRotMatrixZCreate = IsDllStruct($rotMatrixZ) And $typeOfRotMatrixZ == "Scalar"

    If $typeOfRotMatrixZ == Default Then
        $oArrRotMatrixZ = $rotMatrixZ
    ElseIf $bRotMatrixZIsArray Then
        $vectorRotMatrixZ = Call("_VectorOf" & $typeOfRotMatrixZ & "Create")

        $iArrRotMatrixZSize = UBound($rotMatrixZ)
        For $i = 0 To $iArrRotMatrixZSize - 1
            Call("_VectorOf" & $typeOfRotMatrixZ & "Push", $vectorRotMatrixZ, $rotMatrixZ[$i])
        Next

        $oArrRotMatrixZ = Call("_cveOutputArrayFromVectorOf" & $typeOfRotMatrixZ, $vectorRotMatrixZ)
    Else
        If $bRotMatrixZCreate Then
            $rotMatrixZ = Call("_cve" & $typeOfRotMatrixZ & "Create", $rotMatrixZ)
        EndIf
        $oArrRotMatrixZ = Call("_cveOutputArrayFrom" & $typeOfRotMatrixZ, $rotMatrixZ)
    EndIf

    Local $oArrEulerAngles, $vectorEulerAngles, $iArrEulerAnglesSize
    Local $bEulerAnglesIsArray = IsArray($eulerAngles)
    Local $bEulerAnglesCreate = IsDllStruct($eulerAngles) And $typeOfEulerAngles == "Scalar"

    If $typeOfEulerAngles == Default Then
        $oArrEulerAngles = $eulerAngles
    ElseIf $bEulerAnglesIsArray Then
        $vectorEulerAngles = Call("_VectorOf" & $typeOfEulerAngles & "Create")

        $iArrEulerAnglesSize = UBound($eulerAngles)
        For $i = 0 To $iArrEulerAnglesSize - 1
            Call("_VectorOf" & $typeOfEulerAngles & "Push", $vectorEulerAngles, $eulerAngles[$i])
        Next

        $oArrEulerAngles = Call("_cveOutputArrayFromVectorOf" & $typeOfEulerAngles, $vectorEulerAngles)
    Else
        If $bEulerAnglesCreate Then
            $eulerAngles = Call("_cve" & $typeOfEulerAngles & "Create", $eulerAngles)
        EndIf
        $oArrEulerAngles = Call("_cveOutputArrayFrom" & $typeOfEulerAngles, $eulerAngles)
    EndIf

    _cveDecomposeProjectionMatrix($iArrProjMatrix, $oArrCameraMatrix, $oArrRotMatrix, $oArrTransVect, $oArrRotMatrixX, $oArrRotMatrixY, $oArrRotMatrixZ, $oArrEulerAngles)

    If $bEulerAnglesIsArray Then
        Call("_VectorOf" & $typeOfEulerAngles & "Release", $vectorEulerAngles)
    EndIf

    If $typeOfEulerAngles <> Default Then
        _cveOutputArrayRelease($oArrEulerAngles)
        If $bEulerAnglesCreate Then
            Call("_cve" & $typeOfEulerAngles & "Release", $eulerAngles)
        EndIf
    EndIf

    If $bRotMatrixZIsArray Then
        Call("_VectorOf" & $typeOfRotMatrixZ & "Release", $vectorRotMatrixZ)
    EndIf

    If $typeOfRotMatrixZ <> Default Then
        _cveOutputArrayRelease($oArrRotMatrixZ)
        If $bRotMatrixZCreate Then
            Call("_cve" & $typeOfRotMatrixZ & "Release", $rotMatrixZ)
        EndIf
    EndIf

    If $bRotMatrixYIsArray Then
        Call("_VectorOf" & $typeOfRotMatrixY & "Release", $vectorRotMatrixY)
    EndIf

    If $typeOfRotMatrixY <> Default Then
        _cveOutputArrayRelease($oArrRotMatrixY)
        If $bRotMatrixYCreate Then
            Call("_cve" & $typeOfRotMatrixY & "Release", $rotMatrixY)
        EndIf
    EndIf

    If $bRotMatrixXIsArray Then
        Call("_VectorOf" & $typeOfRotMatrixX & "Release", $vectorRotMatrixX)
    EndIf

    If $typeOfRotMatrixX <> Default Then
        _cveOutputArrayRelease($oArrRotMatrixX)
        If $bRotMatrixXCreate Then
            Call("_cve" & $typeOfRotMatrixX & "Release", $rotMatrixX)
        EndIf
    EndIf

    If $bTransVectIsArray Then
        Call("_VectorOf" & $typeOfTransVect & "Release", $vectorTransVect)
    EndIf

    If $typeOfTransVect <> Default Then
        _cveOutputArrayRelease($oArrTransVect)
        If $bTransVectCreate Then
            Call("_cve" & $typeOfTransVect & "Release", $transVect)
        EndIf
    EndIf

    If $bRotMatrixIsArray Then
        Call("_VectorOf" & $typeOfRotMatrix & "Release", $vectorRotMatrix)
    EndIf

    If $typeOfRotMatrix <> Default Then
        _cveOutputArrayRelease($oArrRotMatrix)
        If $bRotMatrixCreate Then
            Call("_cve" & $typeOfRotMatrix & "Release", $rotMatrix)
        EndIf
    EndIf

    If $bCameraMatrixIsArray Then
        Call("_VectorOf" & $typeOfCameraMatrix & "Release", $vectorCameraMatrix)
    EndIf

    If $typeOfCameraMatrix <> Default Then
        _cveOutputArrayRelease($oArrCameraMatrix)
        If $bCameraMatrixCreate Then
            Call("_cve" & $typeOfCameraMatrix & "Release", $cameraMatrix)
        EndIf
    EndIf

    If $bProjMatrixIsArray Then
        Call("_VectorOf" & $typeOfProjMatrix & "Release", $vectorProjMatrix)
    EndIf

    If $typeOfProjMatrix <> Default Then
        _cveInputArrayRelease($iArrProjMatrix)
        If $bProjMatrixCreate Then
            Call("_cve" & $typeOfProjMatrix & "Release", $projMatrix)
        EndIf
    EndIf
EndFunc   ;==>_cveDecomposeProjectionMatrixTyped

Func _cveDecomposeProjectionMatrixMat($projMatrix, $cameraMatrix, $rotMatrix, $transVect, $rotMatrixX = _cveNoArrayMat(), $rotMatrixY = _cveNoArrayMat(), $rotMatrixZ = _cveNoArrayMat(), $eulerAngles = _cveNoArrayMat())
    ; cveDecomposeProjectionMatrix using cv::Mat instead of _*Array
    _cveDecomposeProjectionMatrixTyped("Mat", $projMatrix, "Mat", $cameraMatrix, "Mat", $rotMatrix, "Mat", $transVect, "Mat", $rotMatrixX, "Mat", $rotMatrixY, "Mat", $rotMatrixZ, "Mat", $eulerAngles)
EndFunc   ;==>_cveDecomposeProjectionMatrixMat