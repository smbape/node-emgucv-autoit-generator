#include-once
#include "..\CVEUtils.au3"

Func _VectorOfDMatchPushMatrix($matches, $trainIdx, $distance = 0, $mask = 0)
    ; CVAPI(void) VectorOfDMatchPushMatrix(std::vector<cv::DMatch>* matches, const CvMat* trainIdx, const CvMat* distance = 0, const CvMat* mask = 0);

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

    Local $sTrainIdxDllType
    If IsDllStruct($trainIdx) Then
        $sTrainIdxDllType = "struct*"
    Else
        $sTrainIdxDllType = "ptr"
    EndIf

    Local $sDistanceDllType
    If IsDllStruct($distance) Then
        $sDistanceDllType = "struct*"
    Else
        $sDistanceDllType = "ptr"
    EndIf

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchPushMatrix", $sMatchesDllType, $vecMatches, $sTrainIdxDllType, $trainIdx, $sDistanceDllType, $distance, $sMaskDllType, $mask), "VectorOfDMatchPushMatrix", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_VectorOfDMatchPushMatrix

Func _VectorOfDMatchToMat($matches, $trainIdx, $distance)
    ; CVAPI(void) VectorOfDMatchToMat(std::vector<std::vector<cv::DMatch>>* matches, CvMat* trainIdx, CvMat* distance);

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

    Local $sTrainIdxDllType
    If IsDllStruct($trainIdx) Then
        $sTrainIdxDllType = "struct*"
    Else
        $sTrainIdxDllType = "ptr"
    EndIf

    Local $sDistanceDllType
    If IsDllStruct($distance) Then
        $sDistanceDllType = "struct*"
    Else
        $sDistanceDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchToMat", $sMatchesDllType, $vecMatches, $sTrainIdxDllType, $trainIdx, $sDistanceDllType, $distance), "VectorOfDMatchToMat", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_VectorOfDMatchToMat

Func _VectorOfKeyPointFilterByImageBorder($keypoints, $imageSize, $borderSize)
    ; CVAPI(void) VectorOfKeyPointFilterByImageBorder(std::vector<cv::KeyPoint>* keypoints, CvSize imageSize, int borderSize);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointFilterByImageBorder", $sKeypointsDllType, $vecKeypoints, "ptr", $imageSize, "int", $borderSize), "VectorOfKeyPointFilterByImageBorder", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_VectorOfKeyPointFilterByImageBorder

Func _VectorOfKeyPointFilterByKeypointSize($keypoints, $minSize, $maxSize)
    ; CVAPI(void) VectorOfKeyPointFilterByKeypointSize(std::vector<cv::KeyPoint>* keypoints, float minSize, float maxSize);

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

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointFilterByKeypointSize", $sKeypointsDllType, $vecKeypoints, "float", $minSize, "float", $maxSize), "VectorOfKeyPointFilterByKeypointSize", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_VectorOfKeyPointFilterByKeypointSize

Func _VectorOfKeyPointFilterByPixelsMask($keypoints, $mask)
    ; CVAPI(void) VectorOfKeyPointFilterByPixelsMask(std::vector<cv::KeyPoint>* keypoints, CvMat* mask);

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

    Local $sMaskDllType
    If IsDllStruct($mask) Then
        $sMaskDllType = "struct*"
    Else
        $sMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointFilterByPixelsMask", $sKeypointsDllType, $vecKeypoints, $sMaskDllType, $mask), "VectorOfKeyPointFilterByPixelsMask", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_VectorOfKeyPointFilterByPixelsMask