#include-once
#include "..\CVEUtils.au3"

Func _VectorOfDMatchPushMatrix($matches, $trainIdx, $distance = 0, $mask = 0)
    ; CVAPI(void) VectorOfDMatchPushMatrix(std::vector<cv::DMatch>* matches, const CvMat* trainIdx, const CvMat* distance = 0, const CvMat* mask = 0);

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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bTrainIdxDllType
    If VarGetType($trainIdx) == "DLLStruct" Then
        $bTrainIdxDllType = "struct*"
    Else
        $bTrainIdxDllType = "ptr"
    EndIf

    Local $bDistanceDllType
    If VarGetType($distance) == "DLLStruct" Then
        $bDistanceDllType = "struct*"
    Else
        $bDistanceDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchPushMatrix", $bMatchesDllType, $vecMatches, $bTrainIdxDllType, $trainIdx, $bDistanceDllType, $distance, $bMaskDllType, $mask), "VectorOfDMatchPushMatrix", @error)

    If $bMatchesIsArray Then
        _VectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_VectorOfDMatchPushMatrix

Func _VectorOfDMatchToMat($matches, $trainIdx, $distance)
    ; CVAPI(void) VectorOfDMatchToMat(std::vector<std::vector<cv::DMatch>>* matches, CvMat* trainIdx, CvMat* distance);

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

    Local $bMatchesDllType
    If VarGetType($matches) == "DLLStruct" Then
        $bMatchesDllType = "struct*"
    Else
        $bMatchesDllType = "ptr"
    EndIf

    Local $bTrainIdxDllType
    If VarGetType($trainIdx) == "DLLStruct" Then
        $bTrainIdxDllType = "struct*"
    Else
        $bTrainIdxDllType = "ptr"
    EndIf

    Local $bDistanceDllType
    If VarGetType($distance) == "DLLStruct" Then
        $bDistanceDllType = "struct*"
    Else
        $bDistanceDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfDMatchToMat", $bMatchesDllType, $vecMatches, $bTrainIdxDllType, $trainIdx, $bDistanceDllType, $distance), "VectorOfDMatchToMat", @error)

    If $bMatchesIsArray Then
        _VectorOfVectorOfDMatchRelease($vecMatches)
    EndIf
EndFunc   ;==>_VectorOfDMatchToMat

Func _VectorOfKeyPointFilterByImageBorder($keypoints, $imageSize, $borderSize)
    ; CVAPI(void) VectorOfKeyPointFilterByImageBorder(std::vector<cv::KeyPoint>* keypoints, CvSize imageSize, int borderSize);

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointFilterByImageBorder", $bKeypointsDllType, $vecKeypoints, "ptr", $imageSize, "int", $borderSize), "VectorOfKeyPointFilterByImageBorder", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_VectorOfKeyPointFilterByImageBorder

Func _VectorOfKeyPointFilterByKeypointSize($keypoints, $minSize, $maxSize)
    ; CVAPI(void) VectorOfKeyPointFilterByKeypointSize(std::vector<cv::KeyPoint>* keypoints, float minSize, float maxSize);

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointFilterByKeypointSize", $bKeypointsDllType, $vecKeypoints, "float", $minSize, "float", $maxSize), "VectorOfKeyPointFilterByKeypointSize", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_VectorOfKeyPointFilterByKeypointSize

Func _VectorOfKeyPointFilterByPixelsMask($keypoints, $mask)
    ; CVAPI(void) VectorOfKeyPointFilterByPixelsMask(std::vector<cv::KeyPoint>* keypoints, CvMat* mask);

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

    Local $bKeypointsDllType
    If VarGetType($keypoints) == "DLLStruct" Then
        $bKeypointsDllType = "struct*"
    Else
        $bKeypointsDllType = "ptr"
    EndIf

    Local $bMaskDllType
    If VarGetType($mask) == "DLLStruct" Then
        $bMaskDllType = "struct*"
    Else
        $bMaskDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "VectorOfKeyPointFilterByPixelsMask", $bKeypointsDllType, $vecKeypoints, $bMaskDllType, $mask), "VectorOfKeyPointFilterByPixelsMask", @error)

    If $bKeypointsIsArray Then
        _VectorOfKeyPointRelease($vecKeypoints)
    EndIf
EndFunc   ;==>_VectorOfKeyPointFilterByPixelsMask