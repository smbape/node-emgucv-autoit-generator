#include-once
#include "..\..\CVEUtils.au3"

Func _cveImshow($winname, $mat)
    ; CVAPI(void) cveImshow(cv::String* winname, cv::_InputArray* mat);

    Local $bWinnameIsString = IsString($winname)
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    Local $sMatDllType
    If IsDllStruct($mat) Then
        $sMatDllType = "struct*"
    Else
        $sMatDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveImshow", $sWinnameDllType, $winname, $sMatDllType, $mat), "cveImshow", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveImshow

Func _cveImshowTyped($winname, $typeOfMat, $mat)

    Local $iArrMat, $vectorMat, $iArrMatSize
    Local $bMatIsArray = IsArray($mat)
    Local $bMatCreate = IsDllStruct($mat) And $typeOfMat == "Scalar"

    If $typeOfMat == Default Then
        $iArrMat = $mat
    ElseIf $bMatIsArray Then
        $vectorMat = Call("_VectorOf" & $typeOfMat & "Create")

        $iArrMatSize = UBound($mat)
        For $i = 0 To $iArrMatSize - 1
            Call("_VectorOf" & $typeOfMat & "Push", $vectorMat, $mat[$i])
        Next

        $iArrMat = Call("_cveInputArrayFromVectorOf" & $typeOfMat, $vectorMat)
    Else
        If $bMatCreate Then
            $mat = Call("_cve" & $typeOfMat & "Create", $mat)
        EndIf
        $iArrMat = Call("_cveInputArrayFrom" & $typeOfMat, $mat)
    EndIf

    _cveImshow($winname, $iArrMat)

    If $bMatIsArray Then
        Call("_VectorOf" & $typeOfMat & "Release", $vectorMat)
    EndIf

    If $typeOfMat <> Default Then
        _cveInputArrayRelease($iArrMat)
        If $bMatCreate Then
            Call("_cve" & $typeOfMat & "Release", $mat)
        EndIf
    EndIf
EndFunc   ;==>_cveImshowTyped

Func _cveImshowMat($winname, $mat)
    ; cveImshow using cv::Mat instead of _*Array
    _cveImshowTyped($winname, "Mat", $mat)
EndFunc   ;==>_cveImshowMat

Func _cveNamedWindow($winname, $flags = $CV_WINDOW_AUTOSIZE)
    ; CVAPI(void) cveNamedWindow(cv::String* winname, int flags);

    Local $bWinnameIsString = IsString($winname)
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveNamedWindow", $sWinnameDllType, $winname, "int", $flags), "cveNamedWindow", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveNamedWindow

Func _cveSetWindowProperty($winname, $propId, $propValue)
    ; CVAPI(void) cveSetWindowProperty(cv::String* winname, int propId, double propValue);

    Local $bWinnameIsString = IsString($winname)
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetWindowProperty", $sWinnameDllType, $winname, "int", $propId, "double", $propValue), "cveSetWindowProperty", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveSetWindowProperty

Func _cveSetWindowTitle($winname, $title)
    ; CVAPI(void) cveSetWindowTitle(cv::String* winname, cv::String* title);

    Local $bWinnameIsString = IsString($winname)
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    Local $bTitleIsString = IsString($title)
    If $bTitleIsString Then
        $title = _cveStringCreateFromStr($title)
    EndIf

    Local $sTitleDllType
    If IsDllStruct($title) Then
        $sTitleDllType = "struct*"
    Else
        $sTitleDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSetWindowTitle", $sWinnameDllType, $winname, $sTitleDllType, $title), "cveSetWindowTitle", @error)

    If $bTitleIsString Then
        _cveStringRelease($title)
    EndIf

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveSetWindowTitle

Func _cveGetWindowProperty($winname, $propId)
    ; CVAPI(double) cveGetWindowProperty(cv::String* winname, int propId);

    Local $bWinnameIsString = IsString($winname)
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "double:cdecl", "cveGetWindowProperty", $sWinnameDllType, $winname, "int", $propId), "cveGetWindowProperty", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf

    Return $retval
EndFunc   ;==>_cveGetWindowProperty

Func _cveDestroyWindow($winname)
    ; CVAPI(void) cveDestroyWindow(cv::String* winname);

    Local $bWinnameIsString = IsString($winname)
    If $bWinnameIsString Then
        $winname = _cveStringCreateFromStr($winname)
    EndIf

    Local $sWinnameDllType
    If IsDllStruct($winname) Then
        $sWinnameDllType = "struct*"
    Else
        $sWinnameDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDestroyWindow", $sWinnameDllType, $winname), "cveDestroyWindow", @error)

    If $bWinnameIsString Then
        _cveStringRelease($winname)
    EndIf
EndFunc   ;==>_cveDestroyWindow

Func _cveDestroyAllWindows()
    ; CVAPI(void) cveDestroyAllWindows();
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveDestroyAllWindows"), "cveDestroyAllWindows", @error)
EndFunc   ;==>_cveDestroyAllWindows

Func _cveWaitKey($delay = 0)
    ; CVAPI(int) cveWaitKey(int delay);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveWaitKey", "int", $delay), "cveWaitKey", @error)
EndFunc   ;==>_cveWaitKey

Func _cvePollKey()
    ; CVAPI(int) cvePollKey();
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cvePollKey"), "cvePollKey", @error)
EndFunc   ;==>_cvePollKey

Func _cveSelectROI($windowName, $img, $showCrosshair, $fromCenter, $roi)
    ; CVAPI(void) cveSelectROI(cv::String* windowName, cv::_InputArray* img, bool showCrosshair, bool fromCenter, CvRect* roi);

    Local $bWindowNameIsString = IsString($windowName)
    If $bWindowNameIsString Then
        $windowName = _cveStringCreateFromStr($windowName)
    EndIf

    Local $sWindowNameDllType
    If IsDllStruct($windowName) Then
        $sWindowNameDllType = "struct*"
    Else
        $sWindowNameDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $sRoiDllType
    If IsDllStruct($roi) Then
        $sRoiDllType = "struct*"
    Else
        $sRoiDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectROI", $sWindowNameDllType, $windowName, $sImgDllType, $img, "boolean", $showCrosshair, "boolean", $fromCenter, $sRoiDllType, $roi), "cveSelectROI", @error)

    If $bWindowNameIsString Then
        _cveStringRelease($windowName)
    EndIf
EndFunc   ;==>_cveSelectROI

Func _cveSelectROITyped($windowName, $typeOfImg, $img, $showCrosshair, $fromCenter, $roi)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveSelectROI($windowName, $iArrImg, $showCrosshair, $fromCenter, $roi)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveSelectROITyped

Func _cveSelectROIMat($windowName, $img, $showCrosshair, $fromCenter, $roi)
    ; cveSelectROI using cv::Mat instead of _*Array
    _cveSelectROITyped($windowName, "Mat", $img, $showCrosshair, $fromCenter, $roi)
EndFunc   ;==>_cveSelectROIMat

Func _cveSelectROIs($windowName, $img, $boundingBoxs, $showCrosshair = true, $fromCenter = false)
    ; CVAPI(void) cveSelectROIs(cv::String* windowName, cv::_InputArray* img, std::vector<cv::Rect>* boundingBoxs, bool showCrosshair, bool fromCenter);

    Local $bWindowNameIsString = IsString($windowName)
    If $bWindowNameIsString Then
        $windowName = _cveStringCreateFromStr($windowName)
    EndIf

    Local $sWindowNameDllType
    If IsDllStruct($windowName) Then
        $sWindowNameDllType = "struct*"
    Else
        $sWindowNameDllType = "ptr"
    EndIf

    Local $sImgDllType
    If IsDllStruct($img) Then
        $sImgDllType = "struct*"
    Else
        $sImgDllType = "ptr"
    EndIf

    Local $vecBoundingBoxs, $iArrBoundingBoxsSize
    Local $bBoundingBoxsIsArray = IsArray($boundingBoxs)

    If $bBoundingBoxsIsArray Then
        $vecBoundingBoxs = _VectorOfRectCreate()

        $iArrBoundingBoxsSize = UBound($boundingBoxs)
        For $i = 0 To $iArrBoundingBoxsSize - 1
            _VectorOfRectPush($vecBoundingBoxs, $boundingBoxs[$i])
        Next
    Else
        $vecBoundingBoxs = $boundingBoxs
    EndIf

    Local $sBoundingBoxsDllType
    If IsDllStruct($boundingBoxs) Then
        $sBoundingBoxsDllType = "struct*"
    Else
        $sBoundingBoxsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSelectROIs", $sWindowNameDllType, $windowName, $sImgDllType, $img, $sBoundingBoxsDllType, $vecBoundingBoxs, "boolean", $showCrosshair, "boolean", $fromCenter), "cveSelectROIs", @error)

    If $bBoundingBoxsIsArray Then
        _VectorOfRectRelease($vecBoundingBoxs)
    EndIf

    If $bWindowNameIsString Then
        _cveStringRelease($windowName)
    EndIf
EndFunc   ;==>_cveSelectROIs

Func _cveSelectROIsTyped($windowName, $typeOfImg, $img, $boundingBoxs, $showCrosshair = true, $fromCenter = false)

    Local $iArrImg, $vectorImg, $iArrImgSize
    Local $bImgIsArray = IsArray($img)
    Local $bImgCreate = IsDllStruct($img) And $typeOfImg == "Scalar"

    If $typeOfImg == Default Then
        $iArrImg = $img
    ElseIf $bImgIsArray Then
        $vectorImg = Call("_VectorOf" & $typeOfImg & "Create")

        $iArrImgSize = UBound($img)
        For $i = 0 To $iArrImgSize - 1
            Call("_VectorOf" & $typeOfImg & "Push", $vectorImg, $img[$i])
        Next

        $iArrImg = Call("_cveInputArrayFromVectorOf" & $typeOfImg, $vectorImg)
    Else
        If $bImgCreate Then
            $img = Call("_cve" & $typeOfImg & "Create", $img)
        EndIf
        $iArrImg = Call("_cveInputArrayFrom" & $typeOfImg, $img)
    EndIf

    _cveSelectROIs($windowName, $iArrImg, $boundingBoxs, $showCrosshair, $fromCenter)

    If $bImgIsArray Then
        Call("_VectorOf" & $typeOfImg & "Release", $vectorImg)
    EndIf

    If $typeOfImg <> Default Then
        _cveInputArrayRelease($iArrImg)
        If $bImgCreate Then
            Call("_cve" & $typeOfImg & "Release", $img)
        EndIf
    EndIf
EndFunc   ;==>_cveSelectROIsTyped

Func _cveSelectROIsMat($windowName, $img, $boundingBoxs, $showCrosshair = true, $fromCenter = false)
    ; cveSelectROIs using cv::Mat instead of _*Array
    _cveSelectROIsTyped($windowName, "Mat", $img, $boundingBoxs, $showCrosshair, $fromCenter)
EndFunc   ;==>_cveSelectROIsMat