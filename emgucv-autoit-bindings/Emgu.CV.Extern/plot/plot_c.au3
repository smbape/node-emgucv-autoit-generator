#include-once
#include "..\..\CVEUtils.au3"

Func _cvePlot2dCreateFrom($data, $sharedPtr)
    ; CVAPI(cv::plot::Plot2d*) cvePlot2dCreateFrom(cv::_InputArray* data, cv::Ptr<cv::plot::Plot2d>** sharedPtr);

    Local $sDataDllType
    If IsDllStruct($data) Then
        $sDataDllType = "struct*"
    Else
        $sDataDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlot2dCreateFrom", $sDataDllType, $data, $sSharedPtrDllType, $sharedPtr), "cvePlot2dCreateFrom", @error)
EndFunc   ;==>_cvePlot2dCreateFrom

Func _cvePlot2dCreateFromTyped($typeOfData, $data, $sharedPtr)

    Local $iArrData, $vectorData, $iArrDataSize
    Local $bDataIsArray = IsArray($data)
    Local $bDataCreate = IsDllStruct($data) And $typeOfData == "Scalar"

    If $typeOfData == Default Then
        $iArrData = $data
    ElseIf $bDataIsArray Then
        $vectorData = Call("_VectorOf" & $typeOfData & "Create")

        $iArrDataSize = UBound($data)
        For $i = 0 To $iArrDataSize - 1
            Call("_VectorOf" & $typeOfData & "Push", $vectorData, $data[$i])
        Next

        $iArrData = Call("_cveInputArrayFromVectorOf" & $typeOfData, $vectorData)
    Else
        If $bDataCreate Then
            $data = Call("_cve" & $typeOfData & "Create", $data)
        EndIf
        $iArrData = Call("_cveInputArrayFrom" & $typeOfData, $data)
    EndIf

    Local $retval = _cvePlot2dCreateFrom($iArrData, $sharedPtr)

    If $bDataIsArray Then
        Call("_VectorOf" & $typeOfData & "Release", $vectorData)
    EndIf

    If $typeOfData <> Default Then
        _cveInputArrayRelease($iArrData)
        If $bDataCreate Then
            Call("_cve" & $typeOfData & "Release", $data)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cvePlot2dCreateFromTyped

Func _cvePlot2dCreateFromMat($data, $sharedPtr)
    ; cvePlot2dCreateFrom using cv::Mat instead of _*Array
    Local $retval = _cvePlot2dCreateFromTyped("Mat", $data, $sharedPtr)

    Return $retval
EndFunc   ;==>_cvePlot2dCreateFromMat

Func _cvePlot2dCreateFromXY($dataX, $dataY, $sharedPtr)
    ; CVAPI(cv::plot::Plot2d*) cvePlot2dCreateFromXY(cv::_InputArray* dataX, cv::_InputArray* dataY, cv::Ptr<cv::plot::Plot2d>** sharedPtr);

    Local $sDataXDllType
    If IsDllStruct($dataX) Then
        $sDataXDllType = "struct*"
    Else
        $sDataXDllType = "ptr"
    EndIf

    Local $sDataYDllType
    If IsDllStruct($dataY) Then
        $sDataYDllType = "struct*"
    Else
        $sDataYDllType = "ptr"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cvePlot2dCreateFromXY", $sDataXDllType, $dataX, $sDataYDllType, $dataY, $sSharedPtrDllType, $sharedPtr), "cvePlot2dCreateFromXY", @error)
EndFunc   ;==>_cvePlot2dCreateFromXY

Func _cvePlot2dCreateFromXYTyped($typeOfDataX, $dataX, $typeOfDataY, $dataY, $sharedPtr)

    Local $iArrDataX, $vectorDataX, $iArrDataXSize
    Local $bDataXIsArray = IsArray($dataX)
    Local $bDataXCreate = IsDllStruct($dataX) And $typeOfDataX == "Scalar"

    If $typeOfDataX == Default Then
        $iArrDataX = $dataX
    ElseIf $bDataXIsArray Then
        $vectorDataX = Call("_VectorOf" & $typeOfDataX & "Create")

        $iArrDataXSize = UBound($dataX)
        For $i = 0 To $iArrDataXSize - 1
            Call("_VectorOf" & $typeOfDataX & "Push", $vectorDataX, $dataX[$i])
        Next

        $iArrDataX = Call("_cveInputArrayFromVectorOf" & $typeOfDataX, $vectorDataX)
    Else
        If $bDataXCreate Then
            $dataX = Call("_cve" & $typeOfDataX & "Create", $dataX)
        EndIf
        $iArrDataX = Call("_cveInputArrayFrom" & $typeOfDataX, $dataX)
    EndIf

    Local $iArrDataY, $vectorDataY, $iArrDataYSize
    Local $bDataYIsArray = IsArray($dataY)
    Local $bDataYCreate = IsDllStruct($dataY) And $typeOfDataY == "Scalar"

    If $typeOfDataY == Default Then
        $iArrDataY = $dataY
    ElseIf $bDataYIsArray Then
        $vectorDataY = Call("_VectorOf" & $typeOfDataY & "Create")

        $iArrDataYSize = UBound($dataY)
        For $i = 0 To $iArrDataYSize - 1
            Call("_VectorOf" & $typeOfDataY & "Push", $vectorDataY, $dataY[$i])
        Next

        $iArrDataY = Call("_cveInputArrayFromVectorOf" & $typeOfDataY, $vectorDataY)
    Else
        If $bDataYCreate Then
            $dataY = Call("_cve" & $typeOfDataY & "Create", $dataY)
        EndIf
        $iArrDataY = Call("_cveInputArrayFrom" & $typeOfDataY, $dataY)
    EndIf

    Local $retval = _cvePlot2dCreateFromXY($iArrDataX, $iArrDataY, $sharedPtr)

    If $bDataYIsArray Then
        Call("_VectorOf" & $typeOfDataY & "Release", $vectorDataY)
    EndIf

    If $typeOfDataY <> Default Then
        _cveInputArrayRelease($iArrDataY)
        If $bDataYCreate Then
            Call("_cve" & $typeOfDataY & "Release", $dataY)
        EndIf
    EndIf

    If $bDataXIsArray Then
        Call("_VectorOf" & $typeOfDataX & "Release", $vectorDataX)
    EndIf

    If $typeOfDataX <> Default Then
        _cveInputArrayRelease($iArrDataX)
        If $bDataXCreate Then
            Call("_cve" & $typeOfDataX & "Release", $dataX)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cvePlot2dCreateFromXYTyped

Func _cvePlot2dCreateFromXYMat($dataX, $dataY, $sharedPtr)
    ; cvePlot2dCreateFromXY using cv::Mat instead of _*Array
    Local $retval = _cvePlot2dCreateFromXYTyped("Mat", $dataX, "Mat", $dataY, $sharedPtr)

    Return $retval
EndFunc   ;==>_cvePlot2dCreateFromXYMat

Func _cvePlot2dRender($plot, $result)
    ; CVAPI(void) cvePlot2dRender(cv::plot::Plot2d* plot, cv::_OutputArray* result);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    Else
        $sPlotDllType = "ptr"
    EndIf

    Local $sResultDllType
    If IsDllStruct($result) Then
        $sResultDllType = "struct*"
    Else
        $sResultDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dRender", $sPlotDllType, $plot, $sResultDllType, $result), "cvePlot2dRender", @error)
EndFunc   ;==>_cvePlot2dRender

Func _cvePlot2dRenderTyped($plot, $typeOfResult, $result)

    Local $oArrResult, $vectorResult, $iArrResultSize
    Local $bResultIsArray = IsArray($result)
    Local $bResultCreate = IsDllStruct($result) And $typeOfResult == "Scalar"

    If $typeOfResult == Default Then
        $oArrResult = $result
    ElseIf $bResultIsArray Then
        $vectorResult = Call("_VectorOf" & $typeOfResult & "Create")

        $iArrResultSize = UBound($result)
        For $i = 0 To $iArrResultSize - 1
            Call("_VectorOf" & $typeOfResult & "Push", $vectorResult, $result[$i])
        Next

        $oArrResult = Call("_cveOutputArrayFromVectorOf" & $typeOfResult, $vectorResult)
    Else
        If $bResultCreate Then
            $result = Call("_cve" & $typeOfResult & "Create", $result)
        EndIf
        $oArrResult = Call("_cveOutputArrayFrom" & $typeOfResult, $result)
    EndIf

    _cvePlot2dRender($plot, $oArrResult)

    If $bResultIsArray Then
        Call("_VectorOf" & $typeOfResult & "Release", $vectorResult)
    EndIf

    If $typeOfResult <> Default Then
        _cveOutputArrayRelease($oArrResult)
        If $bResultCreate Then
            Call("_cve" & $typeOfResult & "Release", $result)
        EndIf
    EndIf
EndFunc   ;==>_cvePlot2dRenderTyped

Func _cvePlot2dRenderMat($plot, $result)
    ; cvePlot2dRender using cv::Mat instead of _*Array
    _cvePlot2dRenderTyped($plot, "Mat", $result)
EndFunc   ;==>_cvePlot2dRenderMat

Func _cvePlot2dRelease($plot, $sharedPtr)
    ; CVAPI(void) cvePlot2dRelease(cv::plot::Plot2d** plot, cv::Ptr<cv::plot::Plot2d>** sharedPtr);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    ElseIf $plot == Null Then
        $sPlotDllType = "ptr"
    Else
        $sPlotDllType = "ptr*"
    EndIf

    Local $sSharedPtrDllType
    If IsDllStruct($sharedPtr) Then
        $sSharedPtrDllType = "struct*"
    ElseIf $sharedPtr == Null Then
        $sSharedPtrDllType = "ptr"
    Else
        $sSharedPtrDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dRelease", $sPlotDllType, $plot, $sSharedPtrDllType, $sharedPtr), "cvePlot2dRelease", @error)
EndFunc   ;==>_cvePlot2dRelease

Func _cvePlot2dSetPlotLineColor($plot, $plotLineColor)
    ; CVAPI(void) cvePlot2dSetPlotLineColor(cv::plot::Plot2d* plot, CvScalar* plotLineColor);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    Else
        $sPlotDllType = "ptr"
    EndIf

    Local $sPlotLineColorDllType
    If IsDllStruct($plotLineColor) Then
        $sPlotLineColorDllType = "struct*"
    Else
        $sPlotLineColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotLineColor", $sPlotDllType, $plot, $sPlotLineColorDllType, $plotLineColor), "cvePlot2dSetPlotLineColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotLineColor

Func _cvePlot2dSetPlotBackgroundColor($plot, $plotBackgroundColor)
    ; CVAPI(void) cvePlot2dSetPlotBackgroundColor(cv::plot::Plot2d* plot, CvScalar* plotBackgroundColor);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    Else
        $sPlotDllType = "ptr"
    EndIf

    Local $sPlotBackgroundColorDllType
    If IsDllStruct($plotBackgroundColor) Then
        $sPlotBackgroundColorDllType = "struct*"
    Else
        $sPlotBackgroundColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotBackgroundColor", $sPlotDllType, $plot, $sPlotBackgroundColorDllType, $plotBackgroundColor), "cvePlot2dSetPlotBackgroundColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotBackgroundColor

Func _cvePlot2dSetPlotAxisColor($plot, $plotAxisColor)
    ; CVAPI(void) cvePlot2dSetPlotAxisColor(cv::plot::Plot2d* plot, CvScalar* plotAxisColor);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    Else
        $sPlotDllType = "ptr"
    EndIf

    Local $sPlotAxisColorDllType
    If IsDllStruct($plotAxisColor) Then
        $sPlotAxisColorDllType = "struct*"
    Else
        $sPlotAxisColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotAxisColor", $sPlotDllType, $plot, $sPlotAxisColorDllType, $plotAxisColor), "cvePlot2dSetPlotAxisColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotAxisColor

Func _cvePlot2dSetPlotGridColor($plot, $plotGridColor)
    ; CVAPI(void) cvePlot2dSetPlotGridColor(cv::plot::Plot2d* plot, CvScalar* plotGridColor);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    Else
        $sPlotDllType = "ptr"
    EndIf

    Local $sPlotGridColorDllType
    If IsDllStruct($plotGridColor) Then
        $sPlotGridColorDllType = "struct*"
    Else
        $sPlotGridColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotGridColor", $sPlotDllType, $plot, $sPlotGridColorDllType, $plotGridColor), "cvePlot2dSetPlotGridColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotGridColor

Func _cvePlot2dSetPlotTextColor($plot, $plotTextColor)
    ; CVAPI(void) cvePlot2dSetPlotTextColor(cv::plot::Plot2d* plot, CvScalar* plotTextColor);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    Else
        $sPlotDllType = "ptr"
    EndIf

    Local $sPlotTextColorDllType
    If IsDllStruct($plotTextColor) Then
        $sPlotTextColorDllType = "struct*"
    Else
        $sPlotTextColorDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotTextColor", $sPlotDllType, $plot, $sPlotTextColorDllType, $plotTextColor), "cvePlot2dSetPlotTextColor", @error)
EndFunc   ;==>_cvePlot2dSetPlotTextColor

Func _cvePlot2dSetPlotSize($plot, $plotSizeWidth, $plotSizeHeight)
    ; CVAPI(void) cvePlot2dSetPlotSize(cv::plot::Plot2d* plot, int plotSizeWidth, int plotSizeHeight);

    Local $sPlotDllType
    If IsDllStruct($plot) Then
        $sPlotDllType = "struct*"
    Else
        $sPlotDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cvePlot2dSetPlotSize", $sPlotDllType, $plot, "int", $plotSizeWidth, "int", $plotSizeHeight), "cvePlot2dSetPlotSize", @error)
EndFunc   ;==>_cvePlot2dSetPlotSize