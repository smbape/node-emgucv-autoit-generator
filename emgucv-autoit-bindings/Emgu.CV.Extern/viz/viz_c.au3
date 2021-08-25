#include-once
#include "..\..\CVEUtils.au3"

Func _cveViz3dCreate($s)
    ; CVAPI(cv::viz::Viz3d*) cveViz3dCreate(cv::String* s);

    Local $bSIsString = IsString($s)
    If $bSIsString Then
        $s = _cveStringCreateFromStr($s)
    EndIf

    Local $sSDllType
    If IsDllStruct($s) Then
        $sSDllType = "struct*"
    Else
        $sSDllType = "ptr"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveViz3dCreate", $sSDllType, $s), "cveViz3dCreate", @error)

    If $bSIsString Then
        _cveStringRelease($s)
    EndIf

    Return $retval
EndFunc   ;==>_cveViz3dCreate

Func _cveViz3dShowWidget($viz, $id, $widget, $pose)
    ; CVAPI(void) cveViz3dShowWidget(cv::viz::Viz3d* viz, cv::String* id, cv::viz::Widget* widget, cv::Affine3d* pose);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    Else
        $sVizDllType = "ptr"
    EndIf

    Local $bIdIsString = IsString($id)
    If $bIdIsString Then
        $id = _cveStringCreateFromStr($id)
    EndIf

    Local $sIdDllType
    If IsDllStruct($id) Then
        $sIdDllType = "struct*"
    Else
        $sIdDllType = "ptr"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    Else
        $sWidgetDllType = "ptr"
    EndIf

    Local $sPoseDllType
    If IsDllStruct($pose) Then
        $sPoseDllType = "struct*"
    Else
        $sPoseDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dShowWidget", $sVizDllType, $viz, $sIdDllType, $id, $sWidgetDllType, $widget, $sPoseDllType, $pose), "cveViz3dShowWidget", @error)

    If $bIdIsString Then
        _cveStringRelease($id)
    EndIf
EndFunc   ;==>_cveViz3dShowWidget

Func _cveViz3dSetWidgetPose($viz, $id, $pose)
    ; CVAPI(void) cveViz3dSetWidgetPose(cv::viz::Viz3d* viz, cv::String* id, cv::Affine3d* pose);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    Else
        $sVizDllType = "ptr"
    EndIf

    Local $bIdIsString = IsString($id)
    If $bIdIsString Then
        $id = _cveStringCreateFromStr($id)
    EndIf

    Local $sIdDllType
    If IsDllStruct($id) Then
        $sIdDllType = "struct*"
    Else
        $sIdDllType = "ptr"
    EndIf

    Local $sPoseDllType
    If IsDllStruct($pose) Then
        $sPoseDllType = "struct*"
    Else
        $sPoseDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSetWidgetPose", $sVizDllType, $viz, $sIdDllType, $id, $sPoseDllType, $pose), "cveViz3dSetWidgetPose", @error)

    If $bIdIsString Then
        _cveStringRelease($id)
    EndIf
EndFunc   ;==>_cveViz3dSetWidgetPose

Func _cveViz3dRemoveWidget($viz, $id)
    ; CVAPI(void) cveViz3dRemoveWidget(cv::viz::Viz3d* viz, cv::String* id);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    Else
        $sVizDllType = "ptr"
    EndIf

    Local $bIdIsString = IsString($id)
    If $bIdIsString Then
        $id = _cveStringCreateFromStr($id)
    EndIf

    Local $sIdDllType
    If IsDllStruct($id) Then
        $sIdDllType = "struct*"
    Else
        $sIdDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dRemoveWidget", $sVizDllType, $viz, $sIdDllType, $id), "cveViz3dRemoveWidget", @error)

    If $bIdIsString Then
        _cveStringRelease($id)
    EndIf
EndFunc   ;==>_cveViz3dRemoveWidget

Func _cveViz3dSetBackgroundMeshLab($viz)
    ; CVAPI(void) cveViz3dSetBackgroundMeshLab(cv::viz::Viz3d* viz);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    Else
        $sVizDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSetBackgroundMeshLab", $sVizDllType, $viz), "cveViz3dSetBackgroundMeshLab", @error)
EndFunc   ;==>_cveViz3dSetBackgroundMeshLab

Func _cveViz3dSpin($viz)
    ; CVAPI(void) cveViz3dSpin(cv::viz::Viz3d* viz);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    Else
        $sVizDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSpin", $sVizDllType, $viz), "cveViz3dSpin", @error)
EndFunc   ;==>_cveViz3dSpin

Func _cveViz3dSpinOnce($viz, $time, $forceRedraw)
    ; CVAPI(void) cveViz3dSpinOnce(cv::viz::Viz3d* viz, int time, bool forceRedraw);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    Else
        $sVizDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSpinOnce", $sVizDllType, $viz, "int", $time, "boolean", $forceRedraw), "cveViz3dSpinOnce", @error)
EndFunc   ;==>_cveViz3dSpinOnce

Func _cveViz3dWasStopped($viz)
    ; CVAPI(bool) cveViz3dWasStopped(cv::viz::Viz3d* viz);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    Else
        $sVizDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveViz3dWasStopped", $sVizDllType, $viz), "cveViz3dWasStopped", @error)
EndFunc   ;==>_cveViz3dWasStopped

Func _cveViz3dRelease($viz)
    ; CVAPI(void) cveViz3dRelease(cv::viz::Viz3d** viz);

    Local $sVizDllType
    If IsDllStruct($viz) Then
        $sVizDllType = "struct*"
    ElseIf $viz == Null Then
        $sVizDllType = "ptr"
    Else
        $sVizDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dRelease", $sVizDllType, $viz), "cveViz3dRelease", @error)
EndFunc   ;==>_cveViz3dRelease

Func _cveWTextCreate($text, $pos, $fontSize, $color, $widget2D, $widget)
    ; CVAPI(cv::viz::WText*) cveWTextCreate(cv::String* text, CvPoint* pos, int fontSize, CvScalar* color, cv::viz::Widget2D** widget2D, cv::viz::Widget** widget);

    Local $bTextIsString = IsString($text)
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $sTextDllType
    If IsDllStruct($text) Then
        $sTextDllType = "struct*"
    Else
        $sTextDllType = "ptr"
    EndIf

    Local $sPosDllType
    If IsDllStruct($pos) Then
        $sPosDllType = "struct*"
    Else
        $sPosDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget2DDllType
    If IsDllStruct($widget2D) Then
        $sWidget2DDllType = "struct*"
    ElseIf $widget2D == Null Then
        $sWidget2DDllType = "ptr"
    Else
        $sWidget2DDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWTextCreate", $sTextDllType, $text, $sPosDllType, $pos, "int", $fontSize, $sColorDllType, $color, $sWidget2DDllType, $widget2D, $sWidgetDllType, $widget), "cveWTextCreate", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf

    Return $retval
EndFunc   ;==>_cveWTextCreate

Func _cveWTextRelease($text)
    ; CVAPI(void) cveWTextRelease(cv::viz::WText** text);

    Local $sTextDllType
    If IsDllStruct($text) Then
        $sTextDllType = "struct*"
    ElseIf $text == Null Then
        $sTextDllType = "ptr"
    Else
        $sTextDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWTextRelease", $sTextDllType, $text), "cveWTextRelease", @error)
EndFunc   ;==>_cveWTextRelease

Func _cveWCoordinateSystemCreate($scale, $widget3d, $widget)
    ; CVAPI(cv::viz::WCoordinateSystem*) cveWCoordinateSystemCreate(double scale, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCoordinateSystemCreate", "double", $scale, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWCoordinateSystemCreate", @error)
EndFunc   ;==>_cveWCoordinateSystemCreate

Func _cveWCoordinateSystemRelease($system)
    ; CVAPI(void) cveWCoordinateSystemRelease(cv::viz::WCoordinateSystem** system);

    Local $sSystemDllType
    If IsDllStruct($system) Then
        $sSystemDllType = "struct*"
    ElseIf $system == Null Then
        $sSystemDllType = "ptr"
    Else
        $sSystemDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCoordinateSystemRelease", $sSystemDllType, $system), "cveWCoordinateSystemRelease", @error)
EndFunc   ;==>_cveWCoordinateSystemRelease

Func _cveWCloudCreateWithColorArray($cloud, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCloud*) cveWCloudCreateWithColorArray(cv::_InputArray* cloud, cv::_InputArray* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sCloudDllType
    If IsDllStruct($cloud) Then
        $sCloudDllType = "struct*"
    Else
        $sCloudDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCloudCreateWithColorArray", $sCloudDllType, $cloud, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWCloudCreateWithColorArray", @error)
EndFunc   ;==>_cveWCloudCreateWithColorArray

Func _cveWCloudCreateWithColorArrayTyped($typeOfCloud, $cloud, $typeOfColor, $color, $widget3d, $widget)

    Local $iArrCloud, $vectorCloud, $iArrCloudSize
    Local $bCloudIsArray = IsArray($cloud)
    Local $bCloudCreate = IsDllStruct($cloud) And $typeOfCloud == "Scalar"

    If $typeOfCloud == Default Then
        $iArrCloud = $cloud
    ElseIf $bCloudIsArray Then
        $vectorCloud = Call("_VectorOf" & $typeOfCloud & "Create")

        $iArrCloudSize = UBound($cloud)
        For $i = 0 To $iArrCloudSize - 1
            Call("_VectorOf" & $typeOfCloud & "Push", $vectorCloud, $cloud[$i])
        Next

        $iArrCloud = Call("_cveInputArrayFromVectorOf" & $typeOfCloud, $vectorCloud)
    Else
        If $bCloudCreate Then
            $cloud = Call("_cve" & $typeOfCloud & "Create", $cloud)
        EndIf
        $iArrCloud = Call("_cveInputArrayFrom" & $typeOfCloud, $cloud)
    EndIf

    Local $iArrColor, $vectorColor, $iArrColorSize
    Local $bColorIsArray = IsArray($color)
    Local $bColorCreate = IsDllStruct($color) And $typeOfColor == "Scalar"

    If $typeOfColor == Default Then
        $iArrColor = $color
    ElseIf $bColorIsArray Then
        $vectorColor = Call("_VectorOf" & $typeOfColor & "Create")

        $iArrColorSize = UBound($color)
        For $i = 0 To $iArrColorSize - 1
            Call("_VectorOf" & $typeOfColor & "Push", $vectorColor, $color[$i])
        Next

        $iArrColor = Call("_cveInputArrayFromVectorOf" & $typeOfColor, $vectorColor)
    Else
        If $bColorCreate Then
            $color = Call("_cve" & $typeOfColor & "Create", $color)
        EndIf
        $iArrColor = Call("_cveInputArrayFrom" & $typeOfColor, $color)
    EndIf

    Local $retval = _cveWCloudCreateWithColorArray($iArrCloud, $iArrColor, $widget3d, $widget)

    If $bColorIsArray Then
        Call("_VectorOf" & $typeOfColor & "Release", $vectorColor)
    EndIf

    If $typeOfColor <> Default Then
        _cveInputArrayRelease($iArrColor)
        If $bColorCreate Then
            Call("_cve" & $typeOfColor & "Release", $color)
        EndIf
    EndIf

    If $bCloudIsArray Then
        Call("_VectorOf" & $typeOfCloud & "Release", $vectorCloud)
    EndIf

    If $typeOfCloud <> Default Then
        _cveInputArrayRelease($iArrCloud)
        If $bCloudCreate Then
            Call("_cve" & $typeOfCloud & "Release", $cloud)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveWCloudCreateWithColorArrayTyped

Func _cveWCloudCreateWithColorArrayMat($cloud, $color, $widget3d, $widget)
    ; cveWCloudCreateWithColorArray using cv::Mat instead of _*Array
    Local $retval = _cveWCloudCreateWithColorArrayTyped("Mat", $cloud, "Mat", $color, $widget3d, $widget)

    Return $retval
EndFunc   ;==>_cveWCloudCreateWithColorArrayMat

Func _cveWCloudCreateWithColor($cloud, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCloud*) cveWCloudCreateWithColor(cv::_InputArray* cloud, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sCloudDllType
    If IsDllStruct($cloud) Then
        $sCloudDllType = "struct*"
    Else
        $sCloudDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCloudCreateWithColor", $sCloudDllType, $cloud, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWCloudCreateWithColor", @error)
EndFunc   ;==>_cveWCloudCreateWithColor

Func _cveWCloudCreateWithColorTyped($typeOfCloud, $cloud, $color, $widget3d, $widget)

    Local $iArrCloud, $vectorCloud, $iArrCloudSize
    Local $bCloudIsArray = IsArray($cloud)
    Local $bCloudCreate = IsDllStruct($cloud) And $typeOfCloud == "Scalar"

    If $typeOfCloud == Default Then
        $iArrCloud = $cloud
    ElseIf $bCloudIsArray Then
        $vectorCloud = Call("_VectorOf" & $typeOfCloud & "Create")

        $iArrCloudSize = UBound($cloud)
        For $i = 0 To $iArrCloudSize - 1
            Call("_VectorOf" & $typeOfCloud & "Push", $vectorCloud, $cloud[$i])
        Next

        $iArrCloud = Call("_cveInputArrayFromVectorOf" & $typeOfCloud, $vectorCloud)
    Else
        If $bCloudCreate Then
            $cloud = Call("_cve" & $typeOfCloud & "Create", $cloud)
        EndIf
        $iArrCloud = Call("_cveInputArrayFrom" & $typeOfCloud, $cloud)
    EndIf

    Local $retval = _cveWCloudCreateWithColor($iArrCloud, $color, $widget3d, $widget)

    If $bCloudIsArray Then
        Call("_VectorOf" & $typeOfCloud & "Release", $vectorCloud)
    EndIf

    If $typeOfCloud <> Default Then
        _cveInputArrayRelease($iArrCloud)
        If $bCloudCreate Then
            Call("_cve" & $typeOfCloud & "Release", $cloud)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveWCloudCreateWithColorTyped

Func _cveWCloudCreateWithColorMat($cloud, $color, $widget3d, $widget)
    ; cveWCloudCreateWithColor using cv::Mat instead of _*Array
    Local $retval = _cveWCloudCreateWithColorTyped("Mat", $cloud, $color, $widget3d, $widget)

    Return $retval
EndFunc   ;==>_cveWCloudCreateWithColorMat

Func _cveWCloudRelease($cloud)
    ; CVAPI(void) cveWCloudRelease(cv::viz::WCloud** cloud);

    Local $sCloudDllType
    If IsDllStruct($cloud) Then
        $sCloudDllType = "struct*"
    ElseIf $cloud == Null Then
        $sCloudDllType = "ptr"
    Else
        $sCloudDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCloudRelease", $sCloudDllType, $cloud), "cveWCloudRelease", @error)
EndFunc   ;==>_cveWCloudRelease

Func _cveWriteCloud($file, $cloud, $colors, $normals, $binary)
    ; CVAPI(void) cveWriteCloud(cv::String* file, cv::_InputArray* cloud, cv::_InputArray* colors, cv::_InputArray* normals, bool binary);

    Local $bFileIsString = IsString($file)
    If $bFileIsString Then
        $file = _cveStringCreateFromStr($file)
    EndIf

    Local $sFileDllType
    If IsDllStruct($file) Then
        $sFileDllType = "struct*"
    Else
        $sFileDllType = "ptr"
    EndIf

    Local $sCloudDllType
    If IsDllStruct($cloud) Then
        $sCloudDllType = "struct*"
    Else
        $sCloudDllType = "ptr"
    EndIf

    Local $sColorsDllType
    If IsDllStruct($colors) Then
        $sColorsDllType = "struct*"
    Else
        $sColorsDllType = "ptr"
    EndIf

    Local $sNormalsDllType
    If IsDllStruct($normals) Then
        $sNormalsDllType = "struct*"
    Else
        $sNormalsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWriteCloud", $sFileDllType, $file, $sCloudDllType, $cloud, $sColorsDllType, $colors, $sNormalsDllType, $normals, "boolean", $binary), "cveWriteCloud", @error)

    If $bFileIsString Then
        _cveStringRelease($file)
    EndIf
EndFunc   ;==>_cveWriteCloud

Func _cveWriteCloudTyped($file, $typeOfCloud, $cloud, $typeOfColors, $colors, $typeOfNormals, $normals, $binary)

    Local $iArrCloud, $vectorCloud, $iArrCloudSize
    Local $bCloudIsArray = IsArray($cloud)
    Local $bCloudCreate = IsDllStruct($cloud) And $typeOfCloud == "Scalar"

    If $typeOfCloud == Default Then
        $iArrCloud = $cloud
    ElseIf $bCloudIsArray Then
        $vectorCloud = Call("_VectorOf" & $typeOfCloud & "Create")

        $iArrCloudSize = UBound($cloud)
        For $i = 0 To $iArrCloudSize - 1
            Call("_VectorOf" & $typeOfCloud & "Push", $vectorCloud, $cloud[$i])
        Next

        $iArrCloud = Call("_cveInputArrayFromVectorOf" & $typeOfCloud, $vectorCloud)
    Else
        If $bCloudCreate Then
            $cloud = Call("_cve" & $typeOfCloud & "Create", $cloud)
        EndIf
        $iArrCloud = Call("_cveInputArrayFrom" & $typeOfCloud, $cloud)
    EndIf

    Local $iArrColors, $vectorColors, $iArrColorsSize
    Local $bColorsIsArray = IsArray($colors)
    Local $bColorsCreate = IsDllStruct($colors) And $typeOfColors == "Scalar"

    If $typeOfColors == Default Then
        $iArrColors = $colors
    ElseIf $bColorsIsArray Then
        $vectorColors = Call("_VectorOf" & $typeOfColors & "Create")

        $iArrColorsSize = UBound($colors)
        For $i = 0 To $iArrColorsSize - 1
            Call("_VectorOf" & $typeOfColors & "Push", $vectorColors, $colors[$i])
        Next

        $iArrColors = Call("_cveInputArrayFromVectorOf" & $typeOfColors, $vectorColors)
    Else
        If $bColorsCreate Then
            $colors = Call("_cve" & $typeOfColors & "Create", $colors)
        EndIf
        $iArrColors = Call("_cveInputArrayFrom" & $typeOfColors, $colors)
    EndIf

    Local $iArrNormals, $vectorNormals, $iArrNormalsSize
    Local $bNormalsIsArray = IsArray($normals)
    Local $bNormalsCreate = IsDllStruct($normals) And $typeOfNormals == "Scalar"

    If $typeOfNormals == Default Then
        $iArrNormals = $normals
    ElseIf $bNormalsIsArray Then
        $vectorNormals = Call("_VectorOf" & $typeOfNormals & "Create")

        $iArrNormalsSize = UBound($normals)
        For $i = 0 To $iArrNormalsSize - 1
            Call("_VectorOf" & $typeOfNormals & "Push", $vectorNormals, $normals[$i])
        Next

        $iArrNormals = Call("_cveInputArrayFromVectorOf" & $typeOfNormals, $vectorNormals)
    Else
        If $bNormalsCreate Then
            $normals = Call("_cve" & $typeOfNormals & "Create", $normals)
        EndIf
        $iArrNormals = Call("_cveInputArrayFrom" & $typeOfNormals, $normals)
    EndIf

    _cveWriteCloud($file, $iArrCloud, $iArrColors, $iArrNormals, $binary)

    If $bNormalsIsArray Then
        Call("_VectorOf" & $typeOfNormals & "Release", $vectorNormals)
    EndIf

    If $typeOfNormals <> Default Then
        _cveInputArrayRelease($iArrNormals)
        If $bNormalsCreate Then
            Call("_cve" & $typeOfNormals & "Release", $normals)
        EndIf
    EndIf

    If $bColorsIsArray Then
        Call("_VectorOf" & $typeOfColors & "Release", $vectorColors)
    EndIf

    If $typeOfColors <> Default Then
        _cveInputArrayRelease($iArrColors)
        If $bColorsCreate Then
            Call("_cve" & $typeOfColors & "Release", $colors)
        EndIf
    EndIf

    If $bCloudIsArray Then
        Call("_VectorOf" & $typeOfCloud & "Release", $vectorCloud)
    EndIf

    If $typeOfCloud <> Default Then
        _cveInputArrayRelease($iArrCloud)
        If $bCloudCreate Then
            Call("_cve" & $typeOfCloud & "Release", $cloud)
        EndIf
    EndIf
EndFunc   ;==>_cveWriteCloudTyped

Func _cveWriteCloudMat($file, $cloud, $colors, $normals, $binary)
    ; cveWriteCloud using cv::Mat instead of _*Array
    _cveWriteCloudTyped($file, "Mat", $cloud, "Mat", $colors, "Mat", $normals, $binary)
EndFunc   ;==>_cveWriteCloudMat

Func _cveReadCloud($file, $cloud, $colors, $normals)
    ; CVAPI(void) cveReadCloud(cv::String* file, cv::Mat* cloud, cv::_OutputArray* colors, cv::_OutputArray* normals);

    Local $bFileIsString = IsString($file)
    If $bFileIsString Then
        $file = _cveStringCreateFromStr($file)
    EndIf

    Local $sFileDllType
    If IsDllStruct($file) Then
        $sFileDllType = "struct*"
    Else
        $sFileDllType = "ptr"
    EndIf

    Local $sCloudDllType
    If IsDllStruct($cloud) Then
        $sCloudDllType = "struct*"
    Else
        $sCloudDllType = "ptr"
    EndIf

    Local $sColorsDllType
    If IsDllStruct($colors) Then
        $sColorsDllType = "struct*"
    Else
        $sColorsDllType = "ptr"
    EndIf

    Local $sNormalsDllType
    If IsDllStruct($normals) Then
        $sNormalsDllType = "struct*"
    Else
        $sNormalsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReadCloud", $sFileDllType, $file, $sCloudDllType, $cloud, $sColorsDllType, $colors, $sNormalsDllType, $normals), "cveReadCloud", @error)

    If $bFileIsString Then
        _cveStringRelease($file)
    EndIf
EndFunc   ;==>_cveReadCloud

Func _cveReadCloudTyped($file, $cloud, $typeOfColors, $colors, $typeOfNormals, $normals)

    Local $oArrColors, $vectorColors, $iArrColorsSize
    Local $bColorsIsArray = IsArray($colors)
    Local $bColorsCreate = IsDllStruct($colors) And $typeOfColors == "Scalar"

    If $typeOfColors == Default Then
        $oArrColors = $colors
    ElseIf $bColorsIsArray Then
        $vectorColors = Call("_VectorOf" & $typeOfColors & "Create")

        $iArrColorsSize = UBound($colors)
        For $i = 0 To $iArrColorsSize - 1
            Call("_VectorOf" & $typeOfColors & "Push", $vectorColors, $colors[$i])
        Next

        $oArrColors = Call("_cveOutputArrayFromVectorOf" & $typeOfColors, $vectorColors)
    Else
        If $bColorsCreate Then
            $colors = Call("_cve" & $typeOfColors & "Create", $colors)
        EndIf
        $oArrColors = Call("_cveOutputArrayFrom" & $typeOfColors, $colors)
    EndIf

    Local $oArrNormals, $vectorNormals, $iArrNormalsSize
    Local $bNormalsIsArray = IsArray($normals)
    Local $bNormalsCreate = IsDllStruct($normals) And $typeOfNormals == "Scalar"

    If $typeOfNormals == Default Then
        $oArrNormals = $normals
    ElseIf $bNormalsIsArray Then
        $vectorNormals = Call("_VectorOf" & $typeOfNormals & "Create")

        $iArrNormalsSize = UBound($normals)
        For $i = 0 To $iArrNormalsSize - 1
            Call("_VectorOf" & $typeOfNormals & "Push", $vectorNormals, $normals[$i])
        Next

        $oArrNormals = Call("_cveOutputArrayFromVectorOf" & $typeOfNormals, $vectorNormals)
    Else
        If $bNormalsCreate Then
            $normals = Call("_cve" & $typeOfNormals & "Create", $normals)
        EndIf
        $oArrNormals = Call("_cveOutputArrayFrom" & $typeOfNormals, $normals)
    EndIf

    _cveReadCloud($file, $cloud, $oArrColors, $oArrNormals)

    If $bNormalsIsArray Then
        Call("_VectorOf" & $typeOfNormals & "Release", $vectorNormals)
    EndIf

    If $typeOfNormals <> Default Then
        _cveOutputArrayRelease($oArrNormals)
        If $bNormalsCreate Then
            Call("_cve" & $typeOfNormals & "Release", $normals)
        EndIf
    EndIf

    If $bColorsIsArray Then
        Call("_VectorOf" & $typeOfColors & "Release", $vectorColors)
    EndIf

    If $typeOfColors <> Default Then
        _cveOutputArrayRelease($oArrColors)
        If $bColorsCreate Then
            Call("_cve" & $typeOfColors & "Release", $colors)
        EndIf
    EndIf
EndFunc   ;==>_cveReadCloudTyped

Func _cveReadCloudMat($file, $cloud, $colors, $normals)
    ; cveReadCloud using cv::Mat instead of _*Array
    _cveReadCloudTyped($file, $cloud, "Mat", $colors, "Mat", $normals)
EndFunc   ;==>_cveReadCloudMat

Func _cveWCubeCreate($minPoint, $maxPoint, $wireFrame, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCube*) cveWCubeCreate(CvPoint3D64f* minPoint, CvPoint3D64f* maxPoint, bool wireFrame, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sMinPointDllType
    If IsDllStruct($minPoint) Then
        $sMinPointDllType = "struct*"
    Else
        $sMinPointDllType = "ptr"
    EndIf

    Local $sMaxPointDllType
    If IsDllStruct($maxPoint) Then
        $sMaxPointDllType = "struct*"
    Else
        $sMaxPointDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCubeCreate", $sMinPointDllType, $minPoint, $sMaxPointDllType, $maxPoint, "boolean", $wireFrame, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWCubeCreate", @error)
EndFunc   ;==>_cveWCubeCreate

Func _cveWCubeRelease($cube)
    ; CVAPI(void) cveWCubeRelease(cv::viz::WCube** cube);

    Local $sCubeDllType
    If IsDllStruct($cube) Then
        $sCubeDllType = "struct*"
    ElseIf $cube == Null Then
        $sCubeDllType = "ptr"
    Else
        $sCubeDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCubeRelease", $sCubeDllType, $cube), "cveWCubeRelease", @error)
EndFunc   ;==>_cveWCubeRelease

Func _cveWCylinderCreate($axisPoint1, $axisPoint2, $radius, $numsides, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCylinder*) cveWCylinderCreate(CvPoint3D64f* axisPoint1, CvPoint3D64f* axisPoint2, double radius, int numsides, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sAxisPoint1DllType
    If IsDllStruct($axisPoint1) Then
        $sAxisPoint1DllType = "struct*"
    Else
        $sAxisPoint1DllType = "ptr"
    EndIf

    Local $sAxisPoint2DllType
    If IsDllStruct($axisPoint2) Then
        $sAxisPoint2DllType = "struct*"
    Else
        $sAxisPoint2DllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCylinderCreate", $sAxisPoint1DllType, $axisPoint1, $sAxisPoint2DllType, $axisPoint2, "double", $radius, "int", $numsides, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWCylinderCreate", @error)
EndFunc   ;==>_cveWCylinderCreate

Func _cveWCylinderRelease($cylinder)
    ; CVAPI(void) cveWCylinderRelease(cv::viz::WCylinder** cylinder);

    Local $sCylinderDllType
    If IsDllStruct($cylinder) Then
        $sCylinderDllType = "struct*"
    ElseIf $cylinder == Null Then
        $sCylinderDllType = "ptr"
    Else
        $sCylinderDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCylinderRelease", $sCylinderDllType, $cylinder), "cveWCylinderRelease", @error)
EndFunc   ;==>_cveWCylinderRelease

Func _cveWCircleCreateAtOrigin($radius, $thickness, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCircle*) cveWCircleCreateAtOrigin(double radius, double thickness, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCircleCreateAtOrigin", "double", $radius, "double", $thickness, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWCircleCreateAtOrigin", @error)
EndFunc   ;==>_cveWCircleCreateAtOrigin

Func _cveWCircleCreate($radius, $center, $normal, $thickness, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCircle*) cveWCircleCreate(double radius, CvPoint3D64f* center, CvPoint3D64f* normal, double thickness, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    Local $sNormalDllType
    If IsDllStruct($normal) Then
        $sNormalDllType = "struct*"
    Else
        $sNormalDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCircleCreate", "double", $radius, $sCenterDllType, $center, $sNormalDllType, $normal, "double", $thickness, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWCircleCreate", @error)
EndFunc   ;==>_cveWCircleCreate

Func _cveWCircleRelease($circle)
    ; CVAPI(void) cveWCircleRelease(cv::viz::WCircle** circle);

    Local $sCircleDllType
    If IsDllStruct($circle) Then
        $sCircleDllType = "struct*"
    ElseIf $circle == Null Then
        $sCircleDllType = "ptr"
    Else
        $sCircleDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCircleRelease", $sCircleDllType, $circle), "cveWCircleRelease", @error)
EndFunc   ;==>_cveWCircleRelease

Func _cveWConeCreateAtOrigin($length, $radius, $resolution, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCone*) cveWConeCreateAtOrigin(double length, double radius, int resolution, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWConeCreateAtOrigin", "double", $length, "double", $radius, "int", $resolution, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWConeCreateAtOrigin", @error)
EndFunc   ;==>_cveWConeCreateAtOrigin

Func _cveWConeCreate($radius, $center, $tip, $resolution, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WCone*) cveWConeCreate(double radius, CvPoint3D64f* center, CvPoint3D64f* tip, int resolution, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sCenterDllType
    If IsDllStruct($center) Then
        $sCenterDllType = "struct*"
    Else
        $sCenterDllType = "ptr"
    EndIf

    Local $sTipDllType
    If IsDllStruct($tip) Then
        $sTipDllType = "struct*"
    Else
        $sTipDllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWConeCreate", "double", $radius, $sCenterDllType, $center, $sTipDllType, $tip, "int", $resolution, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWConeCreate", @error)
EndFunc   ;==>_cveWConeCreate

Func _cveWConeRelease($cone)
    ; CVAPI(void) cveWConeRelease(cv::viz::WCone** cone);

    Local $sConeDllType
    If IsDllStruct($cone) Then
        $sConeDllType = "struct*"
    ElseIf $cone == Null Then
        $sConeDllType = "ptr"
    Else
        $sConeDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWConeRelease", $sConeDllType, $cone), "cveWConeRelease", @error)
EndFunc   ;==>_cveWConeRelease

Func _cveWArrowCreate($pt1, $pt2, $thickness, $color, $widget3d, $widget)
    ; CVAPI(cv::viz::WArrow*) cveWArrowCreate(CvPoint3D64f* pt1, CvPoint3D64f* pt2, double thickness, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);

    Local $sPt1DllType
    If IsDllStruct($pt1) Then
        $sPt1DllType = "struct*"
    Else
        $sPt1DllType = "ptr"
    EndIf

    Local $sPt2DllType
    If IsDllStruct($pt2) Then
        $sPt2DllType = "struct*"
    Else
        $sPt2DllType = "ptr"
    EndIf

    Local $sColorDllType
    If IsDllStruct($color) Then
        $sColorDllType = "struct*"
    Else
        $sColorDllType = "ptr"
    EndIf

    Local $sWidget3dDllType
    If IsDllStruct($widget3d) Then
        $sWidget3dDllType = "struct*"
    ElseIf $widget3d == Null Then
        $sWidget3dDllType = "ptr"
    Else
        $sWidget3dDllType = "ptr*"
    EndIf

    Local $sWidgetDllType
    If IsDllStruct($widget) Then
        $sWidgetDllType = "struct*"
    ElseIf $widget == Null Then
        $sWidgetDllType = "ptr"
    Else
        $sWidgetDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWArrowCreate", $sPt1DllType, $pt1, $sPt2DllType, $pt2, "double", $thickness, $sColorDllType, $color, $sWidget3dDllType, $widget3d, $sWidgetDllType, $widget), "cveWArrowCreate", @error)
EndFunc   ;==>_cveWArrowCreate

Func _cveWArrowRelease($arrow)
    ; CVAPI(void) cveWArrowRelease(cv::viz::WArrow** arrow);

    Local $sArrowDllType
    If IsDllStruct($arrow) Then
        $sArrowDllType = "struct*"
    ElseIf $arrow == Null Then
        $sArrowDllType = "ptr"
    Else
        $sArrowDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWArrowRelease", $sArrowDllType, $arrow), "cveWArrowRelease", @error)
EndFunc   ;==>_cveWArrowRelease