#include-once
#include "..\..\CVEUtils.au3"

Func _cveViz3dCreate($s)
    ; CVAPI(cv::viz::Viz3d*) cveViz3dCreate(cv::String* s);

    Local $bSIsString = VarGetType($s) == "String"
    If $bSIsString Then
        $s = _cveStringCreateFromStr($s)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveViz3dCreate", "ptr", $s), "cveViz3dCreate", @error)

    If $bSIsString Then
        _cveStringRelease($s)
    EndIf

    Return $retval
EndFunc   ;==>_cveViz3dCreate

Func _cveViz3dShowWidget(ByRef $viz, $id, ByRef $widget, ByRef $pose)
    ; CVAPI(void) cveViz3dShowWidget(cv::viz::Viz3d* viz, cv::String* id, cv::viz::Widget* widget, cv::Affine3d* pose);

    Local $bIdIsString = VarGetType($id) == "String"
    If $bIdIsString Then
        $id = _cveStringCreateFromStr($id)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dShowWidget", "ptr", $viz, "ptr", $id, "ptr", $widget, "ptr", $pose), "cveViz3dShowWidget", @error)

    If $bIdIsString Then
        _cveStringRelease($id)
    EndIf
EndFunc   ;==>_cveViz3dShowWidget

Func _cveViz3dSetWidgetPose(ByRef $viz, $id, ByRef $pose)
    ; CVAPI(void) cveViz3dSetWidgetPose(cv::viz::Viz3d* viz, cv::String* id, cv::Affine3d* pose);

    Local $bIdIsString = VarGetType($id) == "String"
    If $bIdIsString Then
        $id = _cveStringCreateFromStr($id)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSetWidgetPose", "ptr", $viz, "ptr", $id, "ptr", $pose), "cveViz3dSetWidgetPose", @error)

    If $bIdIsString Then
        _cveStringRelease($id)
    EndIf
EndFunc   ;==>_cveViz3dSetWidgetPose

Func _cveViz3dRemoveWidget(ByRef $viz, $id)
    ; CVAPI(void) cveViz3dRemoveWidget(cv::viz::Viz3d* viz, cv::String* id);

    Local $bIdIsString = VarGetType($id) == "String"
    If $bIdIsString Then
        $id = _cveStringCreateFromStr($id)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dRemoveWidget", "ptr", $viz, "ptr", $id), "cveViz3dRemoveWidget", @error)

    If $bIdIsString Then
        _cveStringRelease($id)
    EndIf
EndFunc   ;==>_cveViz3dRemoveWidget

Func _cveViz3dSetBackgroundMeshLab(ByRef $viz)
    ; CVAPI(void) cveViz3dSetBackgroundMeshLab(cv::viz::Viz3d* viz);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSetBackgroundMeshLab", "ptr", $viz), "cveViz3dSetBackgroundMeshLab", @error)
EndFunc   ;==>_cveViz3dSetBackgroundMeshLab

Func _cveViz3dSpin(ByRef $viz)
    ; CVAPI(void) cveViz3dSpin(cv::viz::Viz3d* viz);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSpin", "ptr", $viz), "cveViz3dSpin", @error)
EndFunc   ;==>_cveViz3dSpin

Func _cveViz3dSpinOnce(ByRef $viz, $time, $forceRedraw)
    ; CVAPI(void) cveViz3dSpinOnce(cv::viz::Viz3d* viz, int time, bool forceRedraw);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dSpinOnce", "ptr", $viz, "int", $time, "boolean", $forceRedraw), "cveViz3dSpinOnce", @error)
EndFunc   ;==>_cveViz3dSpinOnce

Func _cveViz3dWasStopped(ByRef $viz)
    ; CVAPI(bool) cveViz3dWasStopped(cv::viz::Viz3d* viz);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "boolean:cdecl", "cveViz3dWasStopped", "ptr", $viz), "cveViz3dWasStopped", @error)
EndFunc   ;==>_cveViz3dWasStopped

Func _cveViz3dRelease(ByRef $viz)
    ; CVAPI(void) cveViz3dRelease(cv::viz::Viz3d** viz);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveViz3dRelease", "ptr*", $viz), "cveViz3dRelease", @error)
EndFunc   ;==>_cveViz3dRelease

Func _cveWTextCreate($text, ByRef $pos, $fontSize, ByRef $color, ByRef $widget2D, ByRef $widget)
    ; CVAPI(cv::viz::WText*) cveWTextCreate(cv::String* text, CvPoint* pos, int fontSize, CvScalar* color, cv::viz::Widget2D** widget2D, cv::viz::Widget** widget);

    Local $bTextIsString = VarGetType($text) == "String"
    If $bTextIsString Then
        $text = _cveStringCreateFromStr($text)
    EndIf

    Local $retval = CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWTextCreate", "ptr", $text, "struct*", $pos, "int", $fontSize, "struct*", $color, "ptr*", $widget2D, "ptr*", $widget), "cveWTextCreate", @error)

    If $bTextIsString Then
        _cveStringRelease($text)
    EndIf

    Return $retval
EndFunc   ;==>_cveWTextCreate

Func _cveWTextRelease(ByRef $text)
    ; CVAPI(void) cveWTextRelease(cv::viz::WText** text);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWTextRelease", "ptr*", $text), "cveWTextRelease", @error)
EndFunc   ;==>_cveWTextRelease

Func _cveWCoordinateSystemCreate($scale, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCoordinateSystem*) cveWCoordinateSystemCreate(double scale, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCoordinateSystemCreate", "double", $scale, "ptr*", $widget3d, "ptr*", $widget), "cveWCoordinateSystemCreate", @error)
EndFunc   ;==>_cveWCoordinateSystemCreate

Func _cveWCoordinateSystemRelease(ByRef $system)
    ; CVAPI(void) cveWCoordinateSystemRelease(cv::viz::WCoordinateSystem** system);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCoordinateSystemRelease", "ptr*", $system), "cveWCoordinateSystemRelease", @error)
EndFunc   ;==>_cveWCoordinateSystemRelease

Func _cveWCloudCreateWithColorArray(ByRef $cloud, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCloud*) cveWCloudCreateWithColorArray(cv::_InputArray* cloud, cv::_InputArray* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCloudCreateWithColorArray", "ptr", $cloud, "ptr", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWCloudCreateWithColorArray", @error)
EndFunc   ;==>_cveWCloudCreateWithColorArray

Func _cveWCloudCreateWithColorArrayMat(ByRef $matCloud, ByRef $matColor, ByRef $widget3d, ByRef $widget)
    ; cveWCloudCreateWithColorArray using cv::Mat instead of _*Array

    Local $iArrCloud, $vectorOfMatCloud, $iArrCloudSize
    Local $bCloudIsArray = VarGetType($matCloud) == "Array"

    If $bCloudIsArray Then
        $vectorOfMatCloud = _VectorOfMatCreate()

        $iArrCloudSize = UBound($matCloud)
        For $i = 0 To $iArrCloudSize - 1
            _VectorOfMatPush($vectorOfMatCloud, $matCloud[$i])
        Next

        $iArrCloud = _cveInputArrayFromVectorOfMat($vectorOfMatCloud)
    Else
        $iArrCloud = _cveInputArrayFromMat($matCloud)
    EndIf

    Local $iArrColor, $vectorOfMatColor, $iArrColorSize
    Local $bColorIsArray = VarGetType($matColor) == "Array"

    If $bColorIsArray Then
        $vectorOfMatColor = _VectorOfMatCreate()

        $iArrColorSize = UBound($matColor)
        For $i = 0 To $iArrColorSize - 1
            _VectorOfMatPush($vectorOfMatColor, $matColor[$i])
        Next

        $iArrColor = _cveInputArrayFromVectorOfMat($vectorOfMatColor)
    Else
        $iArrColor = _cveInputArrayFromMat($matColor)
    EndIf

    Local $retval = _cveWCloudCreateWithColorArray($iArrCloud, $iArrColor, $widget3d, $widget)

    If $bColorIsArray Then
        _VectorOfMatRelease($vectorOfMatColor)
    EndIf

    _cveInputArrayRelease($iArrColor)

    If $bCloudIsArray Then
        _VectorOfMatRelease($vectorOfMatCloud)
    EndIf

    _cveInputArrayRelease($iArrCloud)

    Return $retval
EndFunc   ;==>_cveWCloudCreateWithColorArrayMat

Func _cveWCloudCreateWithColor(ByRef $cloud, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCloud*) cveWCloudCreateWithColor(cv::_InputArray* cloud, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCloudCreateWithColor", "ptr", $cloud, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWCloudCreateWithColor", @error)
EndFunc   ;==>_cveWCloudCreateWithColor

Func _cveWCloudCreateWithColorMat(ByRef $matCloud, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; cveWCloudCreateWithColor using cv::Mat instead of _*Array

    Local $iArrCloud, $vectorOfMatCloud, $iArrCloudSize
    Local $bCloudIsArray = VarGetType($matCloud) == "Array"

    If $bCloudIsArray Then
        $vectorOfMatCloud = _VectorOfMatCreate()

        $iArrCloudSize = UBound($matCloud)
        For $i = 0 To $iArrCloudSize - 1
            _VectorOfMatPush($vectorOfMatCloud, $matCloud[$i])
        Next

        $iArrCloud = _cveInputArrayFromVectorOfMat($vectorOfMatCloud)
    Else
        $iArrCloud = _cveInputArrayFromMat($matCloud)
    EndIf

    Local $retval = _cveWCloudCreateWithColor($iArrCloud, $color, $widget3d, $widget)

    If $bCloudIsArray Then
        _VectorOfMatRelease($vectorOfMatCloud)
    EndIf

    _cveInputArrayRelease($iArrCloud)

    Return $retval
EndFunc   ;==>_cveWCloudCreateWithColorMat

Func _cveWCloudRelease(ByRef $cloud)
    ; CVAPI(void) cveWCloudRelease(cv::viz::WCloud** cloud);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCloudRelease", "ptr*", $cloud), "cveWCloudRelease", @error)
EndFunc   ;==>_cveWCloudRelease

Func _cveWriteCloud($file, ByRef $cloud, ByRef $colors, ByRef $normals, $binary)
    ; CVAPI(void) cveWriteCloud(cv::String* file, cv::_InputArray* cloud, cv::_InputArray* colors, cv::_InputArray* normals, bool binary);

    Local $bFileIsString = VarGetType($file) == "String"
    If $bFileIsString Then
        $file = _cveStringCreateFromStr($file)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWriteCloud", "ptr", $file, "ptr", $cloud, "ptr", $colors, "ptr", $normals, "boolean", $binary), "cveWriteCloud", @error)

    If $bFileIsString Then
        _cveStringRelease($file)
    EndIf
EndFunc   ;==>_cveWriteCloud

Func _cveWriteCloudMat($file, ByRef $matCloud, ByRef $matColors, ByRef $matNormals, $binary)
    ; cveWriteCloud using cv::Mat instead of _*Array

    Local $iArrCloud, $vectorOfMatCloud, $iArrCloudSize
    Local $bCloudIsArray = VarGetType($matCloud) == "Array"

    If $bCloudIsArray Then
        $vectorOfMatCloud = _VectorOfMatCreate()

        $iArrCloudSize = UBound($matCloud)
        For $i = 0 To $iArrCloudSize - 1
            _VectorOfMatPush($vectorOfMatCloud, $matCloud[$i])
        Next

        $iArrCloud = _cveInputArrayFromVectorOfMat($vectorOfMatCloud)
    Else
        $iArrCloud = _cveInputArrayFromMat($matCloud)
    EndIf

    Local $iArrColors, $vectorOfMatColors, $iArrColorsSize
    Local $bColorsIsArray = VarGetType($matColors) == "Array"

    If $bColorsIsArray Then
        $vectorOfMatColors = _VectorOfMatCreate()

        $iArrColorsSize = UBound($matColors)
        For $i = 0 To $iArrColorsSize - 1
            _VectorOfMatPush($vectorOfMatColors, $matColors[$i])
        Next

        $iArrColors = _cveInputArrayFromVectorOfMat($vectorOfMatColors)
    Else
        $iArrColors = _cveInputArrayFromMat($matColors)
    EndIf

    Local $iArrNormals, $vectorOfMatNormals, $iArrNormalsSize
    Local $bNormalsIsArray = VarGetType($matNormals) == "Array"

    If $bNormalsIsArray Then
        $vectorOfMatNormals = _VectorOfMatCreate()

        $iArrNormalsSize = UBound($matNormals)
        For $i = 0 To $iArrNormalsSize - 1
            _VectorOfMatPush($vectorOfMatNormals, $matNormals[$i])
        Next

        $iArrNormals = _cveInputArrayFromVectorOfMat($vectorOfMatNormals)
    Else
        $iArrNormals = _cveInputArrayFromMat($matNormals)
    EndIf

    _cveWriteCloud($file, $iArrCloud, $iArrColors, $iArrNormals, $binary)

    If $bNormalsIsArray Then
        _VectorOfMatRelease($vectorOfMatNormals)
    EndIf

    _cveInputArrayRelease($iArrNormals)

    If $bColorsIsArray Then
        _VectorOfMatRelease($vectorOfMatColors)
    EndIf

    _cveInputArrayRelease($iArrColors)

    If $bCloudIsArray Then
        _VectorOfMatRelease($vectorOfMatCloud)
    EndIf

    _cveInputArrayRelease($iArrCloud)
EndFunc   ;==>_cveWriteCloudMat

Func _cveReadCloud($file, ByRef $cloud, ByRef $colors, ByRef $normals)
    ; CVAPI(void) cveReadCloud(cv::String* file, cv::Mat* cloud, cv::_OutputArray* colors, cv::_OutputArray* normals);

    Local $bFileIsString = VarGetType($file) == "String"
    If $bFileIsString Then
        $file = _cveStringCreateFromStr($file)
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveReadCloud", "ptr", $file, "ptr", $cloud, "ptr", $colors, "ptr", $normals), "cveReadCloud", @error)

    If $bFileIsString Then
        _cveStringRelease($file)
    EndIf
EndFunc   ;==>_cveReadCloud

Func _cveReadCloudMat($file, ByRef $cloud, ByRef $matColors, ByRef $matNormals)
    ; cveReadCloud using cv::Mat instead of _*Array

    Local $oArrColors, $vectorOfMatColors, $iArrColorsSize
    Local $bColorsIsArray = VarGetType($matColors) == "Array"

    If $bColorsIsArray Then
        $vectorOfMatColors = _VectorOfMatCreate()

        $iArrColorsSize = UBound($matColors)
        For $i = 0 To $iArrColorsSize - 1
            _VectorOfMatPush($vectorOfMatColors, $matColors[$i])
        Next

        $oArrColors = _cveOutputArrayFromVectorOfMat($vectorOfMatColors)
    Else
        $oArrColors = _cveOutputArrayFromMat($matColors)
    EndIf

    Local $oArrNormals, $vectorOfMatNormals, $iArrNormalsSize
    Local $bNormalsIsArray = VarGetType($matNormals) == "Array"

    If $bNormalsIsArray Then
        $vectorOfMatNormals = _VectorOfMatCreate()

        $iArrNormalsSize = UBound($matNormals)
        For $i = 0 To $iArrNormalsSize - 1
            _VectorOfMatPush($vectorOfMatNormals, $matNormals[$i])
        Next

        $oArrNormals = _cveOutputArrayFromVectorOfMat($vectorOfMatNormals)
    Else
        $oArrNormals = _cveOutputArrayFromMat($matNormals)
    EndIf

    _cveReadCloud($file, $cloud, $oArrColors, $oArrNormals)

    If $bNormalsIsArray Then
        _VectorOfMatRelease($vectorOfMatNormals)
    EndIf

    _cveOutputArrayRelease($oArrNormals)

    If $bColorsIsArray Then
        _VectorOfMatRelease($vectorOfMatColors)
    EndIf

    _cveOutputArrayRelease($oArrColors)
EndFunc   ;==>_cveReadCloudMat

Func _cveWCubeCreate(ByRef $minPoint, ByRef $maxPoint, $wireFrame, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCube*) cveWCubeCreate(CvPoint3D64f* minPoint, CvPoint3D64f* maxPoint, bool wireFrame, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCubeCreate", "struct*", $minPoint, "struct*", $maxPoint, "boolean", $wireFrame, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWCubeCreate", @error)
EndFunc   ;==>_cveWCubeCreate

Func _cveWCubeRelease(ByRef $cube)
    ; CVAPI(void) cveWCubeRelease(cv::viz::WCube** cube);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCubeRelease", "ptr*", $cube), "cveWCubeRelease", @error)
EndFunc   ;==>_cveWCubeRelease

Func _cveWCylinderCreate(ByRef $axisPoint1, ByRef $axisPoint2, $radius, $numsides, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCylinder*) cveWCylinderCreate(CvPoint3D64f* axisPoint1, CvPoint3D64f* axisPoint2, double radius, int numsides, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCylinderCreate", "struct*", $axisPoint1, "struct*", $axisPoint2, "double", $radius, "int", $numsides, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWCylinderCreate", @error)
EndFunc   ;==>_cveWCylinderCreate

Func _cveWCylinderRelease(ByRef $cylinder)
    ; CVAPI(void) cveWCylinderRelease(cv::viz::WCylinder** cylinder);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCylinderRelease", "ptr*", $cylinder), "cveWCylinderRelease", @error)
EndFunc   ;==>_cveWCylinderRelease

Func _cveWCircleCreateAtOrigin($radius, $thickness, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCircle*) cveWCircleCreateAtOrigin(double radius, double thickness, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCircleCreateAtOrigin", "double", $radius, "double", $thickness, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWCircleCreateAtOrigin", @error)
EndFunc   ;==>_cveWCircleCreateAtOrigin

Func _cveWCircleCreate($radius, ByRef $center, ByRef $normal, $thickness, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCircle*) cveWCircleCreate(double radius, CvPoint3D64f* center, CvPoint3D64f* normal, double thickness, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWCircleCreate", "double", $radius, "struct*", $center, "struct*", $normal, "double", $thickness, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWCircleCreate", @error)
EndFunc   ;==>_cveWCircleCreate

Func _cveWCircleRelease(ByRef $circle)
    ; CVAPI(void) cveWCircleRelease(cv::viz::WCircle** circle);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWCircleRelease", "ptr*", $circle), "cveWCircleRelease", @error)
EndFunc   ;==>_cveWCircleRelease

Func _cveWConeCreateAtOrigin($length, $radius, $resolution, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCone*) cveWConeCreateAtOrigin(double length, double radius, int resolution, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWConeCreateAtOrigin", "double", $length, "double", $radius, "int", $resolution, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWConeCreateAtOrigin", @error)
EndFunc   ;==>_cveWConeCreateAtOrigin

Func _cveWConeCreate($radius, ByRef $center, ByRef $tip, $resolution, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WCone*) cveWConeCreate(double radius, CvPoint3D64f* center, CvPoint3D64f* tip, int resolution, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWConeCreate", "double", $radius, "struct*", $center, "struct*", $tip, "int", $resolution, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWConeCreate", @error)
EndFunc   ;==>_cveWConeCreate

Func _cveWConeRelease(ByRef $cone)
    ; CVAPI(void) cveWConeRelease(cv::viz::WCone** cone);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWConeRelease", "ptr*", $cone), "cveWConeRelease", @error)
EndFunc   ;==>_cveWConeRelease

Func _cveWArrowCreate(ByRef $pt1, ByRef $pt2, $thickness, ByRef $color, ByRef $widget3d, ByRef $widget)
    ; CVAPI(cv::viz::WArrow*) cveWArrowCreate(CvPoint3D64f* pt1, CvPoint3D64f* pt2, double thickness, CvScalar* color, cv::viz::Widget3D** widget3d, cv::viz::Widget** widget);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveWArrowCreate", "struct*", $pt1, "struct*", $pt2, "double", $thickness, "struct*", $color, "ptr*", $widget3d, "ptr*", $widget), "cveWArrowCreate", @error)
EndFunc   ;==>_cveWArrowCreate

Func _cveWArrowRelease(ByRef $arrow)
    ; CVAPI(void) cveWArrowRelease(cv::viz::WArrow** arrow);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveWArrowRelease", "ptr*", $arrow), "cveWArrowRelease", @error)
EndFunc   ;==>_cveWArrowRelease