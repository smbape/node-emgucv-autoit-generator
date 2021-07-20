#include-once
#include "..\..\CVEUtils.au3"

Func _cveLinearIndexParamsCreate($ip)
    ; CVAPI(cv::flann::LinearIndexParams*) cveLinearIndexParamsCreate(cv::flann::IndexParams** ip);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLinearIndexParamsCreate", $bIpDllType, $ip), "cveLinearIndexParamsCreate", @error)
EndFunc   ;==>_cveLinearIndexParamsCreate

Func _cveLinearIndexParamsRelease($p)
    ; CVAPI(void) cveLinearIndexParamsRelease(cv::flann::LinearIndexParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLinearIndexParamsRelease", $bPDllType, $p), "cveLinearIndexParamsRelease", @error)
EndFunc   ;==>_cveLinearIndexParamsRelease

Func _cveKDTreeIndexParamsCreate($ip, $trees)
    ; CVAPI(cv::flann::KDTreeIndexParams*) cveKDTreeIndexParamsCreate(cv::flann::IndexParams** ip, int trees);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKDTreeIndexParamsCreate", $bIpDllType, $ip, "int", $trees), "cveKDTreeIndexParamsCreate", @error)
EndFunc   ;==>_cveKDTreeIndexParamsCreate

Func _cveKDTreeIndexParamsRelease($p)
    ; CVAPI(void) cveKDTreeIndexParamsRelease(cv::flann::KDTreeIndexParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKDTreeIndexParamsRelease", $bPDllType, $p), "cveKDTreeIndexParamsRelease", @error)
EndFunc   ;==>_cveKDTreeIndexParamsRelease

Func _cveLshIndexParamsCreate($ip, $tableNumber, $keySize, $multiProbeLevel)
    ; CVAPI(cv::flann::LshIndexParams*) cveLshIndexParamsCreate(cv::flann::IndexParams** ip, int tableNumber, int keySize, int multiProbeLevel);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLshIndexParamsCreate", $bIpDllType, $ip, "int", $tableNumber, "int", $keySize, "int", $multiProbeLevel), "cveLshIndexParamsCreate", @error)
EndFunc   ;==>_cveLshIndexParamsCreate

Func _cveLshIndexParamsRelease($p)
    ; CVAPI(void) cveLshIndexParamsRelease(cv::flann::LshIndexParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLshIndexParamsRelease", $bPDllType, $p), "cveLshIndexParamsRelease", @error)
EndFunc   ;==>_cveLshIndexParamsRelease

Func _cveKMeansIndexParamsCreate($ip, $branching, $iterations, $centersInit, $cbIndex)
    ; CVAPI(cv::flann::KMeansIndexParams*) cveKMeansIndexParamsCreate(cv::flann::IndexParams** ip, int branching, int iterations, cvflann::flann_centers_init_t centersInit, float cbIndex);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKMeansIndexParamsCreate", $bIpDllType, $ip, "int", $branching, "int", $iterations, "cvflann::flann_centers_init_t", $centersInit, "float", $cbIndex), "cveKMeansIndexParamsCreate", @error)
EndFunc   ;==>_cveKMeansIndexParamsCreate

Func _cveKMeansIndexParamsRelease($p)
    ; CVAPI(void) cveKMeansIndexParamsRelease(cv::flann::KMeansIndexParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKMeansIndexParamsRelease", $bPDllType, $p), "cveKMeansIndexParamsRelease", @error)
EndFunc   ;==>_cveKMeansIndexParamsRelease

Func _cveCompositeIndexParamsCreate($ip, $trees, $branching, $iterations, $centersInit, $cbIndex)
    ; CVAPI(cv::flann::CompositeIndexParams*) cveCompositeIndexParamsCreate(cv::flann::IndexParams** ip, int trees, int branching, int iterations, cvflann::flann_centers_init_t centersInit, float cbIndex);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCompositeIndexParamsCreate", $bIpDllType, $ip, "int", $trees, "int", $branching, "int", $iterations, "cvflann::flann_centers_init_t", $centersInit, "float", $cbIndex), "cveCompositeIndexParamsCreate", @error)
EndFunc   ;==>_cveCompositeIndexParamsCreate

Func _cveCompositeIndexParamsRelease($p)
    ; CVAPI(void) cveCompositeIndexParamsRelease(cv::flann::CompositeIndexParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCompositeIndexParamsRelease", $bPDllType, $p), "cveCompositeIndexParamsRelease", @error)
EndFunc   ;==>_cveCompositeIndexParamsRelease

Func _cveAutotunedIndexParamsCreate($ip, $targetPrecision, $buildWeight, $memoryWeight, $sampleFraction)
    ; CVAPI(cv::flann::AutotunedIndexParams*) cveAutotunedIndexParamsCreate(cv::flann::IndexParams** ip, float targetPrecision, float buildWeight, float memoryWeight, float sampleFraction);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAutotunedIndexParamsCreate", $bIpDllType, $ip, "float", $targetPrecision, "float", $buildWeight, "float", $memoryWeight, "float", $sampleFraction), "cveAutotunedIndexParamsCreate", @error)
EndFunc   ;==>_cveAutotunedIndexParamsCreate

Func _cveAutotunedIndexParamsRelease($p)
    ; CVAPI(void) cveAutotunedIndexParamsRelease(cv::flann::AutotunedIndexParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAutotunedIndexParamsRelease", $bPDllType, $p), "cveAutotunedIndexParamsRelease", @error)
EndFunc   ;==>_cveAutotunedIndexParamsRelease

Func _cveHierarchicalClusteringIndexParamsCreate($ip, $branching, $centersInit, $trees, $leafSize)
    ; CVAPI(cv::flann::HierarchicalClusteringIndexParams*) cveHierarchicalClusteringIndexParamsCreate(cv::flann::IndexParams** ip, int branching, cvflann::flann_centers_init_t centersInit, int trees, int leafSize);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHierarchicalClusteringIndexParamsCreate", $bIpDllType, $ip, "int", $branching, "cvflann::flann_centers_init_t", $centersInit, "int", $trees, "int", $leafSize), "cveHierarchicalClusteringIndexParamsCreate", @error)
EndFunc   ;==>_cveHierarchicalClusteringIndexParamsCreate

Func _cveHierarchicalClusteringIndexParamsRelease($p)
    ; CVAPI(void) cveHierarchicalClusteringIndexParamsRelease(cv::flann::HierarchicalClusteringIndexParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHierarchicalClusteringIndexParamsRelease", $bPDllType, $p), "cveHierarchicalClusteringIndexParamsRelease", @error)
EndFunc   ;==>_cveHierarchicalClusteringIndexParamsRelease

Func _cveSearchParamsCreate($ip, $checks, $eps, $sorted)
    ; CVAPI(cv::flann::SearchParams*) cveSearchParamsCreate(cv::flann::IndexParams** ip, int checks, float eps, bool sorted);

    Local $bIpDllType
    If VarGetType($ip) == "DLLStruct" Then
        $bIpDllType = "struct*"
    Else
        $bIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSearchParamsCreate", $bIpDllType, $ip, "int", $checks, "float", $eps, "boolean", $sorted), "cveSearchParamsCreate", @error)
EndFunc   ;==>_cveSearchParamsCreate

Func _cveSearchParamsRelease($p)
    ; CVAPI(void) cveSearchParamsRelease(cv::flann::SearchParams** p);

    Local $bPDllType
    If VarGetType($p) == "DLLStruct" Then
        $bPDllType = "struct*"
    Else
        $bPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSearchParamsRelease", $bPDllType, $p), "cveSearchParamsRelease", @error)
EndFunc   ;==>_cveSearchParamsRelease

Func _cveFlannIndexCreate($features, $p, $distType)
    ; CVAPI(cv::flann::Index*) cveFlannIndexCreate(cv::_InputArray* features, cv::flann::IndexParams* p, int distType);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFlannIndexCreate", "ptr", $features, "ptr", $p, "int", $distType), "cveFlannIndexCreate", @error)
EndFunc   ;==>_cveFlannIndexCreate

Func _cveFlannIndexCreateMat($matFeatures, $p, $distType)
    ; cveFlannIndexCreate using cv::Mat instead of _*Array

    Local $iArrFeatures, $vectorOfMatFeatures, $iArrFeaturesSize
    Local $bFeaturesIsArray = VarGetType($matFeatures) == "Array"

    If $bFeaturesIsArray Then
        $vectorOfMatFeatures = _VectorOfMatCreate()

        $iArrFeaturesSize = UBound($matFeatures)
        For $i = 0 To $iArrFeaturesSize - 1
            _VectorOfMatPush($vectorOfMatFeatures, $matFeatures[$i])
        Next

        $iArrFeatures = _cveInputArrayFromVectorOfMat($vectorOfMatFeatures)
    Else
        $iArrFeatures = _cveInputArrayFromMat($matFeatures)
    EndIf

    Local $retval = _cveFlannIndexCreate($iArrFeatures, $p, $distType)

    If $bFeaturesIsArray Then
        _VectorOfMatRelease($vectorOfMatFeatures)
    EndIf

    _cveInputArrayRelease($iArrFeatures)

    Return $retval
EndFunc   ;==>_cveFlannIndexCreateMat

Func _cveFlannIndexKnnSearch($index, $queries, $indices, $dists, $knn, $checks, $eps, $sorted)
    ; CVAPI(void) cveFlannIndexKnnSearch(cv::flann::Index* index, cv::_InputArray* queries, cv::_OutputArray* indices, cv::_OutputArray* dists, int knn, int checks, float eps, bool sorted);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannIndexKnnSearch", "ptr", $index, "ptr", $queries, "ptr", $indices, "ptr", $dists, "int", $knn, "int", $checks, "float", $eps, "boolean", $sorted), "cveFlannIndexKnnSearch", @error)
EndFunc   ;==>_cveFlannIndexKnnSearch

Func _cveFlannIndexKnnSearchMat($index, $matQueries, $matIndices, $matDists, $knn, $checks, $eps, $sorted)
    ; cveFlannIndexKnnSearch using cv::Mat instead of _*Array

    Local $iArrQueries, $vectorOfMatQueries, $iArrQueriesSize
    Local $bQueriesIsArray = VarGetType($matQueries) == "Array"

    If $bQueriesIsArray Then
        $vectorOfMatQueries = _VectorOfMatCreate()

        $iArrQueriesSize = UBound($matQueries)
        For $i = 0 To $iArrQueriesSize - 1
            _VectorOfMatPush($vectorOfMatQueries, $matQueries[$i])
        Next

        $iArrQueries = _cveInputArrayFromVectorOfMat($vectorOfMatQueries)
    Else
        $iArrQueries = _cveInputArrayFromMat($matQueries)
    EndIf

    Local $oArrIndices, $vectorOfMatIndices, $iArrIndicesSize
    Local $bIndicesIsArray = VarGetType($matIndices) == "Array"

    If $bIndicesIsArray Then
        $vectorOfMatIndices = _VectorOfMatCreate()

        $iArrIndicesSize = UBound($matIndices)
        For $i = 0 To $iArrIndicesSize - 1
            _VectorOfMatPush($vectorOfMatIndices, $matIndices[$i])
        Next

        $oArrIndices = _cveOutputArrayFromVectorOfMat($vectorOfMatIndices)
    Else
        $oArrIndices = _cveOutputArrayFromMat($matIndices)
    EndIf

    Local $oArrDists, $vectorOfMatDists, $iArrDistsSize
    Local $bDistsIsArray = VarGetType($matDists) == "Array"

    If $bDistsIsArray Then
        $vectorOfMatDists = _VectorOfMatCreate()

        $iArrDistsSize = UBound($matDists)
        For $i = 0 To $iArrDistsSize - 1
            _VectorOfMatPush($vectorOfMatDists, $matDists[$i])
        Next

        $oArrDists = _cveOutputArrayFromVectorOfMat($vectorOfMatDists)
    Else
        $oArrDists = _cveOutputArrayFromMat($matDists)
    EndIf

    _cveFlannIndexKnnSearch($index, $iArrQueries, $oArrIndices, $oArrDists, $knn, $checks, $eps, $sorted)

    If $bDistsIsArray Then
        _VectorOfMatRelease($vectorOfMatDists)
    EndIf

    _cveOutputArrayRelease($oArrDists)

    If $bIndicesIsArray Then
        _VectorOfMatRelease($vectorOfMatIndices)
    EndIf

    _cveOutputArrayRelease($oArrIndices)

    If $bQueriesIsArray Then
        _VectorOfMatRelease($vectorOfMatQueries)
    EndIf

    _cveInputArrayRelease($iArrQueries)
EndFunc   ;==>_cveFlannIndexKnnSearchMat

Func _cveFlannIndexRadiusSearch($index, $queries, $indices, $dists, $radius, $maxResults, $checks, $eps, $sorted)
    ; CVAPI(int) cveFlannIndexRadiusSearch(cv::flann::Index* index, cv::_InputArray* queries, cv::_OutputArray* indices, cv::_OutputArray* dists, double radius, int maxResults, int checks, float eps, bool sorted);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFlannIndexRadiusSearch", "ptr", $index, "ptr", $queries, "ptr", $indices, "ptr", $dists, "double", $radius, "int", $maxResults, "int", $checks, "float", $eps, "boolean", $sorted), "cveFlannIndexRadiusSearch", @error)
EndFunc   ;==>_cveFlannIndexRadiusSearch

Func _cveFlannIndexRadiusSearchMat($index, $matQueries, $matIndices, $matDists, $radius, $maxResults, $checks, $eps, $sorted)
    ; cveFlannIndexRadiusSearch using cv::Mat instead of _*Array

    Local $iArrQueries, $vectorOfMatQueries, $iArrQueriesSize
    Local $bQueriesIsArray = VarGetType($matQueries) == "Array"

    If $bQueriesIsArray Then
        $vectorOfMatQueries = _VectorOfMatCreate()

        $iArrQueriesSize = UBound($matQueries)
        For $i = 0 To $iArrQueriesSize - 1
            _VectorOfMatPush($vectorOfMatQueries, $matQueries[$i])
        Next

        $iArrQueries = _cveInputArrayFromVectorOfMat($vectorOfMatQueries)
    Else
        $iArrQueries = _cveInputArrayFromMat($matQueries)
    EndIf

    Local $oArrIndices, $vectorOfMatIndices, $iArrIndicesSize
    Local $bIndicesIsArray = VarGetType($matIndices) == "Array"

    If $bIndicesIsArray Then
        $vectorOfMatIndices = _VectorOfMatCreate()

        $iArrIndicesSize = UBound($matIndices)
        For $i = 0 To $iArrIndicesSize - 1
            _VectorOfMatPush($vectorOfMatIndices, $matIndices[$i])
        Next

        $oArrIndices = _cveOutputArrayFromVectorOfMat($vectorOfMatIndices)
    Else
        $oArrIndices = _cveOutputArrayFromMat($matIndices)
    EndIf

    Local $oArrDists, $vectorOfMatDists, $iArrDistsSize
    Local $bDistsIsArray = VarGetType($matDists) == "Array"

    If $bDistsIsArray Then
        $vectorOfMatDists = _VectorOfMatCreate()

        $iArrDistsSize = UBound($matDists)
        For $i = 0 To $iArrDistsSize - 1
            _VectorOfMatPush($vectorOfMatDists, $matDists[$i])
        Next

        $oArrDists = _cveOutputArrayFromVectorOfMat($vectorOfMatDists)
    Else
        $oArrDists = _cveOutputArrayFromMat($matDists)
    EndIf

    Local $retval = _cveFlannIndexRadiusSearch($index, $iArrQueries, $oArrIndices, $oArrDists, $radius, $maxResults, $checks, $eps, $sorted)

    If $bDistsIsArray Then
        _VectorOfMatRelease($vectorOfMatDists)
    EndIf

    _cveOutputArrayRelease($oArrDists)

    If $bIndicesIsArray Then
        _VectorOfMatRelease($vectorOfMatIndices)
    EndIf

    _cveOutputArrayRelease($oArrIndices)

    If $bQueriesIsArray Then
        _VectorOfMatRelease($vectorOfMatQueries)
    EndIf

    _cveInputArrayRelease($iArrQueries)

    Return $retval
EndFunc   ;==>_cveFlannIndexRadiusSearchMat

Func _cveFlannIndexRelease($index)
    ; CVAPI(void) cveFlannIndexRelease(cv::flann::Index** index);

    Local $bIndexDllType
    If VarGetType($index) == "DLLStruct" Then
        $bIndexDllType = "struct*"
    Else
        $bIndexDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannIndexRelease", $bIndexDllType, $index), "cveFlannIndexRelease", @error)
EndFunc   ;==>_cveFlannIndexRelease