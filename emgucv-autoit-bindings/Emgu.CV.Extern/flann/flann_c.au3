#include-once
#include <..\..\CVEUtils.au3>

Func _cveLinearIndexParamsCreate(ByRef $ip)
    ; CVAPI(cv::flann::LinearIndexParams*) cveLinearIndexParamsCreate(cv::flann::IndexParams** ip);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLinearIndexParamsCreate", "ptr*", $ip), "cveLinearIndexParamsCreate", @error)
EndFunc   ;==>_cveLinearIndexParamsCreate

Func _cveLinearIndexParamsRelease(ByRef $p)
    ; CVAPI(void) cveLinearIndexParamsRelease(cv::flann::LinearIndexParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLinearIndexParamsRelease", "ptr*", $p), "cveLinearIndexParamsRelease", @error)
EndFunc   ;==>_cveLinearIndexParamsRelease

Func _cveKDTreeIndexParamsCreate(ByRef $ip, $trees)
    ; CVAPI(cv::flann::KDTreeIndexParams*) cveKDTreeIndexParamsCreate(cv::flann::IndexParams** ip, int trees);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKDTreeIndexParamsCreate", "ptr*", $ip, "int", $trees), "cveKDTreeIndexParamsCreate", @error)
EndFunc   ;==>_cveKDTreeIndexParamsCreate

Func _cveKDTreeIndexParamsRelease(ByRef $p)
    ; CVAPI(void) cveKDTreeIndexParamsRelease(cv::flann::KDTreeIndexParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKDTreeIndexParamsRelease", "ptr*", $p), "cveKDTreeIndexParamsRelease", @error)
EndFunc   ;==>_cveKDTreeIndexParamsRelease

Func _cveLshIndexParamsCreate(ByRef $ip, $tableNumber, $keySize, $multiProbeLevel)
    ; CVAPI(cv::flann::LshIndexParams*) cveLshIndexParamsCreate(cv::flann::IndexParams** ip, int tableNumber, int keySize, int multiProbeLevel);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLshIndexParamsCreate", "ptr*", $ip, "int", $tableNumber, "int", $keySize, "int", $multiProbeLevel), "cveLshIndexParamsCreate", @error)
EndFunc   ;==>_cveLshIndexParamsCreate

Func _cveLshIndexParamsRelease(ByRef $p)
    ; CVAPI(void) cveLshIndexParamsRelease(cv::flann::LshIndexParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLshIndexParamsRelease", "ptr*", $p), "cveLshIndexParamsRelease", @error)
EndFunc   ;==>_cveLshIndexParamsRelease

Func _cveKMeansIndexParamsCreate(ByRef $ip, $branching, $iterations, $centersInit, $cbIndex)
    ; CVAPI(cv::flann::KMeansIndexParams*) cveKMeansIndexParamsCreate(cv::flann::IndexParams** ip, int branching, int iterations, cvflann::flann_centers_init_t centersInit, float cbIndex);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKMeansIndexParamsCreate", "ptr*", $ip, "int", $branching, "int", $iterations, "cvflann::flann_centers_init_t", $centersInit, "float", $cbIndex), "cveKMeansIndexParamsCreate", @error)
EndFunc   ;==>_cveKMeansIndexParamsCreate

Func _cveKMeansIndexParamsRelease(ByRef $p)
    ; CVAPI(void) cveKMeansIndexParamsRelease(cv::flann::KMeansIndexParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKMeansIndexParamsRelease", "ptr*", $p), "cveKMeansIndexParamsRelease", @error)
EndFunc   ;==>_cveKMeansIndexParamsRelease

Func _cveCompositeIndexParamsCreate(ByRef $ip, $trees, $branching, $iterations, $centersInit, $cbIndex)
    ; CVAPI(cv::flann::CompositeIndexParams*) cveCompositeIndexParamsCreate(cv::flann::IndexParams** ip, int trees, int branching, int iterations, cvflann::flann_centers_init_t centersInit, float cbIndex);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCompositeIndexParamsCreate", "ptr*", $ip, "int", $trees, "int", $branching, "int", $iterations, "cvflann::flann_centers_init_t", $centersInit, "float", $cbIndex), "cveCompositeIndexParamsCreate", @error)
EndFunc   ;==>_cveCompositeIndexParamsCreate

Func _cveCompositeIndexParamsRelease(ByRef $p)
    ; CVAPI(void) cveCompositeIndexParamsRelease(cv::flann::CompositeIndexParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCompositeIndexParamsRelease", "ptr*", $p), "cveCompositeIndexParamsRelease", @error)
EndFunc   ;==>_cveCompositeIndexParamsRelease

Func _cveAutotunedIndexParamsCreate(ByRef $ip, $targetPrecision, $buildWeight, $memoryWeight, $sampleFraction)
    ; CVAPI(cv::flann::AutotunedIndexParams*) cveAutotunedIndexParamsCreate(cv::flann::IndexParams** ip, float targetPrecision, float buildWeight, float memoryWeight, float sampleFraction);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAutotunedIndexParamsCreate", "ptr*", $ip, "float", $targetPrecision, "float", $buildWeight, "float", $memoryWeight, "float", $sampleFraction), "cveAutotunedIndexParamsCreate", @error)
EndFunc   ;==>_cveAutotunedIndexParamsCreate

Func _cveAutotunedIndexParamsRelease(ByRef $p)
    ; CVAPI(void) cveAutotunedIndexParamsRelease(cv::flann::AutotunedIndexParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAutotunedIndexParamsRelease", "ptr*", $p), "cveAutotunedIndexParamsRelease", @error)
EndFunc   ;==>_cveAutotunedIndexParamsRelease

Func _cveHierarchicalClusteringIndexParamsCreate(ByRef $ip, $branching, $centersInit, $trees, $leafSize)
    ; CVAPI(cv::flann::HierarchicalClusteringIndexParams*) cveHierarchicalClusteringIndexParamsCreate(cv::flann::IndexParams** ip, int branching, cvflann::flann_centers_init_t centersInit, int trees, int leafSize);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHierarchicalClusteringIndexParamsCreate", "ptr*", $ip, "int", $branching, "cvflann::flann_centers_init_t", $centersInit, "int", $trees, "int", $leafSize), "cveHierarchicalClusteringIndexParamsCreate", @error)
EndFunc   ;==>_cveHierarchicalClusteringIndexParamsCreate

Func _cveHierarchicalClusteringIndexParamsRelease(ByRef $p)
    ; CVAPI(void) cveHierarchicalClusteringIndexParamsRelease(cv::flann::HierarchicalClusteringIndexParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHierarchicalClusteringIndexParamsRelease", "ptr*", $p), "cveHierarchicalClusteringIndexParamsRelease", @error)
EndFunc   ;==>_cveHierarchicalClusteringIndexParamsRelease

Func _cveSearchParamsCreate(ByRef $ip, $checks, $eps, $sorted)
    ; CVAPI(cv::flann::SearchParams*) cveSearchParamsCreate(cv::flann::IndexParams** ip, int checks, float eps, bool sorted);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSearchParamsCreate", "ptr*", $ip, "int", $checks, "float", $eps, "boolean", $sorted), "cveSearchParamsCreate", @error)
EndFunc   ;==>_cveSearchParamsCreate

Func _cveSearchParamsRelease(ByRef $p)
    ; CVAPI(void) cveSearchParamsRelease(cv::flann::SearchParams** p);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSearchParamsRelease", "ptr*", $p), "cveSearchParamsRelease", @error)
EndFunc   ;==>_cveSearchParamsRelease

Func _cveFlannIndexCreate(ByRef $features, ByRef $p, $distType)
    ; CVAPI(cv::flann::Index*) cveFlannIndexCreate(cv::_InputArray* features, cv::flann::IndexParams* p, int distType);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFlannIndexCreate", "ptr", $features, "ptr", $p, "int", $distType), "cveFlannIndexCreate", @error)
EndFunc   ;==>_cveFlannIndexCreate

Func _cveFlannIndexCreateMat(ByRef $matFeatures, ByRef $p, $distType)
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

Func _cveFlannIndexKnnSearch(ByRef $index, ByRef $queries, ByRef $indices, ByRef $dists, $knn, $checks, $eps, $sorted)
    ; CVAPI(void) cveFlannIndexKnnSearch(cv::flann::Index* index, cv::_InputArray* queries, cv::_OutputArray* indices, cv::_OutputArray* dists, int knn, int checks, float eps, bool sorted);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannIndexKnnSearch", "ptr", $index, "ptr", $queries, "ptr", $indices, "ptr", $dists, "int", $knn, "int", $checks, "float", $eps, "boolean", $sorted), "cveFlannIndexKnnSearch", @error)
EndFunc   ;==>_cveFlannIndexKnnSearch

Func _cveFlannIndexKnnSearchMat(ByRef $index, ByRef $matQueries, ByRef $matIndices, ByRef $matDists, $knn, $checks, $eps, $sorted)
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

Func _cveFlannIndexRadiusSearch(ByRef $index, ByRef $queries, ByRef $indices, ByRef $dists, $radius, $maxResults, $checks, $eps, $sorted)
    ; CVAPI(int) cveFlannIndexRadiusSearch(cv::flann::Index* index, cv::_InputArray* queries, cv::_OutputArray* indices, cv::_OutputArray* dists, double radius, int maxResults, int checks, float eps, bool sorted);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFlannIndexRadiusSearch", "ptr", $index, "ptr", $queries, "ptr", $indices, "ptr", $dists, "double", $radius, "int", $maxResults, "int", $checks, "float", $eps, "boolean", $sorted), "cveFlannIndexRadiusSearch", @error)
EndFunc   ;==>_cveFlannIndexRadiusSearch

Func _cveFlannIndexRadiusSearchMat(ByRef $index, ByRef $matQueries, ByRef $matIndices, ByRef $matDists, $radius, $maxResults, $checks, $eps, $sorted)
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

Func _cveFlannIndexRelease(ByRef $index)
    ; CVAPI(void) cveFlannIndexRelease(cv::flann::Index** index);
    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannIndexRelease", "ptr*", $index), "cveFlannIndexRelease", @error)
EndFunc   ;==>_cveFlannIndexRelease