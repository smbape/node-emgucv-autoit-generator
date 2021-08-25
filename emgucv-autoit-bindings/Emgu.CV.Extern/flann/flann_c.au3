#include-once
#include "..\..\CVEUtils.au3"

Func _cveLinearIndexParamsCreate($ip)
    ; CVAPI(cv::flann::LinearIndexParams*) cveLinearIndexParamsCreate(cv::flann::IndexParams** ip);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLinearIndexParamsCreate", $sIpDllType, $ip), "cveLinearIndexParamsCreate", @error)
EndFunc   ;==>_cveLinearIndexParamsCreate

Func _cveLinearIndexParamsRelease($p)
    ; CVAPI(void) cveLinearIndexParamsRelease(cv::flann::LinearIndexParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLinearIndexParamsRelease", $sPDllType, $p), "cveLinearIndexParamsRelease", @error)
EndFunc   ;==>_cveLinearIndexParamsRelease

Func _cveKDTreeIndexParamsCreate($ip, $trees)
    ; CVAPI(cv::flann::KDTreeIndexParams*) cveKDTreeIndexParamsCreate(cv::flann::IndexParams** ip, int trees);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKDTreeIndexParamsCreate", $sIpDllType, $ip, "int", $trees), "cveKDTreeIndexParamsCreate", @error)
EndFunc   ;==>_cveKDTreeIndexParamsCreate

Func _cveKDTreeIndexParamsRelease($p)
    ; CVAPI(void) cveKDTreeIndexParamsRelease(cv::flann::KDTreeIndexParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKDTreeIndexParamsRelease", $sPDllType, $p), "cveKDTreeIndexParamsRelease", @error)
EndFunc   ;==>_cveKDTreeIndexParamsRelease

Func _cveLshIndexParamsCreate($ip, $tableNumber, $keySize, $multiProbeLevel)
    ; CVAPI(cv::flann::LshIndexParams*) cveLshIndexParamsCreate(cv::flann::IndexParams** ip, int tableNumber, int keySize, int multiProbeLevel);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveLshIndexParamsCreate", $sIpDllType, $ip, "int", $tableNumber, "int", $keySize, "int", $multiProbeLevel), "cveLshIndexParamsCreate", @error)
EndFunc   ;==>_cveLshIndexParamsCreate

Func _cveLshIndexParamsRelease($p)
    ; CVAPI(void) cveLshIndexParamsRelease(cv::flann::LshIndexParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveLshIndexParamsRelease", $sPDllType, $p), "cveLshIndexParamsRelease", @error)
EndFunc   ;==>_cveLshIndexParamsRelease

Func _cveKMeansIndexParamsCreate($ip, $branching, $iterations, $centersInit, $cbIndex)
    ; CVAPI(cv::flann::KMeansIndexParams*) cveKMeansIndexParamsCreate(cv::flann::IndexParams** ip, int branching, int iterations, cvflann::flann_centers_init_t centersInit, float cbIndex);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveKMeansIndexParamsCreate", $sIpDllType, $ip, "int", $branching, "int", $iterations, "int", $centersInit, "float", $cbIndex), "cveKMeansIndexParamsCreate", @error)
EndFunc   ;==>_cveKMeansIndexParamsCreate

Func _cveKMeansIndexParamsRelease($p)
    ; CVAPI(void) cveKMeansIndexParamsRelease(cv::flann::KMeansIndexParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveKMeansIndexParamsRelease", $sPDllType, $p), "cveKMeansIndexParamsRelease", @error)
EndFunc   ;==>_cveKMeansIndexParamsRelease

Func _cveCompositeIndexParamsCreate($ip, $trees, $branching, $iterations, $centersInit, $cbIndex)
    ; CVAPI(cv::flann::CompositeIndexParams*) cveCompositeIndexParamsCreate(cv::flann::IndexParams** ip, int trees, int branching, int iterations, cvflann::flann_centers_init_t centersInit, float cbIndex);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveCompositeIndexParamsCreate", $sIpDllType, $ip, "int", $trees, "int", $branching, "int", $iterations, "int", $centersInit, "float", $cbIndex), "cveCompositeIndexParamsCreate", @error)
EndFunc   ;==>_cveCompositeIndexParamsCreate

Func _cveCompositeIndexParamsRelease($p)
    ; CVAPI(void) cveCompositeIndexParamsRelease(cv::flann::CompositeIndexParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveCompositeIndexParamsRelease", $sPDllType, $p), "cveCompositeIndexParamsRelease", @error)
EndFunc   ;==>_cveCompositeIndexParamsRelease

Func _cveAutotunedIndexParamsCreate($ip, $targetPrecision, $buildWeight, $memoryWeight, $sampleFraction)
    ; CVAPI(cv::flann::AutotunedIndexParams*) cveAutotunedIndexParamsCreate(cv::flann::IndexParams** ip, float targetPrecision, float buildWeight, float memoryWeight, float sampleFraction);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveAutotunedIndexParamsCreate", $sIpDllType, $ip, "float", $targetPrecision, "float", $buildWeight, "float", $memoryWeight, "float", $sampleFraction), "cveAutotunedIndexParamsCreate", @error)
EndFunc   ;==>_cveAutotunedIndexParamsCreate

Func _cveAutotunedIndexParamsRelease($p)
    ; CVAPI(void) cveAutotunedIndexParamsRelease(cv::flann::AutotunedIndexParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveAutotunedIndexParamsRelease", $sPDllType, $p), "cveAutotunedIndexParamsRelease", @error)
EndFunc   ;==>_cveAutotunedIndexParamsRelease

Func _cveHierarchicalClusteringIndexParamsCreate($ip, $branching, $centersInit, $trees, $leafSize)
    ; CVAPI(cv::flann::HierarchicalClusteringIndexParams*) cveHierarchicalClusteringIndexParamsCreate(cv::flann::IndexParams** ip, int branching, cvflann::flann_centers_init_t centersInit, int trees, int leafSize);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveHierarchicalClusteringIndexParamsCreate", $sIpDllType, $ip, "int", $branching, "int", $centersInit, "int", $trees, "int", $leafSize), "cveHierarchicalClusteringIndexParamsCreate", @error)
EndFunc   ;==>_cveHierarchicalClusteringIndexParamsCreate

Func _cveHierarchicalClusteringIndexParamsRelease($p)
    ; CVAPI(void) cveHierarchicalClusteringIndexParamsRelease(cv::flann::HierarchicalClusteringIndexParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveHierarchicalClusteringIndexParamsRelease", $sPDllType, $p), "cveHierarchicalClusteringIndexParamsRelease", @error)
EndFunc   ;==>_cveHierarchicalClusteringIndexParamsRelease

Func _cveSearchParamsCreate($ip, $checks, $eps, $sorted)
    ; CVAPI(cv::flann::SearchParams*) cveSearchParamsCreate(cv::flann::IndexParams** ip, int checks, float eps, bool sorted);

    Local $sIpDllType
    If IsDllStruct($ip) Then
        $sIpDllType = "struct*"
    ElseIf $ip == Null Then
        $sIpDllType = "ptr"
    Else
        $sIpDllType = "ptr*"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveSearchParamsCreate", $sIpDllType, $ip, "int", $checks, "float", $eps, "boolean", $sorted), "cveSearchParamsCreate", @error)
EndFunc   ;==>_cveSearchParamsCreate

Func _cveSearchParamsRelease($p)
    ; CVAPI(void) cveSearchParamsRelease(cv::flann::SearchParams** p);

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    ElseIf $p == Null Then
        $sPDllType = "ptr"
    Else
        $sPDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveSearchParamsRelease", $sPDllType, $p), "cveSearchParamsRelease", @error)
EndFunc   ;==>_cveSearchParamsRelease

Func _cveFlannIndexCreate($features, $p, $distType)
    ; CVAPI(cv::flann::Index*) cveFlannIndexCreate(cv::_InputArray* features, cv::flann::IndexParams* p, int distType);

    Local $sFeaturesDllType
    If IsDllStruct($features) Then
        $sFeaturesDllType = "struct*"
    Else
        $sFeaturesDllType = "ptr"
    EndIf

    Local $sPDllType
    If IsDllStruct($p) Then
        $sPDllType = "struct*"
    Else
        $sPDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveFlannIndexCreate", $sFeaturesDllType, $features, $sPDllType, $p, "int", $distType), "cveFlannIndexCreate", @error)
EndFunc   ;==>_cveFlannIndexCreate

Func _cveFlannIndexCreateTyped($typeOfFeatures, $features, $p, $distType)

    Local $iArrFeatures, $vectorFeatures, $iArrFeaturesSize
    Local $bFeaturesIsArray = IsArray($features)
    Local $bFeaturesCreate = IsDllStruct($features) And $typeOfFeatures == "Scalar"

    If $typeOfFeatures == Default Then
        $iArrFeatures = $features
    ElseIf $bFeaturesIsArray Then
        $vectorFeatures = Call("_VectorOf" & $typeOfFeatures & "Create")

        $iArrFeaturesSize = UBound($features)
        For $i = 0 To $iArrFeaturesSize - 1
            Call("_VectorOf" & $typeOfFeatures & "Push", $vectorFeatures, $features[$i])
        Next

        $iArrFeatures = Call("_cveInputArrayFromVectorOf" & $typeOfFeatures, $vectorFeatures)
    Else
        If $bFeaturesCreate Then
            $features = Call("_cve" & $typeOfFeatures & "Create", $features)
        EndIf
        $iArrFeatures = Call("_cveInputArrayFrom" & $typeOfFeatures, $features)
    EndIf

    Local $retval = _cveFlannIndexCreate($iArrFeatures, $p, $distType)

    If $bFeaturesIsArray Then
        Call("_VectorOf" & $typeOfFeatures & "Release", $vectorFeatures)
    EndIf

    If $typeOfFeatures <> Default Then
        _cveInputArrayRelease($iArrFeatures)
        If $bFeaturesCreate Then
            Call("_cve" & $typeOfFeatures & "Release", $features)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveFlannIndexCreateTyped

Func _cveFlannIndexCreateMat($features, $p, $distType)
    ; cveFlannIndexCreate using cv::Mat instead of _*Array
    Local $retval = _cveFlannIndexCreateTyped("Mat", $features, $p, $distType)

    Return $retval
EndFunc   ;==>_cveFlannIndexCreateMat

Func _cveFlannIndexKnnSearch($index, $queries, $indices, $dists, $knn, $checks, $eps, $sorted)
    ; CVAPI(void) cveFlannIndexKnnSearch(cv::flann::Index* index, cv::_InputArray* queries, cv::_OutputArray* indices, cv::_OutputArray* dists, int knn, int checks, float eps, bool sorted);

    Local $sIndexDllType
    If IsDllStruct($index) Then
        $sIndexDllType = "struct*"
    Else
        $sIndexDllType = "ptr"
    EndIf

    Local $sQueriesDllType
    If IsDllStruct($queries) Then
        $sQueriesDllType = "struct*"
    Else
        $sQueriesDllType = "ptr"
    EndIf

    Local $sIndicesDllType
    If IsDllStruct($indices) Then
        $sIndicesDllType = "struct*"
    Else
        $sIndicesDllType = "ptr"
    EndIf

    Local $sDistsDllType
    If IsDllStruct($dists) Then
        $sDistsDllType = "struct*"
    Else
        $sDistsDllType = "ptr"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannIndexKnnSearch", $sIndexDllType, $index, $sQueriesDllType, $queries, $sIndicesDllType, $indices, $sDistsDllType, $dists, "int", $knn, "int", $checks, "float", $eps, "boolean", $sorted), "cveFlannIndexKnnSearch", @error)
EndFunc   ;==>_cveFlannIndexKnnSearch

Func _cveFlannIndexKnnSearchTyped($index, $typeOfQueries, $queries, $typeOfIndices, $indices, $typeOfDists, $dists, $knn, $checks, $eps, $sorted)

    Local $iArrQueries, $vectorQueries, $iArrQueriesSize
    Local $bQueriesIsArray = IsArray($queries)
    Local $bQueriesCreate = IsDllStruct($queries) And $typeOfQueries == "Scalar"

    If $typeOfQueries == Default Then
        $iArrQueries = $queries
    ElseIf $bQueriesIsArray Then
        $vectorQueries = Call("_VectorOf" & $typeOfQueries & "Create")

        $iArrQueriesSize = UBound($queries)
        For $i = 0 To $iArrQueriesSize - 1
            Call("_VectorOf" & $typeOfQueries & "Push", $vectorQueries, $queries[$i])
        Next

        $iArrQueries = Call("_cveInputArrayFromVectorOf" & $typeOfQueries, $vectorQueries)
    Else
        If $bQueriesCreate Then
            $queries = Call("_cve" & $typeOfQueries & "Create", $queries)
        EndIf
        $iArrQueries = Call("_cveInputArrayFrom" & $typeOfQueries, $queries)
    EndIf

    Local $oArrIndices, $vectorIndices, $iArrIndicesSize
    Local $bIndicesIsArray = IsArray($indices)
    Local $bIndicesCreate = IsDllStruct($indices) And $typeOfIndices == "Scalar"

    If $typeOfIndices == Default Then
        $oArrIndices = $indices
    ElseIf $bIndicesIsArray Then
        $vectorIndices = Call("_VectorOf" & $typeOfIndices & "Create")

        $iArrIndicesSize = UBound($indices)
        For $i = 0 To $iArrIndicesSize - 1
            Call("_VectorOf" & $typeOfIndices & "Push", $vectorIndices, $indices[$i])
        Next

        $oArrIndices = Call("_cveOutputArrayFromVectorOf" & $typeOfIndices, $vectorIndices)
    Else
        If $bIndicesCreate Then
            $indices = Call("_cve" & $typeOfIndices & "Create", $indices)
        EndIf
        $oArrIndices = Call("_cveOutputArrayFrom" & $typeOfIndices, $indices)
    EndIf

    Local $oArrDists, $vectorDists, $iArrDistsSize
    Local $bDistsIsArray = IsArray($dists)
    Local $bDistsCreate = IsDllStruct($dists) And $typeOfDists == "Scalar"

    If $typeOfDists == Default Then
        $oArrDists = $dists
    ElseIf $bDistsIsArray Then
        $vectorDists = Call("_VectorOf" & $typeOfDists & "Create")

        $iArrDistsSize = UBound($dists)
        For $i = 0 To $iArrDistsSize - 1
            Call("_VectorOf" & $typeOfDists & "Push", $vectorDists, $dists[$i])
        Next

        $oArrDists = Call("_cveOutputArrayFromVectorOf" & $typeOfDists, $vectorDists)
    Else
        If $bDistsCreate Then
            $dists = Call("_cve" & $typeOfDists & "Create", $dists)
        EndIf
        $oArrDists = Call("_cveOutputArrayFrom" & $typeOfDists, $dists)
    EndIf

    _cveFlannIndexKnnSearch($index, $iArrQueries, $oArrIndices, $oArrDists, $knn, $checks, $eps, $sorted)

    If $bDistsIsArray Then
        Call("_VectorOf" & $typeOfDists & "Release", $vectorDists)
    EndIf

    If $typeOfDists <> Default Then
        _cveOutputArrayRelease($oArrDists)
        If $bDistsCreate Then
            Call("_cve" & $typeOfDists & "Release", $dists)
        EndIf
    EndIf

    If $bIndicesIsArray Then
        Call("_VectorOf" & $typeOfIndices & "Release", $vectorIndices)
    EndIf

    If $typeOfIndices <> Default Then
        _cveOutputArrayRelease($oArrIndices)
        If $bIndicesCreate Then
            Call("_cve" & $typeOfIndices & "Release", $indices)
        EndIf
    EndIf

    If $bQueriesIsArray Then
        Call("_VectorOf" & $typeOfQueries & "Release", $vectorQueries)
    EndIf

    If $typeOfQueries <> Default Then
        _cveInputArrayRelease($iArrQueries)
        If $bQueriesCreate Then
            Call("_cve" & $typeOfQueries & "Release", $queries)
        EndIf
    EndIf
EndFunc   ;==>_cveFlannIndexKnnSearchTyped

Func _cveFlannIndexKnnSearchMat($index, $queries, $indices, $dists, $knn, $checks, $eps, $sorted)
    ; cveFlannIndexKnnSearch using cv::Mat instead of _*Array
    _cveFlannIndexKnnSearchTyped($index, "Mat", $queries, "Mat", $indices, "Mat", $dists, $knn, $checks, $eps, $sorted)
EndFunc   ;==>_cveFlannIndexKnnSearchMat

Func _cveFlannIndexRadiusSearch($index, $queries, $indices, $dists, $radius, $maxResults, $checks, $eps, $sorted)
    ; CVAPI(int) cveFlannIndexRadiusSearch(cv::flann::Index* index, cv::_InputArray* queries, cv::_OutputArray* indices, cv::_OutputArray* dists, double radius, int maxResults, int checks, float eps, bool sorted);

    Local $sIndexDllType
    If IsDllStruct($index) Then
        $sIndexDllType = "struct*"
    Else
        $sIndexDllType = "ptr"
    EndIf

    Local $sQueriesDllType
    If IsDllStruct($queries) Then
        $sQueriesDllType = "struct*"
    Else
        $sQueriesDllType = "ptr"
    EndIf

    Local $sIndicesDllType
    If IsDllStruct($indices) Then
        $sIndicesDllType = "struct*"
    Else
        $sIndicesDllType = "ptr"
    EndIf

    Local $sDistsDllType
    If IsDllStruct($dists) Then
        $sDistsDllType = "struct*"
    Else
        $sDistsDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveFlannIndexRadiusSearch", $sIndexDllType, $index, $sQueriesDllType, $queries, $sIndicesDllType, $indices, $sDistsDllType, $dists, "double", $radius, "int", $maxResults, "int", $checks, "float", $eps, "boolean", $sorted), "cveFlannIndexRadiusSearch", @error)
EndFunc   ;==>_cveFlannIndexRadiusSearch

Func _cveFlannIndexRadiusSearchTyped($index, $typeOfQueries, $queries, $typeOfIndices, $indices, $typeOfDists, $dists, $radius, $maxResults, $checks, $eps, $sorted)

    Local $iArrQueries, $vectorQueries, $iArrQueriesSize
    Local $bQueriesIsArray = IsArray($queries)
    Local $bQueriesCreate = IsDllStruct($queries) And $typeOfQueries == "Scalar"

    If $typeOfQueries == Default Then
        $iArrQueries = $queries
    ElseIf $bQueriesIsArray Then
        $vectorQueries = Call("_VectorOf" & $typeOfQueries & "Create")

        $iArrQueriesSize = UBound($queries)
        For $i = 0 To $iArrQueriesSize - 1
            Call("_VectorOf" & $typeOfQueries & "Push", $vectorQueries, $queries[$i])
        Next

        $iArrQueries = Call("_cveInputArrayFromVectorOf" & $typeOfQueries, $vectorQueries)
    Else
        If $bQueriesCreate Then
            $queries = Call("_cve" & $typeOfQueries & "Create", $queries)
        EndIf
        $iArrQueries = Call("_cveInputArrayFrom" & $typeOfQueries, $queries)
    EndIf

    Local $oArrIndices, $vectorIndices, $iArrIndicesSize
    Local $bIndicesIsArray = IsArray($indices)
    Local $bIndicesCreate = IsDllStruct($indices) And $typeOfIndices == "Scalar"

    If $typeOfIndices == Default Then
        $oArrIndices = $indices
    ElseIf $bIndicesIsArray Then
        $vectorIndices = Call("_VectorOf" & $typeOfIndices & "Create")

        $iArrIndicesSize = UBound($indices)
        For $i = 0 To $iArrIndicesSize - 1
            Call("_VectorOf" & $typeOfIndices & "Push", $vectorIndices, $indices[$i])
        Next

        $oArrIndices = Call("_cveOutputArrayFromVectorOf" & $typeOfIndices, $vectorIndices)
    Else
        If $bIndicesCreate Then
            $indices = Call("_cve" & $typeOfIndices & "Create", $indices)
        EndIf
        $oArrIndices = Call("_cveOutputArrayFrom" & $typeOfIndices, $indices)
    EndIf

    Local $oArrDists, $vectorDists, $iArrDistsSize
    Local $bDistsIsArray = IsArray($dists)
    Local $bDistsCreate = IsDllStruct($dists) And $typeOfDists == "Scalar"

    If $typeOfDists == Default Then
        $oArrDists = $dists
    ElseIf $bDistsIsArray Then
        $vectorDists = Call("_VectorOf" & $typeOfDists & "Create")

        $iArrDistsSize = UBound($dists)
        For $i = 0 To $iArrDistsSize - 1
            Call("_VectorOf" & $typeOfDists & "Push", $vectorDists, $dists[$i])
        Next

        $oArrDists = Call("_cveOutputArrayFromVectorOf" & $typeOfDists, $vectorDists)
    Else
        If $bDistsCreate Then
            $dists = Call("_cve" & $typeOfDists & "Create", $dists)
        EndIf
        $oArrDists = Call("_cveOutputArrayFrom" & $typeOfDists, $dists)
    EndIf

    Local $retval = _cveFlannIndexRadiusSearch($index, $iArrQueries, $oArrIndices, $oArrDists, $radius, $maxResults, $checks, $eps, $sorted)

    If $bDistsIsArray Then
        Call("_VectorOf" & $typeOfDists & "Release", $vectorDists)
    EndIf

    If $typeOfDists <> Default Then
        _cveOutputArrayRelease($oArrDists)
        If $bDistsCreate Then
            Call("_cve" & $typeOfDists & "Release", $dists)
        EndIf
    EndIf

    If $bIndicesIsArray Then
        Call("_VectorOf" & $typeOfIndices & "Release", $vectorIndices)
    EndIf

    If $typeOfIndices <> Default Then
        _cveOutputArrayRelease($oArrIndices)
        If $bIndicesCreate Then
            Call("_cve" & $typeOfIndices & "Release", $indices)
        EndIf
    EndIf

    If $bQueriesIsArray Then
        Call("_VectorOf" & $typeOfQueries & "Release", $vectorQueries)
    EndIf

    If $typeOfQueries <> Default Then
        _cveInputArrayRelease($iArrQueries)
        If $bQueriesCreate Then
            Call("_cve" & $typeOfQueries & "Release", $queries)
        EndIf
    EndIf

    Return $retval
EndFunc   ;==>_cveFlannIndexRadiusSearchTyped

Func _cveFlannIndexRadiusSearchMat($index, $queries, $indices, $dists, $radius, $maxResults, $checks, $eps, $sorted)
    ; cveFlannIndexRadiusSearch using cv::Mat instead of _*Array
    Local $retval = _cveFlannIndexRadiusSearchTyped($index, "Mat", $queries, "Mat", $indices, "Mat", $dists, $radius, $maxResults, $checks, $eps, $sorted)

    Return $retval
EndFunc   ;==>_cveFlannIndexRadiusSearchMat

Func _cveFlannIndexRelease($index)
    ; CVAPI(void) cveFlannIndexRelease(cv::flann::Index** index);

    Local $sIndexDllType
    If IsDllStruct($index) Then
        $sIndexDllType = "struct*"
    ElseIf $index == Null Then
        $sIndexDllType = "ptr"
    Else
        $sIndexDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveFlannIndexRelease", $sIndexDllType, $index), "cveFlannIndexRelease", @error)
EndFunc   ;==>_cveFlannIndexRelease