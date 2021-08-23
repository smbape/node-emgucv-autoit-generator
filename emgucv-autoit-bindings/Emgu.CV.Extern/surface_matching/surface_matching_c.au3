#include-once
#include "..\..\CVEUtils.au3"

Func _cveICPCreate($iterations, $tolerence, $rejectionScale, $numLevels, $sampleType, $numMaxCorr)
    ; CVAPI(cv::ppf_match_3d::ICP*) cveICPCreate(int iterations, float tolerence, float rejectionScale, int numLevels, int sampleType, int numMaxCorr);
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "ptr:cdecl", "cveICPCreate", "int", $iterations, "float", $tolerence, "float", $rejectionScale, "int", $numLevels, "int", $sampleType, "int", $numMaxCorr), "cveICPCreate", @error)
EndFunc   ;==>_cveICPCreate

Func _cveICPRegisterModelToScene($icp, $srcPC, $dstPC, $residual, $pose)
    ; CVAPI(int) cveICPRegisterModelToScene(cv::ppf_match_3d::ICP* icp, cv::Mat* srcPC, cv::Mat* dstPC, double* residual, cv::Mat* pose);

    Local $sIcpDllType
    If IsDllStruct($icp) Then
        $sIcpDllType = "struct*"
    Else
        $sIcpDllType = "ptr"
    EndIf

    Local $sSrcPCDllType
    If IsDllStruct($srcPC) Then
        $sSrcPCDllType = "struct*"
    Else
        $sSrcPCDllType = "ptr"
    EndIf

    Local $sDstPCDllType
    If IsDllStruct($dstPC) Then
        $sDstPCDllType = "struct*"
    Else
        $sDstPCDllType = "ptr"
    EndIf

    Local $sResidualDllType
    If IsDllStruct($residual) Then
        $sResidualDllType = "struct*"
    Else
        $sResidualDllType = "double*"
    EndIf

    Local $sPoseDllType
    If IsDllStruct($pose) Then
        $sPoseDllType = "struct*"
    Else
        $sPoseDllType = "ptr"
    EndIf
    Return CVEDllCallResult(DllCall($_h_cvextern_dll, "int:cdecl", "cveICPRegisterModelToScene", $sIcpDllType, $icp, $sSrcPCDllType, $srcPC, $sDstPCDllType, $dstPC, $sResidualDllType, $residual, $sPoseDllType, $pose), "cveICPRegisterModelToScene", @error)
EndFunc   ;==>_cveICPRegisterModelToScene

Func _cveICPRelease($icp)
    ; CVAPI(void) cveICPRelease(cv::ppf_match_3d::ICP** icp);

    Local $sIcpDllType
    If IsDllStruct($icp) Then
        $sIcpDllType = "struct*"
    ElseIf $icp == Null Then
        $sIcpDllType = "ptr"
    Else
        $sIcpDllType = "ptr*"
    EndIf

    CVEDllCallResult(DllCall($_h_cvextern_dll, "none:cdecl", "cveICPRelease", $sIcpDllType, $icp), "cveICPRelease", @error)
EndFunc   ;==>_cveICPRelease