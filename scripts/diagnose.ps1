# =========================================================
# Batch 4a diagnostic - dumps the actual text around each of
# the 5 target anchors in main.py, plus whether each region
# uses CRLF or LF, so we stop guessing and just look.
# =========================================================

$repo = "D:\swas-pro-cluade\swas-mk4"
$mainPath = Join-Path $repo "backend\app\main.py"
$content = [System.IO.File]::ReadAllText($mainPath, [System.Text.Encoding]::UTF8)

function Dump-Region {
    param($FuncMarker, $Label)
    $idx = $content.IndexOf($FuncMarker)
    if ($idx -lt 0) {
        Write-Host "=== $Label === COULD NOT FIND MARKER '$FuncMarker' AT ALL"
        return
    }
    $region = $content.Substring($idx, [Math]::Min(1400, $content.Length - $idx))
    $hasCrlf = $region.Contains("`r`n")
    Write-Host "=== $Label === (uses CRLF: $hasCrlf)"
    Write-Host $region
    Write-Host "--- END $Label ---"
    Write-Host ""
}

Dump-Region -FuncMarker "async def add_scope_target" -Label "insert_returning (add_scope_target)"
Dump-Region -FuncMarker "async def list_scope_targets" -Label "list_select (list_scope_targets)"
Dump-Region -FuncMarker "async def update_scope_target" -Label "patch_noop_select + patch_returning (update_scope_target)"
Dump-Region -FuncMarker "@app.post(`"/api/projects/{project_id}/scope/bulk`")" -Label "bulk_returning (bulk endpoint)"

Write-Host "Send me everything above."
