$path = "backend\app\main.py"
$raw = Get-Content -Raw $path
$content = $raw -replace "`r`n", "`n"

$old = @'
    results = await asyncio.gather(*tasks, return_exceptions=True)
    failures = [r for r in results if isinstance(r, Exception)]
    if failures:
        logger.warning(
            "scan for project %s: %d of %d target(s) raised an error - "
            "project status still resolves to 'completed' (no 'error' "
            "value exists in projects.status); check phase_runs for detail",
            project_id, len(failures), len(results),
        )
'@

$new = @'
    results = await asyncio.gather(*tasks, return_exceptions=True)
    failures = [r for r in results if isinstance(r, Exception)]
    if failures:
        for i, exc in enumerate(failures):
            logger.error(
                "scan failure detail (%d/%d) for project %s: %r",
                i + 1, len(failures), project_id, exc,
                exc_info=exc,
            )
        logger.warning(
            "scan for project %s: %d of %d target(s) raised an error - "
            "project status still resolves to 'completed' (no 'error' "
            "value exists in projects.status); check phase_runs for detail",
            project_id, len(failures), len(results),
        )
'@

if ($content.Contains($old)) {
    $content = $content.Replace($old, $new)
    Write-Host "Patch applied: exception detail logging added."
} else {
    Write-Host "WARNING: old text not found - skipped."
}

[System.IO.File]::WriteAllText((Resolve-Path $path), $content)
Write-Host "Done. Review with: git diff backend\app\main.py"
