# =========================================================
# SWAS Tool - Batch 4a: Per-Host Rescan + last_scanned_at
#
# BEFORE running: place add_last_scanned_at.sql into:
#   D:\swas-pro-cluade\swas-mk4\backend\db\
# =========================================================

$repo = "D:\swas-pro-cluade\swas-mk4"
$mainPath   = Join-Path $repo "backend\app\main.py"
$modelsPath = Join-Path $repo "backend\app\models.py"
$pipelinePath = Join-Path $repo "backend\app\pipeline.py"
$initSqlPath  = Join-Path $repo "backend\db\init.sql"
$migrationSrc = Join-Path $repo "backend\db\add_last_scanned_at.sql"

Set-Location $repo

if (-not (Test-Path $migrationSrc)) {
    Write-Host "ERROR: add_last_scanned_at.sql not found at $migrationSrc"
    Write-Host "Copy it into backend\db\ first, then re-run this script."
    exit 1
}

$existingBranch = git branch --list feature/batch4a-rescan
if ($existingBranch) { git checkout feature/batch4a-rescan } else { git checkout -b feature/batch4a-rescan }

function Apply-Edit {
    param($Path, $Old, $New, $Label)
    $c = [System.IO.File]::ReadAllText($Path, [System.Text.Encoding]::UTF8)
    $newLf = $New.Replace("`r`n", "`n")
    if ($c.Contains($New) -or $c.Contains($newLf)) {
        Write-Host "  [skip] $Label - already applied"
        return $c
    }
    # Try the anchor as authored (CRLF), then an LF-only variant - whichever
    # actually matches this specific file's line endings wins. This removes
    # the need to know/guess each file's line-ending style in advance.
    $oldLf = $Old.Replace("`r`n", "`n")
    $newLf = $New.Replace("`r`n", "`n")

    $idx = $c.IndexOf($Old)
    if ($idx -ge 0) {
        return $c.Remove($idx, $Old.Length).Insert($idx, $New)
    }
    $idx = $c.IndexOf($oldLf)
    if ($idx -ge 0) {
        Write-Host "  (note: $Label matched via LF variant, not CRLF)"
        return $c.Remove($idx, $oldLf.Length).Insert($idx, $newLf)
    }
    Write-Host "  [FAIL] $Label - anchor not found in either CRLF or LF form"
    [System.IO.File]::WriteAllText("$repo\_batch4a_fail_$Label.txt", $Old, (New-Object System.Text.UTF8Encoding($false)))
    return $null
}

# ---- models.py ----
$oldM = "    notes: Optional[str]`r`n    created_at: datetime"
$newM = "    notes: Optional[str]`r`n    last_scanned_at: Optional[datetime] = None`r`n    created_at: datetime"
$c = Apply-Edit -Path $modelsPath -Old $oldM -New $newM -Label "models_ScopeTarget"
if ($null -eq $c) { Write-Host "Stopping - fix models.py anchor mismatch first."; exit 1 }
[System.IO.File]::WriteAllText($modelsPath, $c, (New-Object System.Text.UTF8Encoding($false)))

# ---- init.sql (fresh-install schema, cosmetic but keep in sync) ----
$oldI = "    reward_range    TEXT,`r`n    notes           TEXT,`r`n    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()`r`n);"
$newI = "    reward_range    TEXT,`r`n    notes           TEXT,`r`n    last_scanned_at TIMESTAMPTZ,`r`n    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()`r`n);"
$c = Apply-Edit -Path $initSqlPath -Old $oldI -New $newI -Label "init_sql_scope_targets"
if ($c) { [System.IO.File]::WriteAllText($initSqlPath, $c, (New-Object System.Text.UTF8Encoding($false))) }
else { Write-Host "  (non-fatal - init.sql only affects brand-new installs, continuing)" }

# ---- pipeline.py ----
$oldP = 'logger.info("Finished pipeline for target_id=%s", target_id)'
$newPLines = @(
    '# Stamped unconditionally here (not per-phase) - this marks "a scan',
    '# attempt happened and finished" for the host, regardless of whether',
    '# every phase succeeded, some were skipped as a dead target, or scope',
    '# drifted mid-run. That is what "last scanned" should mean to an',
    '# operator glancing at the host list - not "last fully clean run".',
    'async with pool.acquire() as conn:',
    '    await conn.execute(',
    '        "UPDATE scope_targets SET last_scanned_at = now() WHERE id = $1", target_id',
    '    )',
    '',
    'logger.info("Finished pipeline for target_id=%s", target_id)'
)
$newP = ($newPLines -join "`r`n    ")  # 4-space indent matches the function body level
$newP = "    " + $newP  # first line needs the same indent too
$c = Apply-Edit -Path $pipelinePath -Old $oldP -New $newP -Label "pipeline_timestamp"
if ($null -eq $c) { Write-Host "Stopping - fix pipeline.py anchor mismatch first."; exit 1 }
[System.IO.File]::WriteAllText($pipelinePath, $c, (New-Object System.Text.UTF8Encoding($false)))

Write-Host ""
Write-Host "models.py, init.sql, pipeline.py done. Now applying main.py (5 small edits)..."

$c = [System.IO.File]::ReadAllText($mainPath, [System.Text.Encoding]::UTF8)
$mainEdits = @(
    @{ Label="insert_returning";  Old="RETURNING id, project_id, target, target_type, in_scope,`n                      reward_range, notes, created_at"; New="RETURNING id, project_id, target, target_type, in_scope,`n                      reward_range, notes, last_scanned_at, created_at" },
    @{ Label="list_select";       Old="SELECT id, project_id, target, target_type, in_scope,`n                   reward_range, notes, created_at"; New="SELECT id, project_id, target, target_type, in_scope,`n                   reward_range, notes, last_scanned_at, created_at" },
    @{ Label="patch_noop_select"; Old="SELECT id, project_id, target, target_type, in_scope, reward_range, notes, created_at`n                FROM scope_targets WHERE id = `$1"; New="SELECT id, project_id, target, target_type, in_scope, reward_range, notes, last_scanned_at, created_at`n                FROM scope_targets WHERE id = `$1" },
    @{ Label="patch_returning";   Old="RETURNING id, project_id, target, target_type, in_scope, reward_range, notes, created_at`n            `"`"`",`n            *params,"; New="RETURNING id, project_id, target, target_type, in_scope, reward_range, notes, last_scanned_at, created_at`n            `"`"`",`n            *params," },
    @{ Label="bulk_returning";    Old="RETURNING id, project_id, target, target_type, in_scope, reward_range, notes, created_at`n                `"`"`",`n                project_id, t,"; New="RETURNING id, project_id, target, target_type, in_scope, reward_range, notes, last_scanned_at, created_at`n                `"`"`",`n                project_id, t," }
)
foreach ($edit in $mainEdits) {
    $newLfCheck = $edit.New.Replace("`r`n", "`n")
    if ($c.Contains($edit.New) -or $c.Contains($newLfCheck)) { Write-Host "  [skip] $($edit.Label) - already applied"; continue }
    $oldLf = $edit.Old.Replace("`r`n", "`n")
    $newLf = $edit.New.Replace("`r`n", "`n")
    $idx = $c.IndexOf($edit.Old)
    if ($idx -ge 0) {
        $c = $c.Remove($idx, $edit.Old.Length).Insert($idx, $edit.New)
        Write-Host "  [ok] $($edit.Label)"
        continue
    }
    $idx = $c.IndexOf($oldLf)
    if ($idx -ge 0) {
        $c = $c.Remove($idx, $oldLf.Length).Insert($idx, $newLf)
        Write-Host "  [ok] $($edit.Label) (matched via LF variant)"
        continue
    }
    Write-Host "  [FAIL] $($edit.Label) - anchor not found in either CRLF or LF form. Saving expected text for comparison."
    [System.IO.File]::WriteAllText("$repo\_batch4a_fail_$($edit.Label).txt", $edit.Old, (New-Object System.Text.UTF8Encoding($false)))
}

# ---- new rescan endpoint ----
$endpointAnchorOld = @'
        row = await conn.fetchrow(
            f"""
            UPDATE scope_targets
            SET {", ".join(set_clauses)}
            WHERE id = ${len(params)}
            RETURNING id, project_id, target, target_type, in_scope, reward_range, notes, last_scanned_at, created_at
            """,
            *params,
        )
    return dict(row)
'@
if ($c.Contains("async def rescan_target")) {
    Write-Host "  [skip] rescan_endpoint - already applied"
} else {
    $endpointAnchorOldLf = $endpointAnchorOld.Replace("`r`n", "`n")
    $idx = $c.IndexOf($endpointAnchorOld)
    $matchedOld = $endpointAnchorOld
    if ($idx -lt 0) {
        $idx = $c.IndexOf($endpointAnchorOldLf)
        $matchedOld = $endpointAnchorOldLf
    }
    if ($idx -lt 0) {
        Write-Host "  [FAIL] rescan_endpoint anchor not found in either CRLF or LF form (this depends on the 4 main.py edits above succeeding first)."
        [System.IO.File]::WriteAllText("$repo\_batch4a_fail_rescan_endpoint.txt", $endpointAnchorOld, (New-Object System.Text.UTF8Encoding($false)))
    } else {
        $endpointNew = $matchedOld + @'


@app.post("/api/projects/{project_id}/scope/{target_id}/rescan")
async def rescan_target(project_id: int, target_id: int):
    """
    Reruns the pipeline for exactly one host, without touching recon or
    any other host in the project - for when a fix just went out and
    you want to confirm it, or a host errored/timed out and you want to
    retry just that one instead of rerunning the whole project.

    Deliberately does NOT flip projects.status to 'scanning' the way a
    full project scan does - that status/the scheduler loop are about
    whole-project runs, and a single-host rescan is a lighter-weight,
    independent action that shouldn't block or interact with either.
    """
    pool = database.get_pool()
    async with pool.acquire() as conn:
        target_row = await conn.fetchrow(
            "SELECT id, target, in_scope FROM scope_targets WHERE id = $1 AND project_id = $2",
            target_id, project_id,
        )
        if target_row is None:
            raise HTTPException(status_code=404, detail="Scope target not found")
        if not target_row["in_scope"]:
            raise HTTPException(
                status_code=400,
                detail="This target is marked out-of-scope - flip it back in-scope before rescanning",
            )

        denylist_raw = os.environ.get("DENYLIST_DOMAINS", "")
        denylist = [d.strip().lower() for d in denylist_raw.split(",") if d.strip()]
        if denylist and any(d in target_row["target"].lower() for d in denylist):
            raise HTTPException(
                status_code=400,
                detail=(
                    f"Refusing to scan: {target_row['target']} matches DENYLIST_DOMAINS. "
                    f"This is explicitly excluded even if marked in-scope."
                ),
            )

        in_progress = await conn.fetchval(
            "SELECT 1 FROM phase_runs WHERE target_id = $1 AND status = 'in_progress' LIMIT 1",
            target_id,
        )
        if in_progress:
            raise HTTPException(
                status_code=409,
                detail="This host already has a scan in progress - wait for it to finish before rescanning",
            )

    asyncio.create_task(
        pipeline.run_target_pipeline(pool, project_id, target_id, target_row["target"])
    )

    return {
        "message": f"Rescan started for {target_row['target']}",
        "target_id": target_id,
    }
'@
        $c = $c.Remove($idx, $matchedOld.Length).Insert($idx, $endpointNew)
        Write-Host "  [ok] rescan_endpoint"
    }
}

[System.IO.File]::WriteAllText($mainPath, $c, (New-Object System.Text.UTF8Encoding($false)))

$failFiles = Get-ChildItem "$repo\_batch4a_fail_*.txt" -ErrorAction SilentlyContinue
if ($failFiles) {
    Write-Host ""
    Write-Host "One or more anchors failed to match - see _batch4a_fail_*.txt files in $repo."
    Write-Host "Do NOT commit yet. Send me those files."
    exit 1
}

Write-Host ""
Write-Host "All edits applied. Running syntax check..."
python -m py_compile "backend\app\main.py" "backend\app\models.py" "backend\app\pipeline.py"
if ($LASTEXITCODE -ne 0) {
    Write-Host "SYNTAX CHECK FAILED - do not commit. Restore with: git checkout -- backend/app/main.py backend/app/models.py backend/app/pipeline.py"
    exit 1
}
Write-Host "Syntax OK."

git add backend/app/main.py backend/app/models.py backend/app/pipeline.py backend/db/init.sql backend/db/add_last_scanned_at.sql
git status
Write-Host ""
Write-Host "Review 'git status' above, then check the diff size BEFORE committing:"
Write-Host "  git diff --cached --stat"
Write-Host "Expect roughly +80/-5 lines total across 5 files - NOT thousands."
Write-Host "If that looks right, commit and push yourself:"
Write-Host '  git commit -m "feat: per-host rescan endpoint + last_scanned_at tracking (Batch 4a)"'
Write-Host "  git push -u origin feature/batch4a-rescan"
Write-Host ""
Write-Host "This script does NOT auto-push, on purpose - you check the diff size first this time."
