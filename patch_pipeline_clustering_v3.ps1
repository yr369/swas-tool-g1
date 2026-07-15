$path = "backend\app\pipeline.py"
$raw = Get-Content -Raw $path

# Normalize CRLF -> LF for reliable matching (file will be saved as LF;
# git/Python both handle LF fine, this just avoids CRLF vs LF mismatches
# breaking the exact-string matches below)
$content = $raw -replace "`r`n", "`n"

# --- Patch 1: nuclei inline insert ---
$old1 = @'
        await conn.execute(
            """
            INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
            VALUES ($1, $2, 'nuclei', $3, $4, $5)
            """,
            project_id, target_id, vuln_type, severity, line[:1000],
        )
        saved_count += 1
'@

$new1 = @'
        finding_id = await conn.fetchval(
            """
            INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
            VALUES ($1, $2, 'nuclei', $3, $4, $5)
            RETURNING id
            """,
            project_id, target_id, vuln_type, severity, line[:1000],
        )
        await _upsert_finding_cluster(conn, target_id, finding_id, 'nuclei')
        saved_count += 1
'@

if ($content.Contains($old1)) {
    $content = $content.Replace($old1, $new1)
    Write-Host "Patch 1 (nuclei insert) applied."
} else {
    Write-Host "WARNING: Patch 1 old text not found - skipped."
}

# --- Patch 2: _save_finding ---
$old2 = @'
    await conn.execute(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, $3, $4, 'unknown', $5)
        """,
        project_id,
        target_id,
        tool_name,
        tool_name,  # Phase 1: vuln_type defaults to the tool name until triage exists
        cleaned_output[:5000],  # cap stored evidence length
    )
'@

$new2 = @'
    finding_id = await conn.fetchval(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, $3, $4, 'unknown', $5)
        RETURNING id
        """,
        project_id,
        target_id,
        tool_name,
        tool_name,  # Phase 1: vuln_type defaults to the tool name until triage exists
        cleaned_output[:5000],  # cap stored evidence length
    )
    await _upsert_finding_cluster(conn, target_id, finding_id, tool_name)
'@

if ($content.Contains($old2)) {
    $content = $content.Replace($old2, $new2)
    Write-Host "Patch 2 (_save_finding) applied."
} else {
    Write-Host "WARNING: Patch 2 old text not found - skipped."
}

# --- Patch 3: _save_detective_finding ---
$old3 = @'
    self_declared_prefix = f"[self-declared-severity: {result['severity']}]\n"
    await conn.execute(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, 'detective', $3, 'unknown', $4)
        """,
        project_id,
        target_id,
        result["vuln_type"],
        (self_declared_prefix + result["evidence"])[:5000],
    )
'@

$new3 = @'
    self_declared_prefix = f"[self-declared-severity: {result['severity']}]\n"
    finding_id = await conn.fetchval(
        """
        INSERT INTO findings (project_id, target_id, tool_name, vuln_type, severity, evidence)
        VALUES ($1, $2, 'detective', $3, 'unknown', $4)
        RETURNING id
        """,
        project_id,
        target_id,
        result["vuln_type"],
        (self_declared_prefix + result["evidence"])[:5000],
    )
    await _upsert_finding_cluster(conn, target_id, finding_id, 'detective')
'@

if ($content.Contains($old3)) {
    $content = $content.Replace($old3, $new3)
    Write-Host "Patch 3 (_save_detective_finding) applied."
} else {
    Write-Host "WARNING: Patch 3 old text not found - skipped."
}

# Helper function - check if already present (it was added by v2 run)
if ($content.Contains("async def _upsert_finding_cluster")) {
    Write-Host "Helper already present - skipped adding again."
} else {
    $anchor = 'async def _save_finding('
    $helper = @'
async def _upsert_finding_cluster(
    conn: asyncpg.Connection, target_id: int, finding_id: int, source: str
) -> None:
    """
    Links a newly-saved finding into its target's cluster row, creating
    the cluster row on first insert for that target. This is what
    populates finding_clusters / finding_cluster_members so the
    correlation layer (high_potential_clusters view) actually has data
    instead of sitting empty.
    """
    cluster_id = await conn.fetchval(
        """
        INSERT INTO finding_clusters (target_id)
        VALUES ($1)
        ON CONFLICT (target_id) DO UPDATE SET updated_at = now()
        RETURNING id
        """,
        target_id,
    )
    await conn.execute(
        """
        INSERT INTO finding_cluster_members (cluster_id, finding_id, source)
        VALUES ($1, $2, $3)
        ON CONFLICT (cluster_id, finding_id) DO NOTHING
        """,
        cluster_id, finding_id, source,
    )


async def _save_finding(
'@
    if ($content.Contains($anchor)) {
        $content = $content.Replace($anchor, $helper)
        Write-Host "Helper function _upsert_finding_cluster added."
    } else {
        Write-Host "WARNING: anchor for helper insertion not found - helper NOT added."
    }
}

[System.IO.File]::WriteAllText((Resolve-Path $path), $content)
Write-Host "Done. Review with: git diff backend\app\pipeline.py"
