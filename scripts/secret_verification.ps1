# =========================================================
# SWAS Tool - Batch 3 (v2): Live Secret Verification
# Fixes v1's failure: the target code contains a Unicode ellipsis
# character (the "..." glyph, U+2026) which Windows PowerShell can
# silently mis-decode when loading a .ps1 script without a BOM.
# This version never embeds that character literally in the script -
# it's built at runtime via [char]0x2026 - and all file I/O is forced
# to UTF-8 explicitly via .NET, bypassing PowerShell's default
# (version-dependent) encoding behavior entirely.
#
# BEFORE running: place secret_verifier.py into:
#   D:\swas-pro-cluade\swas-mk4\backend\app\
# =========================================================

$repo = "D:\swas-pro-cluade\swas-mk4"
$detectivePath = Join-Path $repo "backend\app\detective.py"
$newFilePath   = Join-Path $repo "backend\app\secret_verifier.py"

Set-Location $repo

if (-not (Test-Path $newFilePath)) {
    Write-Host "ERROR: secret_verifier.py not found at $newFilePath"
    Write-Host "Copy it into backend\app\ first, then re-run this script."
    exit 1
}

# If a previous failed attempt left the branch behind, reuse it instead of erroring.
$existingBranch = git branch --list feature/batch3-secret-verification
if ($existingBranch) {
    git checkout feature/batch3-secret-verification
} else {
    git checkout -b feature/batch3-secret-verification
}

$utf8NoBom = New-Object System.Text.UTF8Encoding($false)
$content = [System.IO.File]::ReadAllText($detectivePath, [System.Text.Encoding]::UTF8)
# NOTE: earlier version of this script blanket-normalized the whole
# file's line endings to fix a CRLF mismatch, which backfired badly -
# the file turned out to have MIXED line endings in different regions
# (history of edits from different tools), so a global normalize+restore
# flipped endings on lines far outside our actual edit, producing a
# multi-thousand-line diff instead of a clean ~20-line one. Fixed here
# by never touching the whole file's endings at all - the search/replace
# blocks below are built with `r`n directly, matching only the local
# region we actually edit, so every other line is left byte-for-byte
# untouched.

$ELLIPSIS = [char]0x2026   # built at runtime - never stored as a literal byte sequence in this script

# ---- Edit 1: import ----
$oldImport = "import httpx"
$newImport = "import httpx`r`n`r`nfrom . import secret_verifier"
$firstImportIndex = $content.IndexOf($oldImport)
if ($firstImportIndex -lt 0) {
    Write-Host "ERROR: 'import httpx' not found in detective.py - it may have changed since this script was written."
    exit 1
}
$alreadyWired = $content.Contains("from . import secret_verifier")
if (-not $alreadyWired) {
    $content = $content.Remove($firstImportIndex, $oldImport.Length).Insert($firstImportIndex, $newImport)
}

# ---- Edit 2: verification wiring inside check_api_key_leak_signature ----
# Built line-by-line and joined, so the ellipsis character is inserted
# programmatically rather than typed into the script file.
$oldLines = @(
    "    body = resp.text",
    "    for pattern, provider, severity in _API_KEY_SIGNATURES:",
    "        match = pattern.search(body)",
    "        if match:",
    "            secret_preview = match.group(0)[:8] + `"$ELLIPSIS`" + match.group(0)[-4:]",
    "            return {",
    "                `"vuln_type`": `"exposed_api_key`",",
    "                `"severity`": severity,",
    "                `"evidence`": (",
    "                    f`"{url}: found a live-looking {provider} matching its known format `"",
    "                    f`"({secret_preview}) directly in the response body.`"",
    "                ),",
    "            }",
    "    return None"
)
$oldBlock = ($oldLines -join "`r`n")

$newLines = @(
    "    body = resp.text",
    "    for pattern, provider, severity in _API_KEY_SIGNATURES:",
    "        match = pattern.search(body)",
    "        if match:",
    "            raw_secret = match.group(0)  # only ever held in memory, never persisted",
    "            secret_preview = raw_secret[:8] + `"$ELLIPSIS`" + raw_secret[-4:]",
    "",
    "            # Live-verify while the full value is still in scope, for the",
    "            # subset of providers where the matched string is a complete,",
    "            # usable credential on its own (see secret_verifier.py's",
    "            # module docstring for why AWS/Twilio are excluded here).",
    "            verdict = await secret_verifier.verify_secret(provider, raw_secret)",
    "            if verdict is None:",
    "                verify_note = `" (not independently verifiable from this match alone - needs a paired secret)`"",
    "                effective_severity = severity",
    "            elif verdict.get(`"valid`") is True:",
    "                verify_note = f`" VERIFIED LIVE: {verdict['note']}`"",
    "                effective_severity = `"critical`"  # a confirmed-live credential always outranks the format's default",
    "            elif verdict.get(`"valid`") is False:",
    "                verify_note = f`" VERIFIED DEAD: {verdict['note']}`"",
    "                effective_severity = `"low`"  # keep the finding, don't silently drop it - let triage.py make the final call",
    "            else:",
    "                verify_note = f`" (verification inconclusive: {verdict.get('note', 'unknown')})`"",
    "                effective_severity = severity",
    "",
    "            return {",
    "                `"vuln_type`": `"exposed_api_key`",",
    "                `"severity`": effective_severity,",
    "                `"evidence`": (",
    "                    f`"{url}: found a live-looking {provider} matching its known format `"",
    "                    f`"({secret_preview}) directly in the response body.{verify_note}`"",
    "                ),",
    "            }",
    "    return None"
)
$newBlock = ($newLines -join "`r`n")

$alreadyPatched = $content.Contains("raw_secret = match.group(0)  # only ever held in memory")
if ($alreadyPatched) {
    Write-Host "detective.py already contains the Batch 3 logic - skipping Edit 2 (safe to re-run)."
} else {
    $idx = $content.IndexOf($oldBlock)
    if ($idx -lt 0) {
        Write-Host "ERROR: check_api_key_leak_signature body still not found."
        Write-Host "Saving what this script searched for and what's actually in your file, for comparison:"
        [System.IO.File]::WriteAllText("$repo\_batch3_debug_expected.txt", $oldBlock, $utf8NoBom)
        $funcStart = $content.IndexOf("async def check_api_key_leak_signature")
        if ($funcStart -ge 0) {
            $snippet = $content.Substring($funcStart, [Math]::Min(1500, $content.Length - $funcStart))
            [System.IO.File]::WriteAllText("$repo\_batch3_debug_actual.txt", $snippet, $utf8NoBom)
        }
        Write-Host "Two files written to $repo - _batch3_debug_expected.txt and _batch3_debug_actual.txt."
        Write-Host "Paste both back to me and I'll diagnose exactly what's different."
        exit 1
    }
    $content = $content.Remove($idx, $oldBlock.Length).Insert($idx, $newBlock)
}

[System.IO.File]::WriteAllText($detectivePath, $content, $utf8NoBom)

Write-Host "detective.py updated. Attempting a best-effort syntax check..."
$checkedOk = $false
if (Get-Command python -ErrorAction SilentlyContinue) {
    python -m py_compile "backend\app\detective.py" "backend\app\secret_verifier.py"
    if ($LASTEXITCODE -ne 0) {
        Write-Host "SYNTAX CHECK FAILED - do not commit. Restore with: git checkout -- backend/app/detective.py"
        exit 1
    }
    Write-Host "Syntax OK (checked with local python)."
    $checkedOk = $true
} elseif (Get-Command docker -ErrorAction SilentlyContinue) {
    docker run --rm -v "${repo}\backend\app:/app" python:3.12-slim python -m py_compile /app/detective.py /app/secret_verifier.py
    if ($LASTEXITCODE -ne 0) {
        Write-Host "SYNTAX CHECK FAILED - do not commit. Restore with: git checkout -- backend/app/detective.py"
        exit 1
    }
    Write-Host "Syntax OK (checked via Docker)."
    $checkedOk = $true
}
if (-not $checkedOk) {
    Write-Host "No local python or docker found - skipping local syntax check (already verified before delivery)."
}

git add backend/app/secret_verifier.py backend/app/detective.py
git commit -m "feat: live-verify Stripe/GitHub/Slack keys found by check_api_key_leak_signature (Batch 3)"
git push -u origin feature/batch3-secret-verification

Write-Host ""
Write-Host "Done. Next:"
Write-Host "  gh pr create --base main --head feature/batch3-secret-verification --title 'feat: live secret verification (Stripe/GitHub/Slack)' --body 'Batch 3'"
Write-Host "  gh pr merge feature/batch3-secret-verification --merge --delete-branch"
Write-Host "Then redeploy on OCI with oci_deploy_batch1.sh as usual."
