<#
.SYNOPSIS
    Registers Entra ID (Azure AD) app registrations for the Log Analytics SIEM-lite platform.

.DESCRIPTION
    Creates up to TWO app registrations:
      1. Backend (Confidential Client) — used for Graph API / O365 Management API log collection.
      2. Frontend SPA (Public Client)  — optional; used for interactive Entra ID sign-in.

    Adds all required API permissions and grants admin consent.
    Outputs a ready-to-use .env block with the generated credentials.

    Uses the Microsoft Graph PowerShell SDK (Microsoft.Graph module).

.PARAMETER AppNamePrefix
    Prefix for both app registration display names (default: "log-analytics").

.PARAMETER IncludeSpa
    Also create the frontend SPA registration and configure interactive auth.

.PARAMETER RedirectUri
    SPA redirect URI (default: http://localhost:5173).

.PARAMETER SkipAdminConsent
    Skip the admin consent step (useful if you lack Global Admin / Privileged Role Admin rights).

.EXAMPLE
    # Backend only (client_credentials mode)
    .\Register-EntraApp.ps1

    # Backend + frontend SPA (interactive / both mode)
    .\Register-EntraApp.ps1 -IncludeSpa

    # Custom name, production redirect
    .\Register-EntraApp.ps1 -IncludeSpa -AppNamePrefix "siem-prod" -RedirectUri "https://siem.contoso.com"

.NOTES
    Prerequisites:
      - PowerShell 7+ (pwsh)
      - Microsoft.Graph module:  Install-Module Microsoft.Graph -Scope CurrentUser
      - Sufficient role: Cloud Application Administrator, Application Administrator, or Global Admin
#>

[CmdletBinding()]
param(
    [string]$AppNamePrefix = "log-analytics",
    [switch]$IncludeSpa,
    [string]$RedirectUri = "http://localhost:5173",
    [switch]$SkipAdminConsent
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ──────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────
function Write-Step { param([string]$Msg) Write-Host "`n[*] $Msg" -ForegroundColor Cyan }
function Write-Ok { param([string]$Msg) Write-Host "    $Msg" -ForegroundColor Green }
function Write-Warn { param([string]$Msg) Write-Host "    $Msg" -ForegroundColor Yellow }
function Write-Fail { param([string]$Msg) Write-Host "    $Msg" -ForegroundColor Red }

# ──────────────────────────────────────────────────────────────
# Well-known resource app IDs & permission IDs
# (from Microsoft documentation — these are constant GUIDs)
# ──────────────────────────────────────────────────────────────
# Microsoft Graph
$GraphAppId = "00000003-0000-0000-c000-000000000000"
$AuditLogReadAll = "b0afded3-3588-46d8-8b3d-9842eff778da"   # AuditLog.Read.All
$DirectoryReadAll = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"   # Directory.Read.All
$PolicyReadAll = "246dd0d5-5bd0-4def-940b-0421030a5b68"   # Policy.Read.All
$GroupReadAll = "5b567255-7703-4780-807c-7be8301ae99b"   # Group.Read.All

# Office 365 Management APIs
$O365MgmtAppId = "c5393580-f805-4401-95e8-94b7a6ef2fc2"
$ActivityFeedRead = "594c1fb6-4f81-4571-8f4e-2e975fe587e6"   # ActivityFeed.Read
$ActivityFeedReadDlp = "4807a72c-ad38-4250-94c9-4b5c0d0727c0"   # ActivityFeed.ReadDlp

# Delegated scopes for SPA (openid / profile / User.Read)
$OpenId = "37f7f235-527c-4136-accd-4a02d197296e"
$Profile = "14dad69e-099b-42c9-810b-d002981feec1"
$UserRead = "e1fe6dd8-ba31-4d61-89e7-88639da4683d"

# ──────────────────────────────────────────────────────────────
# 0. Ensure Microsoft.Graph module & sign in
# ──────────────────────────────────────────────────────────────
Write-Step "Checking Microsoft.Graph module..."
if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Applications)) {
    Write-Warn "Microsoft.Graph module not found. Installing (CurrentUser scope)..."
    Install-Module Microsoft.Graph -Scope CurrentUser -Force -AllowClobber
}

# Define the Graph scopes this script needs
$requiredScopes = @(
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "DelegatedPermissionGrant.ReadWrite.All"
)

$tenantID = "c8a8cdf0-9270-446b-9930-3d017bf24220"

Write-Step "Signing in to Microsoft Graph (Connect-MgGraph)..."
Connect-MgGraph -Scopes $requiredScopes -TenantId $tenantID -ErrorAction Stop | Out-Null
$mgContext = Get-MgContext
$tenantId = $mgContext.TenantId
Write-Ok "Signed in as $($mgContext.Account) in tenant $tenantId"

# ══════════════════════════════════════════════════════════════
# 1. BACKEND APP REGISTRATION
# ══════════════════════════════════════════════════════════════
$backendAppName = "$AppNamePrefix-backend"
Write-Step "Creating backend app registration: $backendAppName ..."

# Build required resource access up front
$graphResourceAccess = @(
    @{ Id = $AuditLogReadAll; Type = "Role" },
    @{ Id = $DirectoryReadAll; Type = "Role" },
    @{ Id = $PolicyReadAll; Type = "Role" },
    @{ Id = $GroupReadAll; Type = "Role" }
)
$o365ResourceAccess = @(
    @{ Id = $ActivityFeedRead; Type = "Role" },
    @{ Id = $ActivityFeedReadDlp; Type = "Role" }
)
$requiredResourceAccess = @(
    @{
        ResourceAppId  = $GraphAppId
        ResourceAccess = $graphResourceAccess
    },
    @{
        ResourceAppId  = $O365MgmtAppId
        ResourceAccess = $o365ResourceAccess
    }
)

$backendApp = New-MgApplication `
    -DisplayName $backendAppName `
    -SignInAudience "AzureADMyOrg" `
    -RequiredResourceAccess $requiredResourceAccess
$backendClientId = $backendApp.AppId
$backendObjectId = $backendApp.Id
Write-Ok "App ID (client ID): $backendClientId"
Write-Ok "Microsoft Graph  : AuditLog.Read.All, Directory.Read.All, Policy.Read.All, Group.Read.All"
Write-Ok "O365 Management  : ActivityFeed.Read, ActivityFeed.ReadDlp"

# ── 1a. Client secret ────────────────────────────────────────
Write-Step "Creating client secret (valid 2 years)..."
$secretParams = @{
    PasswordCredential = @{
        DisplayName = "log-analytics-secret"
        EndDateTime = (Get-Date).AddYears(2)
    }
}
$secret = Add-MgApplicationPassword -ApplicationId $backendObjectId @secretParams
$clientSecret = $secret.SecretText
Write-Ok "Secret created (save it now — it won't be shown again)"

# ── 1b. Service principal ────────────────────────────────────
Write-Step "Ensuring service principal exists..."
try {
    $backendSp = New-MgServicePrincipal -AppId $backendClientId
    Write-Ok "Service principal created (object ID: $($backendSp.Id))."
}
catch {
    if ($_.Exception.Message -match "already exists") {
        $backendSp = Get-MgServicePrincipal -Filter "appId eq '$backendClientId'"
        Write-Ok "Service principal already exists (OK)."
    }
    else { throw }
}

# ── 1c. Grant admin consent ──────────────────────────────────
if (-not $SkipAdminConsent) {
    Write-Step "Granting admin consent for backend app..."
    Start-Sleep -Seconds 3  # brief delay for AAD replication

    # Grant app role assignments for each application permission
    # Microsoft Graph service principal
    $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -Top 1
    foreach ($roleId in @($AuditLogReadAll, $DirectoryReadAll, $PolicyReadAll, $GroupReadAll)) {
        try {
            New-MgServicePrincipalAppRoleAssignment `
                -ServicePrincipalId $backendSp.Id `
                -PrincipalId $backendSp.Id `
                -ResourceId $graphSp.Id `
                -AppRoleId $roleId | Out-Null
        }
        catch {
            if ($_.Exception.Message -notmatch "already exists") {
                Write-Warn "Failed to grant Graph role $roleId — $($_.Exception.Message)"
            }
        }
    }
    Write-Ok "Graph application permissions consented."

    # Office 365 Management APIs service principal
    $o365Sp = Get-MgServicePrincipal -Filter "appId eq '$O365MgmtAppId'" -Top 1
    if ($o365Sp) {
        foreach ($roleId in @($ActivityFeedRead, $ActivityFeedReadDlp)) {
            try {
                New-MgServicePrincipalAppRoleAssignment `
                    -ServicePrincipalId $backendSp.Id `
                    -PrincipalId $backendSp.Id `
                    -ResourceId $o365Sp.Id `
                    -AppRoleId $roleId | Out-Null
            }
            catch {
                if ($_.Exception.Message -notmatch "already exists") {
                    Write-Warn "Failed to grant O365 role $roleId — $($_.Exception.Message)"
                }
            }
        }
        Write-Ok "O365 Management application permissions consented."
    }
    else {
        Write-Warn "O365 Management API service principal not found in tenant."
        Write-Warn "Grant consent manually via Azure Portal → API permissions → Grant admin consent."
    }
}
else {
    Write-Warn "Skipping admin consent (-SkipAdminConsent). Grant manually before first collection."
}

# ══════════════════════════════════════════════════════════════
# 2. FRONTEND SPA REGISTRATION (optional)
# ══════════════════════════════════════════════════════════════
$spaClientId = ""
$spaAppIdUri = ""

if ($IncludeSpa) {
    $spaAppName = "$AppNamePrefix-spa"
    Write-Step "Creating SPA app registration: $spaAppName ..."

    # Delegated permissions for the SPA
    $spaDelegatedAccess = @(
        @{ Id = $OpenId; Type = "Scope" },   # openid
        @{ Id = $Profile; Type = "Scope" },   # profile
        @{ Id = $UserRead; Type = "Scope" }    # User.Read
    )
    $spaRequiredResourceAccess = @(
        @{
            ResourceAppId  = $GraphAppId
            ResourceAccess = $spaDelegatedAccess
        }
    )

    # Build the SPA app with redirect URI, token issuance, and permissions in one call
    $spaApp = New-MgApplication `
        -DisplayName $spaAppName `
        -SignInAudience "AzureADMyOrg" `
        -Spa @{ RedirectUris = @($RedirectUri) } `
        -Web @{
        ImplicitGrantSettings = @{
            EnableAccessTokenIssuance = $true
            EnableIdTokenIssuance     = $true
        }
    } `
        -RequiredResourceAccess $spaRequiredResourceAccess

    $spaClientId = $spaApp.AppId
    $spaObjectId = $spaApp.Id
    Write-Ok "SPA App ID (client ID): $spaClientId"
    Write-Ok "Redirect URI: $RedirectUri"

    # ── 2a. Expose an API (Application ID URI + scope) ───────
    $spaAppIdUri = "api://$spaClientId"
    Write-Step "Setting Application ID URI: $spaAppIdUri ..."

    $scopeId = [guid]::NewGuid().ToString()
    Update-MgApplication -ApplicationId $spaObjectId `
        -IdentifierUris @($spaAppIdUri) `
        -Api @{
        Oauth2PermissionScopes = @(
            @{
                Id                      = $scopeId
                AdminConsentDescription = "Allow the Log Analytics SPA to access the backend API on behalf of the signed-in user."
                AdminConsentDisplayName = "Access Log Analytics API"
                UserConsentDescription  = "Allow Log Analytics to access the API on your behalf."
                UserConsentDisplayName  = "Access Log Analytics API"
                IsEnabled               = $true
                Type                    = "Admin"
                Value                   = "access_as_user"
            }
        )
    }
    Write-Ok "App ID URI set and 'access_as_user' scope created."

    # ── 2b. Service principal for SPA ────────────────────────
    Write-Step "Ensuring SPA service principal exists..."
    try {
        $spaSp = New-MgServicePrincipal -AppId $spaClientId
        Write-Ok "SPA service principal created (object ID: $($spaSp.Id))."
    }
    catch {
        if ($_.Exception.Message -match "already exists") {
            $spaSp = Get-MgServicePrincipal -Filter "appId eq '$spaClientId'"
            Write-Ok "SPA service principal already exists (OK)."
        }
        else { throw }
    }

    # ── 2c. Grant admin consent for delegated permissions ────
    if (-not $SkipAdminConsent) {
        Write-Step "Granting admin consent for SPA delegated permissions..."
        Start-Sleep -Seconds 3

        # For delegated permissions, use oauth2PermissionGrant
        $graphSp = Get-MgServicePrincipal -Filter "appId eq '$GraphAppId'" -Top 1
        try {
            New-MgOauth2PermissionGrant -Body @{
                ClientId    = $spaSp.Id
                ConsentType = "AllPrincipals"
                ResourceId  = $graphSp.Id
                Scope       = "openid profile User.Read"
            } | Out-Null
            Write-Ok "Admin consent granted for SPA delegated permissions."
        }
        catch {
            if ($_.Exception.Message -notmatch "already exists") {
                Write-Warn "SPA admin consent failed — grant manually if needed: $($_.Exception.Message)"
            }
            else {
                Write-Ok "Delegated permission grant already exists (OK)."
            }
        }
    }

    Write-Ok "Delegated: openid, profile, User.Read"
}

# ══════════════════════════════════════════════════════════════
# 3. UPDATE .env FILE
# ══════════════════════════════════════════════════════════════
$envPath = Join-Path $PSScriptRoot "backend" ".env"
$envBlock = @"

# ── Entra App Registration (auto-generated by Register-EntraApp.ps1) ──
AZURE_TENANT_ID=$tenantId
AZURE_CLIENT_ID=$backendClientId
AZURE_CLIENT_SECRET=$clientSecret
"@

if ($IncludeSpa) {
    $envBlock += @"

AUTH_MODE=both
FRONTEND_CLIENT_ID=$spaClientId
JWT_AUDIENCE=$spaAppIdUri
"@
}

if (Test-Path $envPath) {
    Write-Step "Updating backend/.env with new credentials..."
    $content = Get-Content $envPath -Raw

    # Replace placeholder values if present, otherwise append
    $replacements = @{
        "AZURE_TENANT_ID=your-tenant-id"         = "AZURE_TENANT_ID=$tenantId"
        "AZURE_CLIENT_ID=your-client-id"         = "AZURE_CLIENT_ID=$backendClientId"
        "AZURE_CLIENT_SECRET=your-client-secret" = "AZURE_CLIENT_SECRET=$clientSecret"
    }
    $modified = $false
    foreach ($kv in $replacements.GetEnumerator()) {
        if ($content -match [regex]::Escape($kv.Key)) {
            $content = $content -replace [regex]::Escape($kv.Key), $kv.Value
            $modified = $true
        }
    }

    if ($IncludeSpa) {
        if ($content -notmatch "FRONTEND_CLIENT_ID=") {
            $content += "`nFRONTEND_CLIENT_ID=$spaClientId"
            $content += "`nJWT_AUDIENCE=$spaAppIdUri"
            $content += "`nAUTH_MODE=both"
            $modified = $true
        }
    }

    if ($modified) {
        $content | Set-Content -Path $envPath -Encoding UTF8 -NoNewline
        Write-Ok ".env updated in place."
    }
    else {
        $envBlock | Add-Content -Path $envPath -Encoding UTF8
        Write-Ok "Credentials appended to .env."
    }
}
else {
    Write-Warn ".env not found at $envPath — printing values for manual setup."
}

# ══════════════════════════════════════════════════════════════
# 4. SUMMARY
# ══════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  Registration Complete!" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Backend App Registration" -ForegroundColor White
Write-Host "  ────────────────────────" -ForegroundColor DarkGray
Write-Host "    Display Name    : $backendAppName"
Write-Host "    Tenant ID       : $tenantId"
Write-Host "    Client ID       : $backendClientId"
Write-Host "    Client Secret   : $($clientSecret.Substring(0,4))****" -ForegroundColor Yellow
Write-Host "    Graph Perms     : AuditLog.Read.All, Directory.Read.All, Policy.Read.All, Group.Read.All"
Write-Host "    O365 Perms      : ActivityFeed.Read, ActivityFeed.ReadDlp"

if ($IncludeSpa) {
    Write-Host ""
    Write-Host "  Frontend SPA Registration" -ForegroundColor White
    Write-Host "  ─────────────────────────" -ForegroundColor DarkGray
    Write-Host "    Display Name    : $spaAppName"
    Write-Host "    Client ID       : $spaClientId"
    Write-Host "    App ID URI      : $spaAppIdUri"
    Write-Host "    Redirect URI    : $RedirectUri"
    Write-Host "    Scope           : access_as_user"
    Write-Host "    Delegated Perms : openid, profile, User.Read"
}

Write-Host ""
Write-Host "  .env values (copy to backend/.env if not auto-updated):" -ForegroundColor White
Write-Host "  ────────────────────────────────────────────────────────" -ForegroundColor DarkGray
Write-Host "    AZURE_TENANT_ID=$tenantId"
Write-Host "    AZURE_CLIENT_ID=$backendClientId"
Write-Host "    AZURE_CLIENT_SECRET=$clientSecret" -ForegroundColor Yellow

if ($IncludeSpa) {
    Write-Host "    AUTH_MODE=both"
    Write-Host "    FRONTEND_CLIENT_ID=$spaClientId"
    Write-Host "    JWT_AUDIENCE=$spaAppIdUri"
}

Write-Host ""
Write-Host "  Next steps:" -ForegroundColor Cyan
Write-Host "    1. Verify admin consent in Azure Portal → App registrations → API permissions"
if (-not $IncludeSpa) {
    Write-Host "    2. Run: .\start.ps1"
}
else {
    Write-Host "    2. Run: .\start.ps1   (frontend will use interactive auth)"
}
Write-Host ""
