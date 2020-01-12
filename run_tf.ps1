#!/usr/bin/env pwsh

param (
    [Parameter(Mandatory = $false)][Alias('e')][string]$EnvironmentName = "default",
    [Parameter(Mandatory = $false)][string]$WorkingDirectory = ".",
    [Parameter(Mandatory = $false)][string]$TerraformPlanOutputPath = "terraform.tfplan",

    [switch]$NoColor = $false,

    [switch]$Init = $false,
    [switch]$Plan = $false,
    [switch]$Destroy = $false,
    [switch]$LeaveFirewallOpen = $false,
    [switch]$Version = $false,

    [switch][Alias('d')]$DownloadTerraform = $false,
    [switch][Alias('p')]$PrintEnv = $false,
    [switch][Alias('v')]$Validate = $false,
    [switch][Alias('f')]$Force = $false
)

Set-StrictMode -Version latest
$ErrorActionPreference = "Stop"

$ScriptVersion = [version]"2.0.0"
$TerrafomMinimumVersion = [version]"0.12.17"
$TerraformNoColor = if ($NoColor) { "-no-color" } else { "" }

function GetLocalTerraformInstallation() {
    $tf = $null

    try {
        $tf = Get-Command terraform
    }
    catch {
        if (!$DownloadTerraform) {
            throw "No local terraform client found and option 'DownloadTerraform' not specified."
        }
    }

    return $tf.Source
}

function New-TemporaryDirectory {
    $parent = [System.IO.Path]::GetTempPath()
    [string] $name = [System.Guid]::NewGuid()
    New-Item -ItemType Directory -Path (Join-Path $parent $name)
}

function GetTerraformOsName {
    if ($IsLinux) {
        return "linux"
    }
    elseif ($IsMacOS) {
        return "darwin"
    }
    elseif ($IsWindows) {
        return "windows"
    }
    else {
        Write-Error "This script is executed in an unsupported OS."
    }
}

function VerifyTerraformSignature {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TerraformDownloadBaseFolder,
        [Parameter(Mandatory = $true)]
        [string]
        $TerraformZipFilePath
    )

    $tfShaSums = Join-Path -Path $TerraformDownloadBaseFolder -ChildPath "terraform_SHA265SUMS"
    $tfShaSumsSig = Join-Path -Path $TerraformDownloadBaseFolder -ChildPath "terraform_SHA265SUMS.sig"

    # See https://www.hashicorp.com/security.html
    $HashiCorpGpgSig = @"
-----BEGIN PGP PUBLIC KEY BLOCK-----
Version: GnuPG v1

mQENBFMORM0BCADBRyKO1MhCirazOSVwcfTr1xUxjPvfxD3hjUwHtjsOy/bT6p9f
W2mRPfwnq2JB5As+paL3UGDsSRDnK9KAxQb0NNF4+eVhr/EJ18s3wwXXDMjpIifq
fIm2WyH3G+aRLTLPIpscUNKDyxFOUbsmgXAmJ46Re1fn8uKxKRHbfa39aeuEYWFA
3drdL1WoUngvED7f+RnKBK2G6ZEpO+LDovQk19xGjiMTtPJrjMjZJ3QXqPvx5wca
KSZLr4lMTuoTI/ZXyZy5bD4tShiZz6KcyX27cD70q2iRcEZ0poLKHyEIDAi3TM5k
SwbbWBFd5RNPOR0qzrb/0p9ksKK48IIfH2FvABEBAAG0K0hhc2hpQ29ycCBTZWN1
cml0eSA8c2VjdXJpdHlAaGFzaGljb3JwLmNvbT6JATgEEwECACIFAlMORM0CGwMG
CwkIBwMCBhUIAgkKCwQWAgMBAh4BAheAAAoJEFGFLYc0j/xMyWIIAIPhcVqiQ59n
Jc07gjUX0SWBJAxEG1lKxfzS4Xp+57h2xxTpdotGQ1fZwsihaIqow337YHQI3q0i
SqV534Ms+j/tU7X8sq11xFJIeEVG8PASRCwmryUwghFKPlHETQ8jJ+Y8+1asRydi
psP3B/5Mjhqv/uOK+Vy3zAyIpyDOMtIpOVfjSpCplVRdtSTFWBu9Em7j5I2HMn1w
sJZnJgXKpybpibGiiTtmnFLOwibmprSu04rsnP4ncdC2XRD4wIjoyA+4PKgX3sCO
klEzKryWYBmLkJOMDdo52LttP3279s7XrkLEE7ia0fXa2c12EQ0f0DQ1tGUvyVEW
WmJVccm5bq25AQ0EUw5EzQEIANaPUY04/g7AmYkOMjaCZ6iTp9hB5Rsj/4ee/ln9
wArzRO9+3eejLWh53FoN1rO+su7tiXJA5YAzVy6tuolrqjM8DBztPxdLBbEi4V+j
2tK0dATdBQBHEh3OJApO2UBtcjaZBT31zrG9K55D+CrcgIVEHAKY8Cb4kLBkb5wM
skn+DrASKU0BNIV1qRsxfiUdQHZfSqtp004nrql1lbFMLFEuiY8FZrkkQ9qduixo
mTT6f34/oiY+Jam3zCK7RDN/OjuWheIPGj/Qbx9JuNiwgX6yRj7OE1tjUx6d8g9y
0H1fmLJbb3WZZbuuGFnK6qrE3bGeY8+AWaJAZ37wpWh1p0cAEQEAAYkBHwQYAQIA
CQUCUw5EzQIbDAAKCRBRhS2HNI/8TJntCAClU7TOO/X053eKF1jqNW4A1qpxctVc
z8eTcY8Om5O4f6a/rfxfNFKn9Qyja/OG1xWNobETy7MiMXYjaa8uUx5iFy6kMVaP
0BXJ59NLZjMARGw6lVTYDTIvzqqqwLxgliSDfSnqUhubGwvykANPO+93BBx89MRG
unNoYGXtPlhNFrAsB1VR8+EyKLv2HQtGCPSFBhrjuzH3gxGibNDDdFQLxxuJWepJ
EK1UbTS4ms0NgZ2Uknqn1WRU1Ki7rE4sTy68iZtWpKQXZEJa0IGnuI2sSINGcXCJ
oEIgXTMyCILo34Fa/C6VCm2WBgz9zZO8/rHIiQm1J5zqz0DrDwKBUM9C
=LYpS
-----END PGP PUBLIC KEY BLOCK-----
"@
    if ($IsWindows) {
        Write-Warning "Skipping SHA256SUM signature validation. Requires GPG."
    }
    else {
        $hashiCorpGpgTmpFile = Join-Path $TerraformDownloadBaseFolder -ChildPath "hashicorp.gpg"
        Set-Content -Path $hashiCorpGpgTmpFile -Value $HashiCorpGpgSig
        gpg --quiet --no-verbose --batch --no-tty --import $hashiCorpGpgTmpFile
        gpg --quiet --no-verbose --batch --no-tty --verify  $tfShaSumsSig $tfShaSums
        if ($LastExitCode -gt 0) { throw "GPG signature validation of Terraform's SHA256 sums failed." }
    }

    $hash = Get-FileHash -Path $TerraformZipFilePath -Algorithm 'SHA256'
    $zipFileName = Split-Path $TerraformZipFilePath -Leaf

    $success = $false
    $shaSums = Get-Content $tfShaSums
    foreach ($line in $shaSums) {
        if ($line -like "*$zipFileName*") {
            $result = $line -Split '  '
            if ($result.Count -gt 0) {
                $success = $result[0] -eq $hash.Hash
            }
        }
    }

    if (!$success) {
        throw "Validating the signature of the downloaded terraform release failed. See Path: $($TerraformDownloadBaseFolder)"
    }
}

function DownloadCurrentTerraformVersionToTemporaryLocation {
    $osName = GetTerraformOsName
    $uriBinary = "https://releases.hashicorp.com/terraform/$TerrafomMinimumVersion/terraform_$($TerrafomMinimumVersion)_$($osName)_amd64.zip"
    $uriShaSums = "https://releases.hashicorp.com/terraform/$TerrafomMinimumVersion/terraform_$($TerrafomMinimumVersion)_SHA256SUMS"
    $uriShaSumsSig = "https://releases.hashicorp.com/terraform/$TerrafomMinimumVersion/terraform_$($TerrafomMinimumVersion)_SHA256SUMS.sig"

    $tmpDirectory = New-TemporaryDirectory
    $outputBinary = Join-Path -Path $tmpDirectory -ChildPath "terraform_$($TerrafomMinimumVersion)_$($osName)_amd64.zip"
    $outputShaSums = Join-Path -Path $tmpDirectory -ChildPath "terraform_SHA265SUMS"
    $outputShaSumsSig = Join-Path -Path $tmpDirectory -ChildPath "terraform_SHA265SUMS.sig"

    Invoke-WebRequest -Uri $uriBinary -OutFile $outputBinary
    Invoke-WebRequest -Uri $uriShaSums -OutFile $outputShaSums
    Invoke-WebRequest -Uri $uriShaSumsSig -OutFile $outputShaSumsSig

    VerifyTerraformSignature -TerraformDownloadBaseFolder $tmpDirectory -TerraformZipFilePath $outputBinary
    Expand-Archive -Path $outputBinary -DestinationPath $tmpDirectory

    if ($IsWindows) {
        $tfExe = Join-Path $tmpDirectory -ChildPath "terraform.exe"
        return $tfExe 
    }
    else {
        $tfExe = Join-Path $tmpDirectory -ChildPath "terraform"
        chmod +x $tfExe
        return $tfExe 
    }
}

function ValidateTerraformMinimumVersion {
    $versionInfo = [Version]"0.0.0"
    $versionStr = &"$TerraformPath" --% -version
    if ($LastExitCode -gt 0) { throw "Cannot validate terraform version." }

    [Regex]$regex = "v(?<versionNumber>\d+.\d+.\d+)"
    $regexMatch = $regex.Match($versionStr)
    if ($regexMatch.Success) {
        $versionInfo = [Version]$($regexMatch.Groups["versionNumber"].Value)
    }
    else {
        throw "Cannot get version number from terraform."
    }

    if (!$($versionInfo -ge $TerrafomMinimumVersion)) {
        throw "Require at least terraform v$TerrafomMinimumVersion but found terraform v$versionInfo."
    }
}

function GetSha256 {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $InputString,
        [Parameter(Mandatory = $false)]
        [int]
        $TrimTo = -1
    )

    $hashValue = New-Object System.Security.Cryptography.SHA256Managed `
    | ForEach-Object { $_.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($InputString)) } `
    | ForEach-Object { $_.ToString("x2") } `
    | Join-String 
    
    $hashValue = $hashValue.ToLower()
    if ($trimTo -gt -1) {
        $hashValue = $hashValue.Substring(0, $trimTo)
    }

    return $hashValue
}

function CreateOrUpdateTerraformBackend {
    if (!$env:TF_VAR_prefix) { $env:TF_VAR_prefix = "contoso" }
    if (!$env:TF_VAR_location) { $env:TF_VAR_location = "northeurope" }
    if (!$env:__TF_backend_resource_group_name) { $env:__TF_backend_resource_group_name = "$($env:TF_VAR_prefix)_tf_state_rg" }
    if (!$env:__TF_backend_location) { $env:__TF_backend_location = $env:TF_VAR_location }
    $env:__TF_backend_location = $env:__TF_backend_location.Replace(' ', '').ToLower()

    az group create --name "$env:__TF_backend_resource_group_name" --location "$env:__TF_backend_location" --output none
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $azRes = az group show --name "$env:__TF_backend_resource_group_name" --output json | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $tf_backend_resource_group_id = $azRes.Id
    $tf_hash_suffix = GetSha256 -InputString $tf_backend_resource_group_id -TrimTo 6

    if (!$env:__TF_backend_storage_account_name) { $env:__TF_backend_storage_account_name = "$($env:TF_VAR_prefix)$($tf_hash_suffix)" }
    if (!$env:__TF_backend_storage_container_name) { $env:__TF_backend_storage_container_name = "tf-state" }

    az storage account create --name $env:__TF_backend_storage_account_name --resource-group $env:__TF_backend_resource_group_name --location $env:__TF_backend_location --sku "Standard_LRS" --kind "BlobStorage" --access-tier "Hot" --encryption-service "blob" --encryption-service "file" --https-only "true" --default-action "Allow" --bypass "None" --output none
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    Write-Verbose "Updating firewall configuration..."
    $saUpdateRetryCount = 0
    $saUpdateSuccessful = $false
    for ($saUpdateRetryCount = 0; $saUpdateRetryCount -lt 5 -and !$saUpdateSuccessful; $saUpdateRetryCount++) {
        $saShowResponse = az storage account show --name $env:__TF_backend_storage_account_name | ConvertFrom-Json
        if ($saShowResponse.networkRuleSet.defaultAction.ToLower() -eq "allow") {
            Write-Verbose "Successfully configured firewall..."
            $saUpdateSuccessful = $true
        }
        else {
            Write-Verbose "Waiting for update..."
            Start-Sleep -Seconds 3
        }
    }

    if (!$saUpdateSuccessful) {
        throw "Failed to temporarily de-activate the terraform state storage account's firewall."
    }

    $accountKeyResponse = az storage account keys list --account-name $env:__TF_backend_storage_account_name | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    az storage container create --account-name $env:__TF_backend_storage_account_name --account-key $accountKeyResponse[0].value --name $env:__TF_backend_storage_container_name --public-access "off" --auth-mode key --output none
    if ($LastExitCode -gt 0) { throw "az CLI error." }
}

function BackendHasLockedStateFiles {
    $azContainerListResponse = az storage blob list -c $env:__TF_backend_storage_container_name --account-name $env:__TF_backend_storage_account_name | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    Write-Verbose "Looking for locked state blobs..."
    $hasAnyLockedBlobs = $false
    foreach ($elem in $azContainerListResponse) {
        if ($elem.properties.lease.state.ToLower() -eq "leased") {
            Write-Verbose "Found locked blob: $($elem.name)"
            $hasAnyLockedBlobs = $true
            Break
        }
    }

    return $hasAnyLockedBlobs
}

function LockdownTerraformBackend {
    if (BackendHasLockedStateFiles) {
        Write-Warning "Skipping Firewall log, found locked state file."
        return
    }

    $existingNetworkRulesResponse = az storage account network-rule list --account-name $env:__TF_backend_storage_account_name | ConvertFrom-Json
    if ($LastExitCode -gt 0) { throw "az CLI error." }
    Write-Verbose "Rewriting network rules..."
    foreach ($ipRule in $existingNetworkRulesResponse.ipRules) {
        Write-Verbose "Dropping $($ipRule.ipAddressOrRange)"
        az storage account network-rule remove --resource-group $env:__TF_backend_resource_group_name --account-name $env:__TF_backend_storage_account_name --ip-address $ipRule.ipAddressOrRange --output none
        if ($LastExitCode -gt 0) { throw "az CLI error." }
    }

    $ipRules = if (!$env:__TF_backend_network_access_rules) { @() } else { $env:__TF_backend_network_access_rules.Split(',') }
    foreach ($ipRule in $ipRules) {
        Write-Verbose "Adding $ipRule"
        az storage account network-rule add --resource-group $env:__TF_backend_resource_group_name --account-name $env:__TF_backend_storage_account_name --ip-address $ipRule --output none
        if ($LastExitCode -gt 0) { throw "az CLI error." }
    }

    Write-Verbose "Set storage account firewall to `"default-action: Deny`"..."
    az storage account update --name $env:__TF_backend_storage_account_name --default-action "Deny" --output none
    if ($LastExitCode -gt 0) { throw "az CLI error." }
}

function CollectTerraformSubDeployments {
    $basePath = Resolve-Path $WorkingDirectory
    $tfFiles = Get-ChildItem -Path $basePath -Filter *.tf -Recurse -ErrorAction SilentlyContinue -Force -Depth 1

    # Get the individual base directories.
    $set = @{ }
    foreach ($tfFile in $tfFiles) {
        if (!$set.ContainsKey($tfFile.Directory.FullName)) {
            $set.Add($tfFile.Directory.FullName, $true)
        }
    }

    return $set.Keys.GetEnumerator() | sort 
}

function EnsureAzureCliContext () {
    if ($Force) {
        return
    }

    $defaultSubscriptionDetails = az account list --all --query "[?isDefault] | [0]" | ConvertFrom-Json 
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $defaultSubscriptionId = $defaultSubscriptionDetails.id;
    $defaultSubscriptionName = $defaultSubscriptionDetails.name;

    Write-Host ""
    Write-Host "Detected the following Azure configuration:"
    Write-Host "Subscription ID = $defaultSubscriptionId"
    Write-Host "Subscription Name = $defaultSubscriptionName"
    Write-Host ""

    $confirmation = Read-Host "Continue using this subscription? (y/n)"
    if ($confirmation.ToLower() -ne 'y') {
        Write-Host "Stopped by user."
        Write-Host ""
        exit
    }
}

function SwitchToTerraformWorskpace {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path,
        [Parameter(Mandatory = $true)]
        [string]
        $Workspace
    )

    Write-Verbose "Switch Workspace: $Path"

    Push-Location
    try {
        Set-Location -Path $Path
        $tfWorkspace = &"$TerraformPath" workspace show
        if ($LastExitCode -gt 0) { throw "terraform error." }

        Write-Verbose "Current Terraform Workspace: $tfWorkspace"
        if ($tfWorkspace.ToLower() -eq $Workspace.ToLower()) {
            Write-Verbose "No Terraform workspace switch required."
        }
        else {
            $tfWorkspaceListString = &"$TerraformPath" workspace list
            if ($LastExitCode -gt 0) { throw "terraform error." }
            $tfWorkspaceList = $tfWorkspaceListString.Split([Environment]::NewLine)
            $found = $false
            foreach ($tfWorkspaceItem in $tfWorkspaceList) {
                Write-Verbose "found $tfWorkspaceItem"
                if ($tfWorkspaceItem.ToLower().Contains($Workspace.ToLower())) {
                    $found = $true
                    Break
                }
            }

            if ($found) {
                &"$TerraformPath" workspace select $Workspace.ToLower()
                if ($LastExitCode -gt 0) { throw "terraform error." }
            }
            else {
                &"$TerraformPath" workspace new $Workspace.ToLower()
                if ($LastExitCode -gt 0) { throw "terraform error." }
            }
        }
    }
    finally {
        Pop-Location
    }
}

function TerraformPlan {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Verbose "Plan: $Path"

    Push-Location
    try {
        Set-Location -Path $Path
        &"$TerraformPath" plan $TerraformNoColor -input=false -out="`"$TerraformPlanOutputPath`""
        if ($LastExitCode -gt 0) { throw "terraform error." }
    }
    finally {
        Pop-Location
    }
}

function SetTerraformOutputAsEnvironmentVariables {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Verbose "Set Output: $Path"

    Push-Location
    try {
        Set-Location -Path $Path

        $tfJsonOutput = &"$TerraformPath" output -json | ConvertFrom-Json
        if ($LastExitCode -gt 0) { throw "terraform error." }

        $tfJsonOutput.PSObject.Properties | ForEach-Object {
            $key = "TF_VAR_$($_.Name)"
            $value = "$($_.Value.value)"
            Write-Verbose "Exporting: $key"
            Set-Item -LiteralPath Env:$key -Value $value
        }
    }
    finally {
        Pop-Location
    }
}

function TerraformApply {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Verbose "Apply: $Path"

    Push-Location
    try {
        Set-Location -Path $Path

        if (!$force) {
            $confirmation = Read-Host "Continue terraform deployment? (y/n)"
            if ($confirmation.ToLower() -ne 'y') {
                Write-Host "Stopped by user."
                Write-Host ""
                exit
            }
        }

        &"$TerraformPath" apply $TerraformNoColor -input=false "`"$TerraformPlanOutputPath`""
        if ($LastExitCode -gt 0) { throw "terraform error." }
    }
    finally {
        Pop-Location
    }
}

function TerraformDestroy {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Verbose "Destroy: $Path"

    Push-Location
    try {
        Set-Location -Path $Path

        if (!$force) {
            $confirmation = Read-Host "Continue with terraform destroy? (y/n)"
            if ($confirmation.ToLower() -ne 'y') {
                Write-Host "Stopped by user."
                Write-Host ""
                exit
            }
        }

        &"$TerraformPath" destroy $TerraformNoColor -auto-approve -input=false 
        if ($LastExitCode -gt 0) { throw "terraform error." }
    }
    finally {
        Pop-Location
    }
}



function CleanTerraformDirectory {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    $tfStateFile = Join-Path -Path $Path -ChildPath ".terraform" -AdditionalChildPath "terraform.tfstate"
    $tfStateEnvironmentFile = Join-Path -Path $Path -ChildPath ".terraform" -AdditionalChildPath "environment"
    $tfPlanFile = Join-Path -Path $Path -ChildPath "terraform.tfplan" 
    Remove-Item -ErrorAction SilentlyContinue -Path $tfStateFile
    Remove-Item -ErrorAction SilentlyContinue -Path $tfStateEnvironmentFile
    Remove-Item -ErrorAction SilentlyContinue -Path $tfPlanFile
}

function InitTerraformWithRemoteBackend {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Write-Verbose "Init: $Path"

    $accountKeyResponse = az storage account keys list --account-name $env:__TF_backend_storage_account_name | ConvertFrom-Json
    $key = $accountKeyResponse[0].value

    Push-Location
    try {
        Set-Location -Path $Path
        &"$TerraformPath" init $TerraformNoColor -backend-config "resource_group_name=$env:__TF_backend_resource_group_name" -backend-config "storage_account_name=$env:__TF_backend_storage_account_name" -backend-config "container_name=$env:__TF_backend_storage_container_name" -backend-config "access_key=`"$key`""
        if ($LastExitCode -gt 0) { throw "terraform error." }
    }
    finally {
        Pop-Location
    }
}

function InitTerraformWithLocalBackend {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Push-Location
    try {
        Set-Location -Path $Path
        $ignoreOutput = &"$TerraformPath" init -backend=false $TerraformNoColor
        if ($LastExitCode -gt 0) { 
            Write-Error $ignoreOutput
            throw "terraform error."
        }
    }
    finally {
        Pop-Location
    }
}

function RunTerraformValidate {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $Path
    )

    Push-Location
    Set-Location -Path $Path
    $ignore = &"$TerraformPath" validate
    $validationError = $LastExitCode -gt 0
    Pop-Location
    return $validationError
}

function PatchTerraformEnvironmentVariables {
    $isVerbose = [bool](Write-Verbose ([String]::Empty) 4>&1)

    Write-Verbose "Patching Environment Variables to be compatible with Terraform Variables"
    $environmentVariables = (Get-ChildItem env:*).GetEnumerator() | Sort-Object Name 

    if ($isVerbose -and $PrintEnv) {
        Write-Verbose ""
        Write-Verbose "[ Original Environment Variables ]"
        foreach ($environmentVariable in $environmentVariables) {
            Write-Verbose "$($environmentVariable.Name)=$($environmentVariable.Value)"
        }
    }

    foreach ($environmentVariable in $environmentVariables) {
        if ($environmentVariable.Name.StartsWith("TF_VAR_")) {
            $caseFixedName = "TF_VAR_" + $environmentVariable.Name.Remove(0, "TF_VAR_".Length).ToLower()
            Set-Item -LiteralPath Env:$caseFixedName -Value $environmentVariable.Value
        }

        if ($environmentVariable.Name.StartsWith("__TF_")) {
            $caseFixedName = "__TF_" + $environmentVariable.Name.Remove(0, "__TF_".Length).ToLower()
            Set-Item -LiteralPath Env:$caseFixedName -Value $environmentVariable.Value
        }
    }

    if ($isVerbose -and $PrintEnv) {
        $environmentVariables = (Get-ChildItem env:*).GetEnumerator() | Sort-Object Name 

        Write-Verbose ""
        Write-Verbose "[ Patched Environment Variables ]"
        foreach ($environmentVariable in $environmentVariables) {
            Write-Verbose "$($environmentVariable.Name)=$($environmentVariable.Value)"
        }
    }
}


# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
# ------------------------------------------------------------------------------
if ($Version) {
    Write-Host $ScriptVersion
    return
}

# Prepare Terraform Environment ------------------------------------------------
if ($env:ARM_CLIENT_ID -and $env:ARM_CLIENT_SECRET -and $env:ARM_SUBSCRIPTION_ID -and $env:ARM_TENANT_ID) {
    Write-Verbose "Detected Terraform-specific Azure Authorization via environment variables (ARM_CLIENT_ID, ...)"
}
elseif ($env:servicePrincipalId) {
    Write-Verbose "Detected Azure DevOps az configuration. Automatically setting Terraform env vars."
    $env:ARM_CLIENT_ID = $env:servicePrincipalId
    $env:ARM_CLIENT_SECRET = $env:servicePrincipalKey

    $defaultSubscriptionDetails = az account list --all --query "[?isDefault] | [0]" | ConvertFrom-Json 
    if ($LastExitCode -gt 0) { throw "az CLI error." }

    $env:ARM_SUBSCRIPTION_ID = = $defaultSubscriptionDetails.id
    $env:ARM_TENANT_ID = $defaultSubscriptionDetails.tenantId
}
elseif ($env:AZURE_CREDENTIALS) {
    Write-Verbose "Detected GitHub az configuration. Automatically setting Terraform env vars. "
    $GitHubJsonSettings = ConvertFrom-Json -InputObject $env:AZURE_CREDENTIALS
    $env:ARM_CLIENT_ID = $GitHubJsonSettings.clientId
    $env:ARM_CLIENT_SECRET = $GitHubJsonSettings.clientSecret
    $env:ARM_SUBSCRIPTION_ID = $GitHubJsonSettings.subscriptionId
    $env:ARM_TENANT_ID = $GitHubJsonSettings.tenantId
}
else {
    Write-Verbose "Using az authentication context for Terraform (default for interactive login)"
}

# Fix Environment --------------------------------------------------------------
PatchTerraformEnvironmentVariables

# Setup Terraform --------------------------------------------------------------
if ($DownloadTerraform) {
    $TerraformPath = DownloadCurrentTerraformVersionToTemporaryLocation
}
else {
    $TerraformPath = GetLocalTerraformInstallation
}

ValidateTerraformMinimumVersion

$subDeployments = CollectTerraformSubDeployments
if ($subDeployments -is [Array] -and $Plan) {
    throw "Cannot have multiple 'Deployment Tiers' and use -Plan. Split your terraform code in multiple pipelines and push artefacts from tier to tier."
}

if (!$($subDeployments -is [Array])) {
    $subDeployment = @($subDeployments)
}

# Run Validation on all Subdeployments -----------------------------------------
$tfValidationErrorsDetected = $false
foreach ($subDeployment in $subDeployments) {
    Write-Verbose "Validating Sub-Deployment: $subDeployment"
    CleanTerraformDirectory -Path $subDeployment
    InitTerraformWithLocalBackend -Path $subDeployment
    $tfValidate = RunTerraformValidate -Path $subDeployment
    $tfValidationErrorsDetected = $tfValidationErrorsDetected -or $tfValidate
    if ($tfValidationErrorsDetected) {
        Write-Warning "Sub-Deployment $subDeployment has validation errors."
    }
}

# Run deployment on all Subdeployments -----------------------------------------
if ($tfValidationErrorsDetected) {
    throw "Terraform Validation errors in at least one Sub-Deployment detected. Stopping deployment process."
}
else {
    Write-Verbose "Validation completed successfully."
}

if ($Validate) {
    Write-Verbose "Validation only completed successfully."
    return
}

EnsureAzureCliContext
CreateOrUpdateTerraformBackend

if ($Destroy) {
    foreach ($subDeployment in $subDeployments) {
        CleanTerraformDirectory -Path $subDeployment
        InitTerraformWithRemoteBackend -Path $subDeployment
        SwitchToTerraformWorskpace -Path $subDeployment -Workspace $EnvironmentName
        SetTerraformOutputAsEnvironmentVariables -Path $subDeployment
        CleanTerraformDirectory -Path $subDeployment
    }

    if ($subDeployments -is [Array]) {
        [array]::Reverse($subDeployments)
    }

    foreach ($subDeployment in $subDeployments) {
        CleanTerraformDirectory -Path $subDeployment
        InitTerraformWithRemoteBackend -Path $subDeployment
        SwitchToTerraformWorskpace -Path $subDeployment -Workspace $EnvironmentName
        TerraformDestroy -Path $subDeployment
    }
}
else {
    foreach ($subDeployment in $subDeployments) {
        CleanTerraformDirectory -Path $subDeployment
        InitTerraformWithRemoteBackend -Path $subDeployment
        SwitchToTerraformWorskpace -Path $subDeployment -Workspace $EnvironmentName
        if ($Init) { Break }

        TerraformPlan -Path $subDeployment
        if ($Plan) { Break }

        TerraformApply -Path $subDeployment
        SetTerraformOutputAsEnvironmentVariables -Path $subDeployment
    }
}

if (!$LeaveFirewallOpen) {
    LockdownTerraformBackend
}
