#!/usr/bin/env pwsh

#Requires -PSEdition Core
#Requires -Modules @{ ModuleName="Pester"; ModuleVersion="4.0.0" }

function GenerateRandomPrefix {
    $rndPrefix = -join ((97..122) | Get-Random -Count 8 | % {[char]$_})
    $rndPrefix
}

function TfApply {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TestCase,
        [Parameter(Mandatory = $true)]
        [string]
        $TestCasePrefix
    )

    $path = Join-Path -Path $PSScriptRoot -ChildPath $TestCase 
    $tf = Join-Path -Path $PSScriptRoot -ChildPath "../tf.ps1"
    $env:TF_VAR_resource_group_name = "$($TestCasePrefix)"
    
    & "$tf" -Apply -Prefix "$TestCasePrefix" -EnvironmentName "test" -Verbose -Force -TargetPath "$path" -DownloadTerraform
}

function TfDestroy {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TestCase,
        [Parameter(Mandatory = $true)]
        [string]
        $TestCasePrefix
    )

    $path = Join-Path -Path $PSScriptRoot -ChildPath $TestCase
    $tf = Join-Path -Path $PSScriptRoot -ChildPath "../tf.ps1"
    $env:TF_VAR_resource_group_name = "$($TestCasePrefix)"
    
    & "$tf" -Destroy -Prefix "$TestCasePrefix" -EnvironmentName "test" -Verbose -Force -TargetPath "$path" -DownloadTerraform
}

function CleanUp {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TestCasePrefix
    )
    
    $rgName="$($TestCasePrefix)_test_util_rg"
    az group delete -n $rgName -y --output none
}

Describe "deployments" {
    It "should handle simple (one sub-deployment) deployments " {
        TfApply -TestCase "simple/01_tf" -TestCasePrefix "$testCasePrefix"
        $exists = az group exists -n $testCasePrefix | ConvertFrom-Json
        $exists | Should -Be $true
        
        TfDestroy -TestCase "simple/01_tf" -TestCasePrefix "$testCasePrefix"
        $exists = az group exists -n "$testCasePrefix" | ConvertFrom-Json
        $exists | Should -Be $false
    }

    BeforeEach {
        $testCasePrefix = GenerateRandomPrefix
    }

    AfterEach {
        CleanUp -TestCasePrefix $testCasePrefix
    }
}
