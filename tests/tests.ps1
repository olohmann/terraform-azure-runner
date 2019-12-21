#!/usr/bin/env pwsh

function TfApply {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TestCase,
        [Parameter(Mandatory = $true)]
        [string]
        $TestCaseId
    )

    $env:__TF_backend_resource_group_name="$($TestCaseId)_tf_state"
    $env:TF_VAR_resource_group_name=$TestCaseId
    $env:TF_VAR_prefix="test"
    & "$PSScriptRoot\..\run_tf.ps1" -f -WorkingDirectory "$PSScriptRoot\$TestCase"
}

function TfDestroy {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TestCase,
        [Parameter(Mandatory = $true)]
        [string]
        $TestCaseId
    )

    $env:__TF_backend_resource_group_name="$($TestCaseId)_tf_state"
    $env:TF_VAR_resource_group_name=$TestCaseId
    $env:TF_VAR_prefix="test"
    & "$PSScriptRoot\..\run_tf.ps1" -f -destroy -WorkingDirectory "$PSScriptRoot\$TestCase"
}

function CleanUp {
    param (
        [Parameter(Mandatory = $true)]
        [string]
        $TestCaseId
    )
    
    $rgName="$($TestCaseId)_tf_state"
    az group delete -n $rgName -y --output none
}

Describe "deployments" {
    It "should handle simple (one sub-deployment) deployments " {
        TfApply -TestCase "simple" -TestCaseId "$testCaseId"
        $exists = az group exists -n $testCaseId | ConvertFrom-Json
        $exists | Should -Be $true
        
        TfDestroy -TestCase "simple" -TestCaseId "$testCaseId"
        $exists = az group exists -n $testCaseId | ConvertFrom-Json
        $exists | Should -Be $false
    }

    It "should handle complex (multiple sub-deployments) deployments " {
        TfApply -TestCase "multiple-sub-deployments" -TestCaseId "$testCaseId"
        $exists = az group exists -n $testCaseId | ConvertFrom-Json
        $exists | Should -Be $true
        
        TfDestroy -TestCase "multiple-sub-deployments" -TestCaseId "$testCaseId"
        $exists = az group exists -n $testCaseId | ConvertFrom-Json
        $exists | Should -Be $false
    }

    BeforeEach {
        $testCaseId = "test_$(New-Guid)"
    }

    AfterEach {
        CleanUp -TestCaseId $testCaseId
    }
}
