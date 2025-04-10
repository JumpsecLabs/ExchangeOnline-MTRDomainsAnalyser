param( 
    [string]$oA,     # Output Approved Domains/IPs file
    [string]$oR,     # Output Rejected Domains/IPs file
    [string]$oU,     # Output Uncategorised Rules file (CSV)
    [string]$oE,     # Output Excluded (Conflicting) Domains/IPs file
    [string]$Lookup, # Lookup a specific domain/IP and show its associated rules
    [switch]$ShowConflicts,
    [switch]$Help
)

if ($Help) {
    Write-Host "Usage: .\ExchangeOnline-MTR_Domains.ps1 [-oA approved.txt] [-oR rejected.txt] [-oU uncategorised.csv] [-oE excluded.txt] [-Lookup domainname.com] [-ShowConflicts] [-Help] [-Verbose]" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   -oA             Specifies the output file for approved domains/IPs."
    Write-Host "   -oR             Specifies the output file for rejected domains/IPs."
    Write-Host "   -oU             Specifies the output CSV file for uncategorised rules."
    Write-Host "   -oE             Specifies the output file for excluded (conflicting) domains/IPs."
    Write-Host "   -Lookup         Lookup a specific domain/IP (e.g., 'domainname.com') and show its associated rules."
    Write-Host "   -ShowConflicts  Show detailed conflicting rules information."
    Write-Host "   -Help, -?       Display this help message."
    Write-Host "   -Verbose        Show additional details for categorisation actions."
    exit
}

# Connect to Exchange Online
$account = Read-Host "Enter the account (UPN) for Connect-ExchangeOnline"
Connect-ExchangeOnline -UserPrincipalName $account -ShowBanner:$false

# Retrieve Tenant name
$tenantName = (Get-OrganizationConfig).Name

# Retrieve enabled transport rules
$rules = Get-TransportRule | Where-Object { $_.State -eq "Enabled" }

# Initialise domain/IP categorisation sets and tracking dictionaries for conflict diffing
$approvedDomains = New-Object System.Collections.Generic.HashSet[string]
$rejectedDomains = New-Object System.Collections.Generic.HashSet[string]
$uncategorisedRules = @()
$domainApprovalRules = @{}
$domainRejectionRules = @{}

foreach ($rule in $rules) {
    $ruleDomains = @()
    $ruleIPs = @()

    # Extract explicit sender and recipient domains
    $domainConditions = @(
        $rule.SenderDomainIs,
        $rule.ExceptIfSenderDomainIs,
        $rule.RecipientDomainIs,
        $rule.ExceptIfRecipientDomainIs
    ) | Where-Object { $_ } | Select-Object -Unique

    foreach ($domArray in $domainConditions) {
        $ruleDomains += $domArray
    }

    # Extract exception domains separately (those in the Except if clauses)
    $exceptionDomains = @()
    if ($rule.ExceptIfSenderDomainIs) { $exceptionDomains += $rule.ExceptIfSenderDomainIs }
    if ($rule.ExceptIfRecipientDomainIs) { $exceptionDomains += $rule.ExceptIfRecipientDomainIs }
    $exceptionDomains = $exceptionDomains | Select-Object -Unique

    # For each exception domain, mark it as approved and track it
    foreach ($ex in $exceptionDomains) {
        $key = $ex.ToLower()
        $approvedDomains.Add($key) | Out-Null
        if (-not $domainApprovalRules.ContainsKey($key)) { $domainApprovalRules[$key] = @() }
        $domainApprovalRules[$key] += $rule
    }
    # Remove exception domains from ruleDomains so they aren't processed twice
    $ruleDomains = $ruleDomains | Where-Object { $exceptionDomains -notcontains $_ }

    # Extract explicit sender IPs
    if ($rule.SenderIpRanges) {
        foreach ($ip in $rule.SenderIpRanges) {
            $ruleIPs += $ip
        }
    }

    # Parse Rule Name for additional domains/emails/IPs
    $ruleNameDomains = [regex]::Matches($rule.Name, "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b|\b[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b") |
                       Select-Object -ExpandProperty Value |
                       ForEach-Object { $_.ToLower() }
    $ruleNameIPs = [regex]::Matches($rule.Name, "\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b") |
                   Select-Object -ExpandProperty Value

    foreach ($nameDomain in $ruleNameDomains) {
        if ($nameDomain -notin $ruleDomains) {
            $ruleDomains += $nameDomain
        }
    }
    foreach ($nameIP in $ruleNameIPs) {
        if ($nameIP -notin $ruleIPs) {
            $ruleIPs += $nameIP
        }
    }

    # Explicit handling of SenderDomainIs/SenderIP rules with SetSCL
    if (($ruleDomains.Count -gt 0 -or $ruleIPs.Count -gt 0) -and $rule.SetSCL -ne $null) {
        if ($rule.SetSCL -eq -1) {
            foreach ($domain in $ruleDomains) {
                $key = $domain.ToLower()
                $approvedDomains.Add($key) | Out-Null
                if (-not $domainApprovalRules.ContainsKey($key)) { $domainApprovalRules[$key] = @() }
                $domainApprovalRules[$key] += $rule
                Write-Verbose "- Domain '$domain' explicitly bypasses spam filtering (SCL=-1). Categorised as Approved."
            }
            foreach ($ip in $ruleIPs) {
                $key = $ip
                $approvedDomains.Add($key) | Out-Null
                if (-not $domainApprovalRules.ContainsKey($key)) { $domainApprovalRules[$key] = @() }
                $domainApprovalRules[$key] += $rule
                Write-Verbose "- IP '$ip' explicitly bypasses spam filtering (SCL=-1). Categorised as Approved."
            }
            continue
        }
        elseif ($rule.SetSCL -ge 5) {
            foreach ($domain in $ruleDomains) {
                $key = $domain.ToLower()
                $rejectedDomains.Add($key) | Out-Null
                if (-not $domainRejectionRules.ContainsKey($key)) { $domainRejectionRules[$key] = @() }
                $domainRejectionRules[$key] += $rule
                Write-Verbose "- Domain '$domain' marked as spam/high risk (SCL=$($rule.SetSCL)). Categorised as Rejected."
            }
            continue
        }
    }

    # Enhanced rejection logic
    $isRejectAction = $rule.DeleteMessage -or
                      $rule.Quarantine -or
                      $rule.RejectMessageReasonText -or
                      $rule.ModerateMessageByUser -or
                      ($rule.SetSCL -ge 5) -or
                      ($rule.RedirectMessageTo -match "quarantine|junk") -or
                      $rule.SubjectOrBodyContainsWords -match "spam|phish|malware|junk|invoice|urgent|password|payment" -or
                      $rule.AttachmentNameMatchesPatterns -match "\.(exe|bat|vbs|ps1|scr|zip|rar|7z)$" -or
                      $rule.HeaderMatchesPatterns -match "X-Originating-IP|Return-Path|Authentication-Results" -or
                      ($rule.MessageSizeOver -and $rule.MessageSizeOver -ge 10485760) -or
                      $rule.UserIs -match "Impersonation" -or
                      $rule.SubjectOrBodyMatchesPatterns -or
                      $rule.SubjectMatchesPatterns -or
                      $rule.FromAddressContainsWords -or
                      $rule.From -or
                      $rule.RecipientAddressContainsWords -or
                      $rule.RecipientAddressContainsWordsPredicate -or
                      ($rule.HeaderContainsWords -and $rule.SetSCL -ge 5)

    # Enhanced approval logic
    $isApproveAction = $rule.ApplyHtmlDisclaimerText -or
                       $rule.PrependSubject -or
                       $rule.PrependBody -or
                       $rule.ApplyOME -or
                       $rule.ApplyRightsProtectionTemplate -or
                       ($rule.SetSCL -le 0 -and $rule.SetSCL -ne $null) -or
                       ($rule.RedirectMessageTo -and $rule.RedirectMessageTo -notmatch "quarantine|junk") -or
                       $rule.AddManagerAsRecipientType -or
                       $rule.SetAuditSeverity -or
                       $rule.SetHeaderName -or
                       $rule.CopyTo -or
                       $rule.RedirectMessageTo -or
                       $rule.ApplyHtmlDisclaimer -or
                       $rule.StopRuleProcessing -or
                       $rule.FromMemberOfPredicate

    # Final Categorisation logic
    if ($ruleDomains.Count -gt 0 -or $ruleIPs.Count -gt 0) {
        if ($isRejectAction -and -not $isApproveAction) {
            foreach ($item in ($ruleDomains + $ruleIPs)) {
                $key = $item.ToLower()
                $rejectedDomains.Add($key) | Out-Null
                if (-not $domainRejectionRules.ContainsKey($key)) { $domainRejectionRules[$key] = @() }
                $domainRejectionRules[$key] += $rule
            }
        }
        elseif ($isApproveAction -and -not $isRejectAction) {
            foreach ($item in ($ruleDomains + $ruleIPs)) {
                $key = $item.ToLower()
                $approvedDomains.Add($key) | Out-Null
                if (-not $domainApprovalRules.ContainsKey($key)) { $domainApprovalRules[$key] = @() }
                $domainApprovalRules[$key] += $rule
            }
        }
        elseif ($isRejectAction -and $isApproveAction) {
            foreach ($item in ($ruleDomains + $ruleIPs)) {
                $key = $item.ToLower()
                $rejectedDomains.Add($key) | Out-Null
                if (-not $domainRejectionRules.ContainsKey($key)) { $domainRejectionRules[$key] = @() }
                $domainRejectionRules[$key] += $rule
            }
        }
        else {
            $uncategorisedRules += [PSCustomObject]@{
                RuleName    = $rule.Name
                DomainsIPs  = ($ruleDomains + $ruleIPs) -join ", "
                Conditions  = $rule.Conditions | Out-String
                Actions     = $rule.Actions | Out-String
                SCL         = if ($rule.SetSCL -ne $null) { $rule.SetSCL } else { "N/A" }
                Description = $rule.Description
            }
        }
    }
}

# Conflict/Diffing Feature: Detect domains/IPs that appear in both approved and rejected lists
$conflicts = @($approvedDomains) | Where-Object { $rejectedDomains.Contains($_) }
$excludedDomains = @()
if ($conflicts.Count -gt 0) {
    $excludedDomains = $conflicts
    # Remove conflicting domains/IPs from approved and rejected lists
    foreach ($domain in $excludedDomains) {
        $approvedDomains.Remove($domain) | Out-Null
        $rejectedDomains.Remove($domain) | Out-Null
    }
}

# Lookup Feature: If -Lookup is specified, show the rules associated with that domain/IP and exit
if ($Lookup) {
    $lookupKey = $Lookup.ToLower()
    $lookupRules = @()
    if ($domainApprovalRules.ContainsKey($lookupKey)) {
        $lookupRules += $domainApprovalRules[$lookupKey]
    }
    if ($domainRejectionRules.ContainsKey($lookupKey)) {
        $lookupRules += $domainRejectionRules[$lookupKey]
    }
    foreach ($uncat in $uncategorisedRules) {
        if ($uncat.DomainsIPs -match $lookupKey) {
            $lookupRules += $uncat
        }
    }
    if ($lookupRules.Count -gt 0) {
        Write-Host "`n[Lookup Results for '$Lookup']:" -ForegroundColor Cyan
        foreach ($rule in $lookupRules) {
            if ($rule -is [PSCustomObject]) {
                Write-Host "Rule: $($rule.RuleName)" -ForegroundColor Yellow
                if ($rule.PSObject.Properties["Identity"]) {
                    Write-Host "   Identity: $($rule.Identity)" -ForegroundColor Yellow
                }
                Write-Host "  Domains/IPs: $($rule.DomainsIPs)"
                Write-Host "  Conditions: $($rule.Conditions)"
                Write-Host "  Actions: $($rule.Actions)"
                Write-Host "  SCL: $($rule.SCL)"
                Write-Host "  Description: $($rule.Description)"
                Write-Host ""
            } else {
                Write-Host "Rule: $($rule.Name)" -ForegroundColor Yellow
                if ($rule.PSObject.Properties["Identity"]) {
                    Write-Host "   Identity: $($rule.Identity)" -ForegroundColor Yellow
                }
                Write-Host "  Domains/IPs: $($rule.SenderDomainIs -join ', ')"
                Write-Host "  Conditions: $($rule.Conditions | Out-String)"
                Write-Host "  Actions: $($rule.Actions | Out-String)"
                Write-Host "  SCL: $($rule.SetSCL)"
                Write-Host "  Description: $($rule.Description)"
                Write-Host ""
            }
        }
    }
    else {
        Write-Host "`nNo rules found for '$Lookup'." -ForegroundColor Red
    }
    Disconnect-ExchangeOnline -Confirm:$true
    exit
}

# Output Results
Write-Host "`n=== Enhanced Domain/IP Categorisation Report for Tenant: '$tenantName' ===`n" -ForegroundColor Cyan

# Print Excluded Domains/IPs at the top
if ($excludedDomains.Count -gt 0) {
    Write-Host "[Excluded Domains/IPs] ($($excludedDomains.Count)):" -ForegroundColor Cyan
    Write-Host (($excludedDomains | Sort-Object) -join ", ")
} else {
    Write-Host "[Excluded Domains/IPs] (0): None." -ForegroundColor Cyan
}

Write-Host "`n"

if ($approvedDomains.Count -gt 0) {
    Write-Host "[Approved Domains/IPs] ($($approvedDomains.Count)):" -ForegroundColor Green
    Write-Host (($approvedDomains | Sort-Object) -join ", ")
} else {
    Write-Host "[Approved Domains/IPs] (0): None identified." -ForegroundColor Green
}

Write-Host "`n"

if ($rejectedDomains.Count -gt 0) {
    Write-Host "[Rejected Domains/IPs] ($($rejectedDomains.Count)):" -ForegroundColor Red
    Write-Host (($rejectedDomains | Sort-Object) -join ", ")
} else {
    Write-Host "[Rejected Domains/IPs] (0): None identified." -ForegroundColor Red
}

Write-Host "`n"

if ($uncategorisedRules.Count -gt 0) {
    Write-Host "[Uncategorised Rules] ($($uncategorisedRules.Count)):" -ForegroundColor Yellow
    $uncategorisedRules | Format-List
} else {
    Write-Host "[Uncategorised Rules] (0): None." -ForegroundColor Yellow
}

# Only show detailed conflicting rules if -ShowConflicts is specified
if ($ShowConflicts -and $excludedDomains.Count -gt 0) {
    Write-Host "`n[Conflicting Domains/IPs Detailed Information]:" -ForegroundColor Magenta
    foreach ($conflict in $excludedDomains) {
        Write-Host "- Conflict: '$conflict'" -ForegroundColor Magenta
        if ($domainApprovalRules.ContainsKey($conflict)) {
            Write-Host "  Approved by rules:" -ForegroundColor Green
            foreach ($rule in $domainApprovalRules[$conflict]) {
                Write-Host "    - Rule: '$($rule.Name)'" -ForegroundColor Green
                if ($rule.PSObject.Properties["Identity"]) {
                    Write-Host "      Identity: $($rule.Identity)" -ForegroundColor Green
                }
                Write-Host "      Conditions: $($rule.Conditions | Out-String)" -ForegroundColor Green
                Write-Host "      Actions: $($rule.Actions | Out-String)" -ForegroundColor Green
                Write-Host "      Description: $($rule.Description)" -ForegroundColor Green
            }
        }
        if ($domainRejectionRules.ContainsKey($conflict)) {
            Write-Host "  Rejected by rules:" -ForegroundColor Red
            foreach ($rule in $domainRejectionRules[$conflict]) {
                Write-Host "    - Rule: '$($rule.Name)'" -ForegroundColor Red
                if ($rule.PSObject.Properties["Identity"]) {
                    Write-Host "      Identity: $($rule.Identity)" -ForegroundColor Red
                }
                Write-Host "      Conditions: $($rule.Conditions | Out-String)" -ForegroundColor Red
                Write-Host "      Actions: $($rule.Actions | Out-String)" -ForegroundColor Red
                Write-Host "      Description: $($rule.Description)" -ForegroundColor Red
            }
        }
    }
} elseif ($ShowConflicts) {
    Write-Host "`n[Conflicting Domains/IPs Detailed Information]: None detected." -ForegroundColor Magenta
}

# Optional File Outputs: Exclude conflicting (excluded) domains/IPs from file outputs
if ($oA) {
    $approvedDomains | Sort-Object | Out-File -FilePath $oA -Encoding utf8
}
if ($oR) {
    $rejectedDomains | Sort-Object | Out-File -FilePath $oR -Encoding utf8
}
if ($oU) {
    $uncategorisedRules | Export-Csv -Path $oU -NoTypeInformation -Encoding utf8
}
if ($oE) {
    $excludedDomains | Sort-Object | Out-File -FilePath $oE -Encoding utf8
}
