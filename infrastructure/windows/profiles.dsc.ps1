Configuration SecurityMasterBaseline {
  Import-DscResource -ModuleName PSDesiredStateConfiguration
  Import-DscResource -ModuleName ComputerManagementDsc
  Import-DscResource -ModuleName NetworkingDsc

  Node "localhost" {
    # BitLocker check
    Script BitLockerCheck {
      GetScript  = { @{ Result = (Get-BitLockerVolume -MountPoint C:).VolumeStatus } }
      TestScript = { (Get-BitLockerVolume -MountPoint C:).ProtectionStatus -eq "On" }
      SetScript  = { Write-Warning "[sec-master] BitLocker is NOT enabled on C:" }
    }

    # Firewall default deny
    Firewall SMDefaultDeny {
      Name        = "SecurityMaster-DefaultDeny"
      DisplayName = "sec-master default-deny outbound"
      Direction   = "Outbound"
      Action      = "Block"
      Enabled     = "True"
    }

    # Sysmon service
    Service Sysmon {
      Name        = "Sysmon64"
      State       = "Running"
      StartupType = "Automatic"
    }

    # Windows Event Forwarding
    Service Wecsvc {
      Name        = "Wecsvc"
      State       = "Running"
      StartupType = "Automatic"
    }
  }
}

SecurityMasterBaseline -OutputPath "C:\ProgramData\SecurityMaster\DSC"
Start-DscConfiguration -Path "C:\ProgramData\SecurityMaster\DSC" -Wait -Verbose
