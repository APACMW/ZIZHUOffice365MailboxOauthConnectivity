#
# Module manifest for module 'ZIZHUOffice365MailboxOauthConnectivity'
#
# Generated by: Lincky Lin, Paolo Lin and Qi Dong
#
# Generated on: 2/7/2024
#

@{

    # Script module or binary module file associated with this manifest.
    RootModule = 'ZIZHUOffice365MailboxOauthConnectivity.psm1'

    # Version number of this module.
    ModuleVersion        = '1.0'

    # Supported PSEditions
    CompatiblePSEditions = 'Desktop'

    # ID used to uniquely identify this module
    GUID                 = 'e23d4d82-3ffe-4713-812c-32de36b7d6fa'

    # Author of this module
    Author               = 'Lincky Lin<lincky.lin@microsoft.com>;Paolo Lin<paololin@microsoft.com>;Qi Dong<doqi@@microsoft.com>'

    # Company or vendor of this module
    CompanyName          = 'MSFT'

    # Copyright statement for this module
    Copyright            = '(c) Lincky Lin, Paolo Lin and Qi Dong. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'PowerShell module to test EXO mailbox Oauth connectivity for Admin or dev.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion    = '5.1'

    # Name of the PowerShell host required by this module
    # PowerShellHostName = ''

    # Minimum version of the PowerShell host required by this module
    # PowerShellHostVersion = ''

    # Minimum version of Microsoft .NET Framework required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # DotNetFrameworkVersion = ''

    # Minimum version of the common language runtime (CLR) required by this module. This prerequisite is valid for the PowerShell Desktop edition only.
    # ClrVersion = ''

    # Processor architecture (None, X86, Amd64) required by this module
    # ProcessorArchitecture = ''

    # Modules that must be imported into the global environment prior to importing this module
    RequiredModules      = @(
        @{
            ModuleName    = "MSAL.PS"; 
            ModuleVersion = "4.2.1.3"; 
            Guid          = "c765c957-c730-4520-9c36-6a522e35d60b"
        }
    )

    # Assemblies that must be loaded prior to importing this module
    # RequiredAssemblies = @()

    # Script files (.ps1) that are run in the caller's environment prior to importing this module.
    # ScriptsToProcess = @()

    # Type files (.ps1xml) to be loaded when importing this module
    # TypesToProcess = @()

    # Format files (.ps1xml) to be loaded when importing this module
    # FormatsToProcess = @()

    # Modules to import as nested modules of the module specified in RootModule/ModuleToProcess
    # NestedModules = @()

    # Functions to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no functions to export.
    FunctionsToExport    = 'Connect-Office365MailboxOauthConnectivity','Test-MailOauthConnectivity','Set-MailProtocol', 'Disconnect-Office365MailboxOauthConnectivity'

    # Cmdlets to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no cmdlets to export.
    CmdletsToExport      = @()

    # Variables to export from this module
    VariablesToExport    = '*'

    # Aliases to export from this module, for best performance, do not use wildcards and do not delete the entry, use an empty array if there are no aliases to export.
    AliasesToExport      = @()

    # DSC resources to export from this module
    # DscResourcesToExport = @()

    # List of all modules packaged with this module
    # ModuleList = @()

    # List of all files packaged with this module
    FileList             = @('.\ZIZHUOffice365MailboxOauthConnectivity.psd1', '.\ZIZHUOffice365MailboxOauthConnectivity.psm1')

    # Private data to pass to the module specified in RootModule/ModuleToProcess. This may also contain a PSData hashtable with additional module metadata used by PowerShell.
    PrivateData          = @{

        PSData = @{

            # Tags applied to this module. These help with module discovery in online galleries.
            Tags = @('Microsoft', 'EXO')

            # A URL to the license for this module.
            # LicenseUri = 'https://github.com/APACMW/ZIZHUOffice365MailboxOauthConnectivity/blob/main/LICENSE'

            # A URL to the main website for this project.
            # ProjectUri = 'https://github.com/APACMW/ZIZHUOffice365MailboxOauthConnectivity'

            # A URL to an icon representing this module.
            # IconUri = ''

            # ReleaseNotes of this module
            # ReleaseNotes = ''

            # Prerelease string of this module
            # Prerelease = ''

            # Flag to indicate whether the module requires explicit user acceptance for install/update/save
            # RequireLicenseAcceptance = $false

            # External dependent modules of this module
            # ExternalModuleDependencies = @()

        } # End of PSData hashtable

    } # End of PrivateData hashtable

    # HelpInfo URI of this module
    # HelpInfoURI = ''

    # Default prefix for commands exported from this module. Override the default prefix using Import-Module -Prefix.
    # DefaultCommandPrefix = ''
}
