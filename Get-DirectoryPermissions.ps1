<#
.Synopsis
   Retrieves permissions of directories
.DESCRIPTION
   
.EXAMPLE
Retrieves only the permissions of the directories in the targeted folder
   Get-DirectoryPermissions -Path C:\Skripts
.EXAMPLE
Retrieves  the permissions of the directories in the targeted folder and subfolders
   Get-DirectoryPermissions -Path C:\Skripts -Recurce:$true
.INPUTS
   
.OUTPUTS

.NOTES
  Ti
.COMPONENT
   
.ROLE
  Permissions
.FUNCTIONALITY
   
#>
function Get-DirectoryPermissions {
    [CmdletBinding(DefaultParameterSetName = 'Parameter Set 1', 
        SupportsShouldProcess = $true, 
        PositionalBinding = $false,
        HelpUri = 'ti.novelnetworking.se/',
        ConfirmImpact = 'Medium')]
    [Alias()]
    [OutputType([String])]
    Param
    (
        # Path to folder
        [Parameter(Mandatory = $true, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            ValueFromRemainingArguments = $false, 
            Position = 0,
            ParameterSetName = 'Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias("P")] 
        $Path,

        [Parameter(Mandatory = $false, 
            ValueFromPipeline = $true,
            ValueFromPipelineByPropertyName = $true, 
            ValueFromRemainingArguments = $false, 
            Position = 1,
            ParameterSetName = 'Parameter Set 1')]
        [ValidateNotNull()]
        [ValidateNotNullOrEmpty()]
        [Alias("R")]
        [Switch]
        $Recurce = $false

    
    )

    Begin {

        $Directories = Get-ChildItem -Path $Path  -Recurse:$Recurce -Directory 

        $Acls = $Directories | Get-Acl

    }
    Process {

        $obj = @()

        foreach ($acl in $Acls) {
            
            $Path = $acl.PSPath -replace ("Microsoft.PowerShell.Core\\FileSystem::", "")

            $sddl = $acl.Sddl | ConvertFrom-SddlString

            $Permissions = $sddl.DiscretionaryAcl | ConvertFrom-String -Delimiter ":" -PropertyNames User, Permissions
            $USR = @()
            $Permissions | ForEach-Object {

            
                $PropsPer = @{ 
                    User       = $_.User
                    Permission = $_.Permissions
                }

                $USR += New-Object -TypeName PSobject -Property $PropsPer 

            }


            $Props = @{ 
                Path        = $Path
                Users       = $Permissions.User
                Permissions = $USR
            }

            $Obj += New-Object -TypeName PSobject -Property $Props 


        }#end foreach

    }
    End {

        $Obj
    }
}#End function DirectoryPermission



function Get-SubDirPermission {
[CmdletBinding(DefaultParameterSetName = 'Parameter Set 1', 
    SupportsShouldProcess = $true, 
    PositionalBinding = $false,
    HelpUri = 'ti.novelnetworking.se/',
    ConfirmImpact = 'Medium')]
param (
     # Path to root folder
     [Parameter(Mandatory = $false, 
     ValueFromPipeline = $true,
     ValueFromPipelineByPropertyName = $true, 
     ValueFromRemainingArguments = $false, 
     Position = 0,
     ParameterSetName = 'Parameter Set 1')]
 [ValidateNotNull()]
 [ValidateNotNullOrEmpty()]
 [Alias("RP")] 
 $RootPath

)

if ($RootPath -ne $true){
#Select root folder path
    Add-Type -AssemblyName System.Windows.Forms
    $FolderBrowser = New-Object System.Windows.Forms.FolderBrowserDialog  -Property @{ RootFolder = "MyComputer"}
    $null = $FolderBrowser.ShowDialog()
    $RootPath = "$($FolderBrowser.SelectedPath)"
} #End if 

 Write-Verbose "The selected Root Folder is $RootPath"

#Select subfolder path
$Grid = Get-DirectoryPermissions -Path $RootPath | Out-GridView -PassThru
    Write-Verbose "The selected subfolder is $Grid"

    if ($Grid.count -gt 1) {
    Write-Error "To many directories selected"
        break

    }
#Retrieve subfolder permission
$Perm = Get-DirectoryPermissions -Path $RootPath | Where-Object { $_.Path -eq "$($Grid.path)"  } 

$Perm.permissions | ForEach-Object {$_ | Select-Object @{name="Path";e={$($Grid.path)}},User,Permission} 



}#End function SubDirPermission



Function Get-UserPermissionsfromDir {
    param(
    [Parameter(Mandatory = $true, 
                ValueFromPipeline = $true,
                ValueFromPipelineByPropertyName = $true, 
                ValueFromRemainingArguments = $false, 
                Position = 0,
                ParameterSetName = 'Parameter Set 1')]
                $Path,
                $Recurce = $false
                )
    
    If (Get-Module -Name ActiveDirectory -ListAvailable) {
    
    
        $Perm = Get-DirectoryPermissions -Path $path  $Recurce
    
        $obj =  @()
        
        
        foreach ($path in $perm) {
        $users = $path.permissions.user  -match "^$env:USERDOMAIN\\" -replace '^.*\\'
        
            foreach ($user in $users) {
        
            $ADUser = Get-ADUser -Filter {SamAccountName -eq $user}
            
            if ($ADUser -ne $null) {
        
                    $Props = [ordered]@{
                              Path = $path.path
                              SamAccountName = $ADUser.SamAccountName
                              GivenName = $ADUser.GivenName
                              Permissions = ($path.Permissions | where {$_.user -like "*$user*" }).permission
        
        
                              }
        
                $obj += New-Object -TypeName psobject -Property $Props
        
                } #end if User n
        
            }#End Foreach User
        
        }#End foreach Path
    
          
          if ($obj) {$obj
          
                    }
          else { Write-Information -MessageData "No domain users have permission on this folder" -InformationAction Continue}
          
    
      }#End if module
      else {
      Write-Information "ActiveDirectory Module is not installed(RSAT-AD-Tools )" -InformationAction Continue
      
      }
    
    }#end Function