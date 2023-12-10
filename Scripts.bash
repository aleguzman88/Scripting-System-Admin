#********************Scripting-System-Admin*********************
#*********Empowering System Administration through PowerShell***
#Welcome to "Scripting-System-Admin," your comprehensive guide to leveraging PowerShell scripts for efficient system administration. 
#Before diving into the scripts, ensure you have administrative privileges and necessary modules imported.
#Each section provides step-by-step instructions and explanations to guide you through the process.
#Let's empower your scripting journey!!!


# Get information about installed features
Get-WindowsFeature

# Get information about a specific feature
Get-WindowsFeature -Name AD-Domain-Services

# Get information about a specific role (e.g., DHCP Server)
Get-WindowsFeature -Name DHCP

# Get information about a specific feature on a remote server
Get-WindowsFeature -Name Web-Server -ComputerName RemoteServer

#Keep in mind that the Get-WindowsFeature cmdlet is used on Windows Server operating systems. If you are on a client version of Windows (e.g., Windows 10), you may use the Get-WindowsOptionalFeature cmdlet to query information about optional features.
#Always run PowerShell with administrative privileges (Run as Administrator) to perform operations related to features and roles on Windows Server.


# PS command for installation of ADDS 

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

#This command installs the Active Directory Domain Services feature and includes the management tools. Ensure that you run PowerShell with administrative privileges (Run as Administrator) to perform these tasks.
#If you're working with Windows Server 2012 R2 and later, you should use the Install-WindowsFeature cmdlet. For Windows Server 2012 R2 and later, the Install-WindowsFeature cmdlet is included for compatibility, but it's recommended to use the newer Install-WindowsFeature cmdlet.

Get-ADDomain
#With this command you can verify your Domain information.


#To Create an new OU  
# Import the Active Directory module (if not already imported)
Import-Module ActiveDirectory

# Create a new OU named "Ou_name" with protection from accidental deletion set to $false
New-ADOrganizationalUnit -Name "Ou_name" -ProtectedFromAccidentalDeletion $false
#The New-ADOrganizationalUnit cmdlet is used to create a new organizational unit (OU) in Active Directory. 
#The -ProtectedFromAccidentalDeletion parameter is used to specify whether the newly created OU should be protected from accidental deletion. 
#If you set it to $false, it means the OU is not protected from accidental deletion.


# Create a new global security group named "groupA" in the "Ou_name" OU
New-ADGroup -Name "AMG" -SamAccountName "groupA" -GroupScope Global -Path "OU=Ou_name,DC=domain_name,DC=ca"

# Create a new global security group named "groupB" in the "Ou_name" OU
New-ADGroup -Name "PMG" -SamAccountName "groupB" -GroupScope Global -Path "OU=Ou_name,DC=domain_name,DC=ca"
#These commands are useful for automating the creation of groups in Active Directory. 


Get-ADGroup -Filter * -SearchBase "OU=Ou_name,DC=domain_name,DC=ca"
#The Get-ADGroup cmdlet is used to retrieve information about Active Directory groups. 
#The command you provided aims to get a list of all groups within the specified organizational unit (OU). Let's break down the command:
#Get-ADGroup: This cmdlet retrieves information about Active Directory groups.
#-Filter *: Specifies that the filter should match all groups. Essentially, it retrieves all groups without any specific filtering criteria.
#-SearchBase "OU=Ou_name,DC=domain_name,DC=ca": Specifies the search base, indicating the location where the search for groups should occur.


# Create User1
New-ADUser -Name "Manuel" -SamAccountName "Manu" -UserPrincipalName "mguzman@manuel.ca" -GivenName "User" -Surname "One" -Path "OU=Ou_name,DC=domain_name,DC=ca" -AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force) -Enabled $true -PasswordNeverExpires $true
#New-ADUser: This cmdlet is used to create a new Active Directory user account.
#-Name "Manuel": Specifies the display name of the user, which is set to "Manuel."
#-SamAccountName "Manu": Specifies the Security Account Manager (SAM) account name for the user, set to "Manu."
#-UserPrincipalName "mguzman@manuel.ca": Specifies the User Principal Name (UPN) for the user, set to "mguzman@manuel.ca."
#-GivenName "User" and -Surname "One": Specify the first name and last name of the user, respectively.
#-Path "OU=Ou_name,DC=domain_name,DC=ca": Specifies the organizational unit (OU) where the user account should be created.
#-AccountPassword (ConvertTo-SecureString "Password123" -AsPlainText -Force): Sets the initial password for the user. The password is set to "Password123" in this case.
#-Enabled $true: Enables the user account.
#-PasswordNeverExpires $true: Ensures that the password for the user account never expires.


#Verify the user information / Users from especific OU
Get-ADUser -Filter * -SearchBase "OU=Ou_name,DC=domain_name,DC=ca"
Get-ADUser -Filter {Name -eq "Manuel"} -SearchBase "OU=Ou_name,DC=domain_name,DC=ca"
#To find the user named "Manuel" using the Get-ADUser cmdlet with a filter and search base, you can use the following command:
#Get-ADUser: This cmdlet retrieves information about Active Directory user accounts.
#-Filter {Name -eq "Manuel"}: Specifies a filter to find users where the Name property is equal to "Manuel."
#-SearchBase "OU=Ou_name,DC=domain_name,DC=ca": Specifies the search base, indicating the location where the search for users should occur. In this case, it's the "Toronto" organizational unit (OU) within the "manuel.ca" domain.
#This command will return information about the user account named "Manuel" within the specified organizational unit.
#If there is a match, you should see details about the "Manuel" user account, including attributes like Name, SamAccountName, UserPrincipalName, and more.

# Add User to "groupA" group
Add-ADGroupMember -Identity "groupA" -Members "Manu"
#Add-ADGroupMember: This cmdlet is used to add members to an Active Directory group.
#-Identity "groupA": Specifies the identity of the group to which you want to add members, which is "groupA" in this case.
#-Members "Manu": Specifies the member (user) you want to add to the group. In this case, you are adding the user with the SAM account name "Manu" to the "groupA" group.
#This command will add the user "Manu" to the "groupA" group in Active Directory.



# To create and Share a directory
mkdir "C:\Share"

# Define variables
$ShareName = "MyShare"
$SharePath = "C:\Share"
$ShareDescription = "Description for MyShare"

# Create an SMB share
New-SmbShare -Name $ShareName -Path $SharePath -Description $ShareDescription -FullAccess "groupA"

# Grant full access permissions to the "groupA" group using icacls
icacls "C:\Share" /grant "groupA:(OI)(CI)F"
#Creates a directory at "C:\Share."
#Defines variables for the share name ($ShareName), share path ($SharePath), and share description ($ShareDescription).
#Uses New-SmbShare to create an SMB share named "MyShare" with the specified path, description, and full access granted to the "groupA" group.
#Uses icacls to grant full access permissions to the "groupA" group on the directory.


# Install DHCP Server feature
Install-WindowsFeature -Name DHCP -IncludeManagementTools
#to install a DHCP Server using PowerShell on a Windows Server, you can use the Install-WindowsFeature


#How to define Scope on Windows Server (options 1)
Add-DhcpServerv4Scope -Name "Win10" -StartRange 192.168.1.10 -EndRange 192.168.1.100 -SubnetMask 255.255.255.0 -Description "Scope for Windows 10 clients"

#How to define Scope on Windows Server (options 2)
# Define variables for the DHCP server and scope settings
$DhcpServer = "YourDhcpServerName"  # Replace with the actual DHCP server hostname or IP address
$ScopeName = "VLAN1"
$ScopeStartRange = "192.168.1.10"
$ScopeEndRange = "192.168.1.100"
$SubnetMask = "255.255.255.0"
$DefaultGateway = "192.168.1.1"
$DnsServers = "192.168.1.2", "192.168.1.3"  # Replace with your DNS server IP addresses
$LeaseDuration = "8.00:00:00"  # Lease duration of 8 days
# Create a new DHCP scope
Add-DhcpServerv4Scope -ComputerName $DhcpServer -Name $ScopeName -StartRange $ScopeStartRange -EndRange $ScopeEndRange -SubnetMask $SubnetMask -State Active
# Set scope options (Default Gateway, DNS Servers, Lease Duration)
Set-DhcpServerv4OptionValue -ComputerName $DhcpServer -ScopeId $ScopeName -OptionId 3 -Value $DefaultGateway
Set-DhcpServerv4OptionValue -ComputerName $DhcpServer -ScopeId $ScopeName -OptionId 6 -Value $DnsServers
Set-DhcpServerv4OptionValue -ComputerName $DhcpServer -ScopeId $ScopeName -OptionId 51 -Value $LeaseDuration


# Get information about all DHCP server scopes
Get-DhcpServerv4Scope 
#Authorize the server to run in an ADDS
Add-DhcpServerInDC  
#Ensure the DHCP Server lease IP address.
Get-DhcpServerv4Lease -scopeid "192.168.1.0"


# Install WDS Server role and management tools
Install-WindowsFeature -Name WDS -IncludeManagementTools
# Import the WDS module
Import-WdsBootImage -Path "D:\sources\install.wim" -NewImageName "Win10"  
# Add a new boot image for Windows 10
Import-WdsImage -ImageName "Install Image" -ImagePath "C:\ISO\install.wim" -ImageGroupId "YourImageGroup"
# Get the image name from the specified WIM file
Get-WindowsImage -ImagePath "D:\sources\install.wim" | Select-Object ImageName
#If you have multiple images within the WIM file, you might see a list of image names. 
#If you want information about a specific image, you can specify the image index using the -Index parameter. For example:
# Get information about the image with index 1 from the specified WIM file
Get-WindowsImage -ImagePath "D:\sources\install.wim" -Index 1 | Select-Object ImageName











