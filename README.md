\# Aya OSDCloud Deployment



This repository hosts Aya Healthcare’s OSDCloud automation assets.



\## Structure



| Folder | Purpose |

| ------- | -------- |

| `Scripts/` | PowerShell scripts and wrappers used during OSDCloud deployments |

| `Unattend/` | Windows Unattend and AutoUnattend templates |

| `Media/` | Packaged tools such as Lenovo Diagnostics or BurnInTest |

| `README.md` | This overview |



\## Typical Usage



In WinPE:



```powershell

Invoke-Expression (Invoke-RestMethod 'https://raw.githubusercontent.com/JustinSparksAya/OSDCloud/main/Scripts/Start-OSDCloudWrapper.ps1')



