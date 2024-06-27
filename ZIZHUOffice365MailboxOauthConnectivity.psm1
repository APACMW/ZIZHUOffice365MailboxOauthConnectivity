<#

    # Connect to ZIZHUOffice365MailboxOauthConnectivity via user sign-in
    $clientID = '06087bc1-286d-47f5-b487-5f0b15a0180d';
    $tenantId = 'cff343b2-f0ff-416a-802b-28595997daa2';
    $redirectUri='https://localhost';
    $loginHint = 'freeman@vjqg8.onmicrosoft.com';    
    Connect-Office365MailboxOauthConnectivity -tenantID $tenantId -clientID $clientID -loginHint $loginHint -redirectUri $redirectUri;

    # Connect to ZIZHUOffice365MailboxOauthConnectivity via user sign-in
    $clientID = '7bc50456-263a-475d-9fd3-58a50e4e8cf8';
    $tenantId = 'cff343b2-f0ff-416a-802b-28595997daa2';
    $clientsecret='';
    $targetMailbox = 'freeman@vjqg8.onmicrosoft.com';    
    Connect-Office365MailboxOauthConnectivity -tenantID $tenantId -clientID $clientID -clientsecret $clientsecret -targetMailbox $targetMailbox;
#>
enum MailProtocol {
    SMTP    
    IMAP
    POP3
}
[string]$script:tenantID = $null;
[string]$script:clientId = $null;
[string]$script:clientsecret = $null;
[string]$script:redirectUri = $null;
[string]$script:loginHint = $null;
[X509Certificate]$script:clientcertificate = $null;
$script:AuthResult = $null;
[string]$script:scope = "https://outlook.office365.com/.default"; 
[string]$script:office365Server = 'outlook.office365.com';
[string]$script:userMailbox = $null;
[string]$script:sASLXOAUTH2 = $null;
[int]$script:timeout = 8000;

function Show-VerboseMessage {    
    param(
        [Parameter(Mandatory = $true)][string]$message
    )    
    Write-Verbose "[$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))]: $message";
    return;
}
function Show-InformationalMessage {
    param(
        [Parameter(Mandatory = $true)][string]$message,
        [Parameter(Mandatory = $false)][System.ConsoleColor]$consoleColor = [System.ConsoleColor]::Gray
    )
    $defaultConsoleColor = $host.UI.RawUI.ForegroundColor;
    $host.UI.RawUI.ForegroundColor = $consoleColor;
    Write-Information -InformationAction Continue -MessageData "[$((Get-Date).ToUniversalTime().ToString("yyyy-MM-dd HH:mm:ss"))]: $message";
    $host.UI.RawUI.ForegroundColor = $defaultConsoleColor;
    return;
}
function Show-HttpErrorResponse {
    param(
        [Parameter(Mandatory = $true)][object]$httpErrorResponse
    )
    $httpError = $httpErrorResponse | Format-List | Out-String;
    Show-InformationalMessage -message $httpError -consoleColor Red;
}
function Show-LastErrorDetails {
    param(
        [Parameter(Mandatory = $false)]$lastError = $Error[0]
    )
    $lastError | Format-List -Property * -Force;
    $lastError.InvocationInfo | Format-List -Property *;
    $exception = $lastError.Exception;
    for ($depth = 0; $null -ne $exception; $depth++) {
        Show-InformationalMessage -message "$depth" * 80 -consoleColor Green;
        $exception | Format-List -Property * -Force;               
        $exception = $exception.InnerException;                
    }
}
function Show-AppPermissions {
    <#
    .SYNOPSIS
    Show the API permissions in the access token
    
    .DESCRIPTION
    Show the API permissions in the access token
    
    .PARAMETER jwtToken
    The accesstoken string
    
    .EXAMPLE
    Show-AppPermissions $accesstoken
    
    .NOTES
    Just show the API permissions. Not enforce to must have the specific permissions
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)][string]$jwtToken
    )
    $decodedToken = Read-JWTtoken -token $jwtToken;
    if ($null -ne $decodedToken -and $null -ne $decodedToken.scp) {
        $permissions = $decodedToken.scp;
    }
    elseif ($null -ne $decodedToken -and $null -ne $decodedToken.roles) {
        $permissions = $decodedToken.roles;
    }
    else {
        $permissions = $null;
    }
    Show-InformationalMessage -message "API permissions in the AccessToke: $($permissions)" -consoleColor Yellow;
}
function Read-JWTtoken {
    <#
    .SYNOPSIS
    Parse the access token/ID token based on https://datatracker.ietf.org/doc/html/rfc7519
    
    .DESCRIPTION
    Parse the access token/ID token based on https://datatracker.ietf.org/doc/html/rfc7519
    
    .PARAMETER token
    The accesstoken/ID token string
    
    .EXAMPLE
    Read-JWTtoken -token $jwtToken
    
    .NOTES
    https://datatracker.ietf.org/doc/html/rfc7519
    #>
    [cmdletbinding()]
    param(
        [Parameter(Mandatory = $true)][string]$token
    )
    # Validate Access and ID tokens per RFC 7519
    if (!$token.Contains(".") -or !$token.StartsWith("eyJ")) {
        Show-InformationalMessage -message "Invalid token" -consoleColor Red;
        return;
    }
    # Parse the Header
    $tokenheader = $token.Split(".")[0].Replace('-', '+').Replace('_', '/');
    # Fix padding as needed; keep adding "=" until string length modulus 4 reaches 0
    while ($tokenheader.Length % 4) {
        Show-VerboseMessage -message "Invalid length for a Base-64 char array or string, adding =";
        $tokenheader += "=";
    }
    Show-VerboseMessage -message "Base64 encoded (padded) header:"
    Show-VerboseMessage -message $tokenheader;

    # Convert from Base64 encoded string to PSObject
    Show-VerboseMessage -message "Decoded header:"
    $headers = [System.Text.Encoding]::ASCII.GetString([system.convert]::FromBase64String($tokenheader)) | ConvertFrom-Json | Format-List | Out-String;
    Show-VerboseMessage -message $headers;

    # Payload
    $tokenPayload = $token.Split(".")[1].Replace('-', '+').Replace('_', '/');
    # Fix padding as needed; keep adding "=" until string length modulus 4 reaches 0
    while ($tokenPayload.Length % 4) {
        Show-VerboseMessage -message "Invalid length for a Base-64 char array or string, adding =";
        $tokenPayload += "=";
    }
    Show-VerboseMessage -message "Base64 encoded (padded) payload:";
    Show-VerboseMessage -message $tokenPayload;

    # Convert to Byte array
    $tokenByteArray = [System.Convert]::FromBase64String($tokenPayload);
    # Convert to string array
    $tokenArray = [System.Text.Encoding]::ASCII.GetString($tokenByteArray);
    Show-VerboseMessage -message "Decoded array in JSON format:"
    Show-VerboseMessage -message $tokenArray

    # Convert from JSON to PSObject
    $tokenObj = $tokenArray | ConvertFrom-Json;
    Show-VerboseMessage -message "Decoded Payload:"
    Write-Output $tokenObj;
    return;
}

function Set-SASLXOAUTH2 {
    if ($null -eq $script:userMailbox) {
        Write-Error "Not supply the user mailbox. Exit." -ErrorAction Stop;
    }
    $saslXoauthstring = "user=" + $script:userMailbox + "$([char]0x01)auth=Bearer " + $accessToken + "$([char]0x01)$([char]0x01)";
    $saslXoauthbytes = [System.Text.Encoding]::ASCII.GetBytes($saslXoauthstring);
    $script:sASLXOAUTH2 = [Convert]::ToBase64String($saslXoauthbytes);
    Write-Verbose "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] SASL XOAUTH2 login string $script:sASLXOAUTH2";
}

function Connect-Office365MailboxOauthConnectivity {
    <#
    .SYNOPSIS
    Initilize the script varibles to prepare for calling APIs
    
    .DESCRIPTION
    Initilize the script varibles to prepare for calling APIs
    
    .PARAMETER tenantID
    tenant id
    
    .PARAMETER clientId
    Azure AD application Id
    
    .PARAMETER redirectUri
    The redirectUri used for implicit auth flow
    
    .PARAMETER loginHint
    The loginHint (user's UPN) used for implicit auth flow
    
    .PARAMETER clientsecret
    The clientsecret used for client credential auth flow
    
    .PARAMETER clientcertificate
    The clientcertificate used for client credential auth flow
    
    .PARAMETER office365SubscriptionPlanType
    Tenant type
    
    .EXAMPLE
    Connect-Office365MailboxOauthConnectivity -tenantID $tenantId -clientID $clientID -ClientSecret $clientSecret;
    
    .NOTES
    Read how to register the app in Azure AD: https://learn.microsoft.com/en-us/office/office-365-management-api/get-started-with-office-365-management-apis
    #>
    param (
        [Parameter(Mandatory = $true)][string]$tenantID,
        [Parameter(Mandatory = $true)][String]$clientId,
    
        [Parameter(Mandatory = $true, ParameterSetName = "authorizationcode")][String]$redirectUri,
        [Parameter(Mandatory = $true, ParameterSetName = "authorizationcode")][String]$loginHint,
        [Parameter(Mandatory = $false, ParameterSetName = "authorizationcode")][String]$sharedMailbox,

        [Parameter(Mandatory = $true, ParameterSetName = "clientcredentialsSecret")][String]$clientsecret,
        [Parameter(Mandatory = $true, ParameterSetName = "clientcredentialsCertificate")][String]$clientcertificate,

        [Parameter(Mandatory = $true, ParameterSetName = "clientcredentialsSecret")]
        [Parameter(Mandatory = $true, ParameterSetName = "clientcredentialsCertificate")][String]$targetMailbox        
    )

    Import-Module -name 'msal.ps';
    $msalModule = Get-Module msal.ps;
    #check for needed msal.ps module
    if ( $null -eq $msalModule) {
        Write-Error -message "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] MSAL.PS module not installed, please check it out here https://www.powershellgallery.com/packages/MSAL.PS/" -ErrorAction Stop;
    }

    $script:tenantID = $tenantID;
    $script:clientId = $clientId;
    $script:mailProtocol = $mailProtocol;

    if (-not [string]::IsNullOrWhiteSpace($clientsecret)) {
        $script:clientsecret = $clientsecret;
    }
    elseif ($null -ne $clientcertificate) {
        $script:clientcertificate = $clientcertificate;
    }
    elseif (-not [string]::IsNullOrWhiteSpace($redirectUri)) {
        $script:loginHint = $loginHint;
        $script:redirectUri = $redirectUri;
    }
    else {
        Write-Error "Not implement." -ErrorAction Stop;
    }
    Get-OauthToken;
    if ($null -eq $script:AuthResult) {
        Write-Error "The authentication failure. Can not do Connect-Office365MailboxOauthConnectivity. Please check your app registration in AAD." -ErrorAction Stop;
    }

    Show-AppPermissions $script:AuthResult.accesstoken;
    Show-InformationalMessage -message "The authentication succeeds. You can test the mail protocol $mailProtocol" -consoleColor Green;

    if ($PSBoundParameters.ContainsKey('targetMailbox') -and (-not [string]::IsNullOrWhiteSpace($targetMailbox))) { 
        $script:userMailbox = $targetMailbox 
    }
    elseif ($PSBoundParameters.ContainsKey('sharedMailbox') -and (-not [string]::IsNullOrWhiteSpace($sharedMailbox))) {
        $script:userMailbox = $sharedMailbox
    }
    elseif ($null -ne $script:AuthResult.Account -and $null -ne $script:AuthResult.Account.Username) {
        $script:userMailbox = $script:AuthResult.Account.Username;
    }
    else {
        Write-Error "Not supply the user mailbox. Exit." -ErrorAction Stop;        
    }
    
    switch ($mailProtocol) {
        SMTP {
            Test-SMTPXOAuth2Connectivity;
        }
        IMAP {
            Test-IMAPXOAuth2Connectivity;
        }
        POP3 {
            Test-POP3XOAuth2Connectivity;
        }
        default {
            Write-Error "Not implement." -ErrorAction Stop;
        }
    }
}

function Get-OauthToken {
    <#
    .SYNOPSIS
    Use the Msal.ps module to get the access token. Support client credential, Implicit auth flow
    
    .DESCRIPTION
    Use the Msal.ps module to get the access token. Support client credential, Implicit auth flow
    
    .NOTES
    Use the variables from script scope
    #>
    Show-VerboseMessage "Start to invoke Get-OauthToken";
    # If the access token is valid, then use an existing token
    $utcNow = (get-date).ToUniversalTime().AddMinutes(1);
    if ($null -ne $script:AuthResult -and ($utcNow -lt $script:AuthResult.ExpiresOn.UtcDateTime)) {
        Show-VerboseMessage "Current accesstoken is valid before $($script:AuthResult.ExpiresOn.UtcDateTime)";
        return;
    }
    # Implicit auth flow (delegated API permissions). Will try to get the access token silently. If fail, then interactive sign-in
    if (-not [string]::IsNullOrWhiteSpace($script:redirectUri)) {
        try {
            Show-VerboseMessage "Get-MsalToken via user sign-in";
            $script:AuthResult = Get-MsalToken -ClientId $script:clientId -TenantId $script:tenantID -Silent -LoginHint $script:loginHint -RedirectUri $script:redirectUri -Scopes $script:scope -AzureCloudInstance $script:AzureCloudInstance;
        }
        Catch [Microsoft.Identity.Client.MsalUiRequiredException] {
            $script:AuthResult = Get-MsalToken -ClientId $script:clientId -TenantId $script:tenantID -Interactive -LoginHint $script:loginHint -RedirectUri $script:redirectUri -Scopes $script:scope  -AzureCloudInstance $script:AzureCloudInstance;
        }
        Catch {
            Show-LastErrorDetails;
            Write-Error -Message "Can not get the access token, exit." -ErrorAction Stop;
        }
    }
    # Client credential auth flow. Can use the client secret or certificate
    else {
        try {
            if (-not [string]::IsNullOrWhiteSpace($script:clientsecret)) {
                Show-VerboseMessage "Get-MsalToken via client crendential auth flow";
                $securedclientSecret = ConvertTo-SecureString $script:clientsecret -AsPlainText -Force
                $script:AuthResult = Get-MsalToken -clientID $script:clientId -ClientSecret $securedclientSecret -tenantID $script:tenantID -Scopes $script:scope -AzureCloudInstance $script:AzureCloudInstance;
            }
            elseif ($null -ne $script:clientcertificate) {
                $script:AuthResult = Get-MsalToken -clientID $script:clientId -ClientCertificate $script:clientcertificate -tenantID $script:tenantID -Scopes $script:scope -AzureCloudInstance $script:AzureCloudInstance;
            }        
        }
        catch {
            Show-LastErrorDetails;
            Write-Error -Message "Can not get the access token, stop." -ErrorAction Stop;
        }
    }
    Show-VerboseMessage "Succeed to invoke Get-OauthToken";
}

function Test-SMTPXOAuth2Connectivity {   
    # connecting to Office 365 IMAP Service
    Show-InformationalMessage -message "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] Connect to Office 365 SMTP Service." -consoleColor DarkGreen;
    $smtpServer = $script:office365Server;
    $smtpPort = '587';
    try {
        # Create a TCP client and connect to the SMTP server
        $tcpClient = New-Object System.Net.Sockets.TcpClient($smtpServer, $smtpPort);
        $stream = $tcpClient.GetStream();
        $stream.ReadTimeout = $script:timeout;
        $stream.WriteTimeout = $script:timeout;  
        $streamWriter = new-object System.IO.StreamWriter($stream);
        $streamReader = new-object System.IO.StreamReader($stream);
        $streamWriter.AutoFlush = $true; 
        $sslStream = New-Object System.Net.Security.SslStream($stream)    
        $sslStream.ReadTimeout = $script:timeout
        $sslStream.WriteTimeout = $script:timeout        
        $response = $streamReader.ReadLine();
        Show-InformationalMessage "Server: $response" -consoleColor Yellow; 
        if (!$response.StartsWith("220")) {
            Write-Error "Error connecting to the SMTP Server" -ErrorAction Stop;
        }
        Show-InformationalMessage -message "Client: EHLO" -consoleColor Green; 
        $streamWriter.WriteLine("EHLO");
        $response = $streamReader.ReadLine();
        Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
        if (!$response.StartsWith("250")) {
            Write-Error "Error in EHLO Response" -ErrorAction Stop;
        }
        while ($streamReader.Peek() -ne -1) {
            $response = $streamReader.ReadLine();
            Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
        }
        Show-InformationalMessage -message "Client: STARTTLS" -consoleColor Green; 
        $streamWriter.WriteLine("STARTTLS");
        $response = $streamReader.ReadLine();
        Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
        $CheckCertRevocationStatus = $true;
        $sslStream.AuthenticateAsClient($smtpServer, $null, [System.Security.Authentication.SslProtocols]::Tls12, $CheckCertRevocationStatus);
        $SSLstreamReader = new-object System.IO.StreamReader($sslStream)
        $SSLstreamWriter = new-object System.IO.StreamWriter($sslStream)
        $SSLstreamWriter.AutoFlush = $true;
   
        $SSLstreamWriter.WriteLine("EHLO");
        $response = $SSLstreamReader.ReadLine();
        Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
        if (!$response.StartsWith("250")) {
            Write-Error "Error in EHLO Response" -ErrorAction Stop;
        }
        while ($streamReader.Peek() -ne -1) {
            $response = $SSLstreamReader.ReadLine();
            Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
        }
   
        Show-InformationalMessage -message "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] Authenticate using XOAuth2." -consoleColor DarkGreen;
        Show-InformationalMessage -message "Authenticate using XOAuth2" -consoleColor DarkGreen;
        # authenticate and check for results
        $command = "auth xoauth2"
        Show-InformationalMessage -message "Client: $command" -consoleColor Green; 
        $SSLstreamWriter.WriteLine($command);
        $response = $SSLstreamReader.ReadLine();
        Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
   
        $command = $script:sASLXOAUTH2;
        Show-InformationalMessage -message "Client: $command" -consoleColor Green; 
        $SSLstreamWriter.WriteLine($command);
        $response = $SSLstreamReader.ReadLine();
        Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;

        $SendingAddress = $script:userMailbox;
        $To = $script:userMailbox;
        if ($response.StartsWith("235 2.7.0 Authentication successful")) {
            $command = "MAIL FROM: <" + $SendingAddress + ">";
            Show-InformationalMessage -message "Client: $command" -consoleColor Green;
            $SSLstreamWriter.WriteLine($command) 
            $response = $SSLstreamReader.ReadLine();
            Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
            $command = "RCPT TO: <" + $To + ">";
            Show-InformationalMessage -message "Client: $command" -consoleColor Green;
            $SSLstreamWriter.WriteLine($command);
            $response = $SSLstreamReader.ReadLine();
            Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
            $command = "DATA";
            Show-InformationalMessage -message "Client: $command" -consoleColor Green;
            $SSLstreamWriter.WriteLine($command);
            $response = $SSLstreamReader.ReadLine()
            Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
            $SSLstreamWriter.WriteLine("Subject:test");
            $SSLstreamWriter.WriteLine([string]::Empty);
            $SSLstreamWriter.WriteLine("This is a test message");
            $SSLstreamWriter.WriteLine('.');
            $response = $SSLstreamReader.ReadLine();
            Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
            $command = "QUIT";
            Show-InformationalMessage -message "Client: $command" -consoleColor Green;
            $SSLstreamWriter.WriteLine($command);
            $response = $SSLstreamReader.ReadLine();
            Show-InformationalMessage -message "Server: $response" -consoleColor Yellow;
        }
        else {
            Show-InformationalMessage -message "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] ERROR during authentication $ResponseStr" -consoleColor Red;
        }

        @($SSLstreamWriter, $SSLstreamReader, $sslStream, $streamWriter, $streamReader, $stream, $tcpClient) | ForEach-Object {
            if ($null -ne $psitem) {
                $psitem.Close();
            }
        }
    }
    catch {
        Show-LastErrorDetails;
    }    
}

function Test-IMAPXOAuth2Connectivity {
    Set-SASLXOAUTH2;
    # connecting to Office 365 IMAP Service
    Show-InformationalMessage -message "Connect to Office 365 IMAP Service." -consoleColor DarkGreen;
    $ComputerName = $script:office365Server;
    $Port = '993';
    try {
        $TCPConnection = New-Object System.Net.Sockets.Tcpclient($($ComputerName), $Port);
        $TCPStream = $TCPConnection.GetStream();
        try {
            $SSLStream  = New-Object System.Net.Security.SslStream($TCPStream);
            $SSLStream.ReadTimeout = $script:timeout;
            $SSLStream.WriteTimeout = $script:timeout;
            $CheckCertRevocationStatus = $true;
            $SSLStream.AuthenticateAsClient($ComputerName,$null,[System.Security.Authentication.SslProtocols]::Tls12,$CheckCertRevocationStatus)
        }
        catch  {
            Show-LastErrorDetails;
            Write-Error "Ran into an exception while negotating SSL connection. Exiting." -ErrorAction Stop;
        }
    }
    catch  {
        Show-LastErrorDetails;
        Write-Error "Ran into an exception while opening TCP connection. Exiting." -ErrorAction Stop;
    }    

    # continue if connection was successfully established
    $SSLstreamReader = new-object System.IO.StreamReader($sslStream);
    $SSLstreamWriter = new-object System.IO.StreamWriter($sslStream);
    $SSLstreamWriter.AutoFlush = $true;
    $SSLstreamWriter.Newline = "`r`n";
    $SSLstreamReader.ReadLine();

    Show-InformationalMessage -message "Authenticate using XOAuth2." -consoleColor DarkGreen;
    # authenticate and check for results
    $command = "A01 AUTHENTICATE XOAUTH2 {0}" -f $POPIMAPLogin
    Write-Verbose "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] Executing command -- $command"
    $SSLstreamWriter.WriteLine($command) 
    #respose might take longer sometimes
    while (!$ResponseStr ) { 
        try { $ResponseStr = $SSLstreamReader.ReadLine() 
        } catch { 
            Show-LastErrorDetails;
        }
    }

    if ( $ResponseStr -like "*OK AUTHENTICATE completed.") 
    {
        $ResponseStr
        Write-Host "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] Getting mailbox folder list as authentication was successfull." -ForegroundColor DarkGreen
        $command = 'A01 LIST "" *'
        Write-Verbose "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] Executing command -- $command"
        $SSLstreamWriter.WriteLine($command) 

        $done = $false
        $str = $null
        while (!$done ) {
            $str = $SSLstreamReader.ReadLine()
            if ($str -like "* OK LIST completed.") { $str ; $done = $true } 
            elseif ($str -like "* BAD User is authenticated but not connected.") { $str; "Causing Error: IMAP protocol access to mailbox is disabled or permission not granted for client credential flow. Please enable IMAP protcol access or grant fullaccess to service principal."; $done = $true}
            else { $str }
        }

        Write-Host "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] Logout and cleanup sessions." -ForegroundColor DarkGreen
        $command = 'A01 Logout'
        Write-Verbose "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] Executing command -- $command"
        $SSLstreamWriter.WriteLine($command) 
        $SSLstreamReader.ReadLine()

    } else {
        Write-host "[$((Get-Date).ToString("yyyy/MM/dd HH:mm:ss.fff"))] ERROR during authentication $ResponseStr" -Foregroundcolor Red
    }

    # Session cleanup
    if ($SSLStream) {
        $SSLStream.Dispose()
    }
    if ($TCPStream) {
        $TCPStream.Dispose()
    }
    if ($TCPConnection) {
        $TCPConnection.Dispose()
    }    
}

function Test-POP3XOAuth2Connectivity {
	Write-Host "Connect to Office 365 POP3 Service." -ForegroundColor DarkGreen;
    $ComputerName = $script:office365Server;
    $Port = '995';
    try {
        $TCPConnection = New-Object System.Net.Sockets.Tcpclient($($ComputerName), $Port)
        $TCPStream = $TCPConnection.GetStream()
        try {
            $SSLStream  = New-Object System.Net.Security.SslStream($TCPStream)
            $SSLStream.ReadTimeout = 5000
            $SSLStream.WriteTimeout = 5000     
            $CheckCertRevocationStatus = $true
            $SSLStream.AuthenticateAsClient($ComputerName,$null,[System.Security.Authentication.SslProtocols]::Tls12,$CheckCertRevocationStatus)
        }
        catch  {
            Write-Host "Ran into an exception while negotating SSL connection. Exiting." -ForegroundColor Red
            $_.Exception.Message
            break
        }
    }
    catch  {
    Write-Host "Ran into an exception while opening TCP connection. Exiting." -ForegroundColor Red
    $_.Exception.Message
    break
    }    

    # continue if connection was successfully established
    $SSLstreamReader = new-object System.IO.StreamReader($sslStream)
    $SSLstreamWriter = new-object System.IO.StreamWriter($sslStream)
    $SSLstreamWriter.AutoFlush = $true
    $SSLstreamReader.ReadLine()

    Write-Host "Authenticate using XOAuth2." -ForegroundColor DarkGreen
    # authenticate and check for results
    #$command = "AUTH XOAUTH2 {0}" -f $POPIMAPLogin
	$command = "AUTH XOAUTH2"
    Write-Verbose "Executing command -- $command"
    $SSLstreamWriter.WriteLine($command) 
    #respose might take longer sometimes
    while (!$ResponseStr ) { 
        try { $ResponseStr = $SSLstreamReader.ReadLine() } catch { }
    }
#Write-Verbose $ResponseStr
    if ( $ResponseStr -like "*+*") 
    {
        $ResponseStr
	} else {
        Write-host "ERROR during authentication $ResponseStr" -Foregroundcolor Red
    }
	
		Write-Verbose "Passing XOAUTH2 formatted token"
		$SSLstreamWriter.WriteLine($POPIMAPLogin) 
		#respose might take longer sometimes
    while (!$ResponseStr2 ) { 
        try { $ResponseStr2 = $SSLstreamReader.ReadLine() } catch { }
    }
	
	Write-Verbose $ResponseStr2

    if ( $ResponseStr2 -like "*+OK*") 
    {
        $ResponseStr
        Write-Host "Getting list of messages as authentication was successfull." -ForegroundColor DarkGreen
        $command = 'LIST'
        Write-Verbose "Executing command -- $command"
        $SSLstreamWriter.WriteLine($command) 

        $done = $false
        $str = $null
        while (!$done ) {
            $str = $SSLstreamReader.ReadLine()
            if ($str -like "*.") { $str ; $done = $true } 
            elseif ($str -like "* BAD User is authenticated but not connected.") { $str; "Causing Error: POP3 protcol access to mailbox is disabled or permission not granted for client credential flow. Please enable POP3 protcol access or grant fullaccess to service principal."; $done = $true} 
            else { $str }
        }

        Write-Host "Logout and cleanup sessions." -ForegroundColor DarkGreen
        $command = 'QUIT'
        Write-Verbose "Executing command -- $command"
        $SSLstreamWriter.WriteLine($command) 
        $SSLstreamReader.ReadLine()

    } else {
        Write-host "ERROR during authentication $ResponseStr2" -Foregroundcolor Red
    }

    # Session cleanup
    if ($SSLStream) {
        $SSLStream.Dispose()
    }
    if ($TCPStream) {
        $TCPStream.Dispose()
    }
    if ($TCPConnection) {
        $TCPConnection.Dispose()
    }
}

Export-ModuleMember Connect-Office365MailboxOauthConnectivity, Test-SMTPXOAuth2Connectivity, Test-IMAPXOAuth2Connectivity, Test-POP3XOAuth2Connectivity;