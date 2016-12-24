<# 
@Author: Brandon C. Poole
@Version: 1.0
@Dependencies: Windows PowerShell 3.0
@Modified By: 
@Date of Last Change: 8/12/2016
@Changes: New Script
Purpose: To provide a PowerShell based toolset that allowed anaylist to gather security
related information from IBM's XForce Exchange via its API. These tools can be used to automate
research of an IPs or domains.
#>


<#####################################################
                        Functions
#######################################################>

function Set-MyAPISet {

   <#
    .SYNOPSIS
    Configures API key for CMDlets to use

    .DESCRIPTION
    Takes API key & password for API key and encrypts the key & password using the secure string method. 
    The encrypted strings are then stored in a file located in the path $([Environment]::GetFolderPath("MyDocuments"))\API with the file name being the 
    input of name function with a .key file extension. Inofrmation on setting XForce Exchange API key at https://api.xforce.ibmcloud.com/doc/#auth 


    .PARAMETER Key
    Takes the API key or Username for the key as input
   
    .PARAMETER Password
    Takes the API password/API key that corisponds to the API key/user

    .SWITCH XForce
    Specifies the key and password supplied is for IBM's XForce Exchange

    .EXAMPLE
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce

   #>
    [cmdletbinding()]
    Param (
        [Parameter (Mandatory=$True, HelpMessage = "Enter Username or the API key if it has a password associated with it.",Position = 1)][string]$Key,
        [Parameter (Mandatory=$True, HelpMessage = "API key or password if not given a username",Position = 2)][Alias('Pass')][string]$Password,
        [Parameter(ParameterSetName=’XForce’)][Switch]$XForce
    )

    BEGIN{

        #Creating API folder if it doesn't exist
        Write-Verbose -Message "Checking for $([Environment]::GetFolderPath("MyDocuments"))\api...." 
        if((Test-Path -Path $([Environment]::GetFolderPath("MyDocuments"))\API\) -eq $false){
            Write-Debug -Message "$([Environment]::GetFolderPath("MyDocuments"))\API\ not found."
            Write-Verbose -Message "Creating $([Environment]::GetFolderPath("MyDocuments"))\api...."
            New-Item -Path $([Environment]::GetFolderPath("MyDocuments"))\API -ItemType directory | ForEach-Object {$_.Attributes = "hidden"}
            Write-Debug -Message "Created $([Environment]::GetFolderPath("MyDocuments"))\API\"
        
        }#end of Test-Path if statement

        else{
            
            Write-Debug -Message "Found $([Environment]::GetFolderPath("MyDocuments"))\API\"

        }#End of else statement
    
    }#End of BEGIN block

    PROCESS{

        Write-Verbose -Message "Beginning PROCESS block"
        
        #Key & password encryption
        Write-Verbose -Message "Converting key to secure string."
        $secKey = $Key | ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
        Write-Debug -Message 'Key Encrypted and stored in $seckey'
        Write-Verbose -Message "Converting password to secure string."
        $secPass = $Password| ConvertTo-SecureString -AsPlainText -Force | ConvertFrom-SecureString
        Write-Debug -Message 'Key Encrypted and stored in $secPass'
         
        #xForce
        if($XForce){
            Write-Verbose -Message "Storing xForce Exchange API..."
            "$secKey///$secPass" | Out-File -FilePath "$([Environment]::GetFolderPath("MyDocuments"))\API\xforce.key"
            Write-Debug -Message "Wrote key & password to $([Environment]::GetFolderPath("MyDocuments"))\API\xforce.key."
 
        }#XForce    
    
    }#End of PROCESS Block

    END{}#End of END block

}#End of Set-XForceAPI                                                                                                                                                                          


function Get-MyAPIKey {

   <#
    .SYNOPSIS
    Retierves API key & password to be used with CMDlets

    .DESCRIPTION
    Pulls the encrypted API key & password from the .key file located at $([Environment]::GetFolderPath("MyDocuments"))\API and decrypts thems. 

    .SWITCH XForce
    Specifies the key and password supplied is for IBM's XForce Exchange

    .EXAMPLE
    Get-MyAPIKey -XForce
    api                                                          key                                                         
    ----                                                         ---                                                         
    e551d9e4-ff0a-ccca-41c21-c215893ae74bc                       544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4  
   #>

    [cmdletbinding()]

    Param (
        [Parameter(ParameterSetName=’XForce’)][Switch]$XForce
    )

    BEGIN{}#End of BEGIN block

    PROCESS{
    
        Write-Verbose -Message "Beginning PROCESS block"
            
        if($XForce){

            #Getting API key & Pass
            Write-Verbose -Message "Starting process to retrieve XForce key from $([Environment]::GetFolderPath("MyDocuments"))\api\xforce.key"

            try{
            
                $data = Get-Content -Path "$([Environment]::GetFolderPath("MyDocuments"))\api\xforce.key" -ErrorAction Stop
                Write-Debug -Message "Content from $([Environment]::GetFolderPath("MyDocuments"))\api\xforce.key has been retieved"

            } catch{
            
                 Write-Verbose -Message "$([Environment]::GetFolderPath("MyDocuments"))\api\xforce.key not found"
                 Write-Debug -Message "$([Environment]::GetFolderPath("MyDocuments"))\api\xforce.key not found"
                 Write-Error -Message "$([Environment]::GetFolderPath("MyDocuments"))\api\xforce.key not found. Please run Set-MyAPISet -XForce to set API key."

            }
          
        }#XForce

        #Parsing Key & Password
        Write-Verbose -Message "Parsing data..."
        $key = $data.Split("///")[0] | ConvertTo-SecureString
        Write-Debug -Message "Key has been parsed & stored: $key"
        $pass = $data.Split("///")[3] | ConvertTo-SecureString
        Write-Debug -Message "Password has been parsed & stored: $pass"

        #Decrypting key & pass
        Write-Verbose -Message "Decrypting the key & password..."
        $bstrKey = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($key)
        $bstrPass = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($pass)
        $key = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrKey)
        Write-Debug -Message "Key has been decrypted and stored: $key"
        $pass = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstrPass)
        Write-Debug -Message "Password has been decrypted and stored: $pass"
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrKey)
        [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstrPass)

        #Creating Object
        $apiCred = [ordered]@{
            
            'api' = $key
            'pass' = $pass
        
        }

        $apiCred = New-Object -TypeName psobject -Property $apiCred
        Write-Debug -Message 'Created API object $apiCred'
        Write-Output -InputObject $apiCred 
    
    }#End of Process Block

    END{}#End of END block

}#End of Get-MyAPIKey


function New-APIAuthHeader{

   <#
    .SYNOPSIS
    Creates authorization header for API calls

    .DESCRIPTION
    Takes API key & password amd creates a base64 encode authorization header for API request

    .PARAMETER Key
    Takes the API key as input
   
    .PARAMETER Password
    Takes the API password that corisponds to the API key

    .EXAMPLE
    New-APIAuthHeader -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4

     Name                           Value                                                                                       
     ----                           -----                                                                                       
    Authorization             Basic ZTU1MWQ5ZTQtZmYwYS1jY2NhLTQxYzIxLWMyMTU4OTNhZTc0YmM6NTQ0YTQyYjFjLTBlNGEtM...
   #>


   [cmdletbinding()]
    Param (
        [Parameter (Mandatory=$True, HelpMessage = "Username or API key if not given a username",Position = 1)][string]$Key,
        [Parameter (Mandatory=$True, HelpMessage = "Password or API key if not given a password",Position = 2)][Alias('Pass')][string]$Password

    )

    BEGIN{}#End of BEGIN block

    PROCESS{
    
        #Magic stuff
        $pair = "$Key" + ":" + "$Password"
        Write-Verbose -Message "Encoding pair to Base64..."
        $encoded = "Basic " + "$([System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes($pair)))"
        Write-Debug -Message "Key pair encoded in base64 & tagged: $encoded"
        $header = @{Authorization = $encoded}
        Write-Output -InputObject $header

    
    }#End of PROCESS block

    END{}#End of END block


}#End of New-APIAuthHeader


function Get-XFPassiveDNS {

   <#
    .SYNOPSIS
    Gets Passive DNS info from xForce Exchange

    .DESCRIPTION
    Makes an API call to xForce Exchange using the API key & retreives passive DNS info for a given IPv4, IPv6 address or domain

    .PARAMETER IP
    Takes valid IPv4 or IPv6 address as input
   
    .PARAMETER Domain
    Takes FQDN as input

    .SWITCH Clipboard
    Copies all output from this function to your clipboard

    .EXAMPLE
    Get-XFPassiveDNS -IP 8.8.8.8 | Select-Object -First 2


    value      : loveisthemessage.it
    type       : url
    recordType : A
    last       : 2016-08-04T14:17:00Z
    first      : 2015-10-02T21:59:00Z

    value      : otsklada.ru
    type       : url
    recordType : A
    last       : 2016-08-04T11:54:00Z
    first      : 2015-08-01T16:26:00Z

    .EXAMPLE
    Get-XFPassiveDNS -IP 2001:4860:4860::8888 | Select-Object -First 1


    value      : chisholmlumber.com
    type       : url
    recordType : A
    last       : 2016-07-31T05:40:00Z
    first      : 2015-08-19T16:03:00Z

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>

   [cmdletbinding()]
    Param (
        [ValidatePattern("(\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")]
        [Parameter(ParameterSetName=’IP’, HelpMessage = "Enter a valid IPv4 or IPv6 address.",Position = 1)][Alias('IPv6','IPv4')][string]$IP,
        [Parameter(ParameterSetName=’Domain’, HelpMessage = "Enter a FQDN.")][Alias('FQDN','Host')][string]$Domain,
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )

    
    
    BEGIN{

        #Getting xForce Key
        try{

            $coun = $true
            Write-Verbose -Message "Retrieving API key for XForce."
            $myKey = Get-MyAPIKey -XForce

            #Building Header for XForce
            Write-Verbose -Message "Building authenication header."
            $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
            $API_URI = "https://api.xforce.ibmcloud.com/resolve"

        } catch{
            Write-Debug -Message "Moving to Catch statement" 
            $coun = $false
        
        }#End of Try-Catch block

    }#End of BEGIN block

    PROCESS{

        if ($coun = $true){

             #API call
             Write-Verbose -Message "Requesting data from IBM XForce"

            try{
            
                $proceed  = $true
                if($Domain -ne ""){

                    $pDNS = $(Invoke-RestMethod -Uri "$API_URI/$Domain" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI/$Domain : $pDNS"
                    Write-Verbose -Message "Parsing data..."
                    $pDNS = $pDNS.Passive.Records
                    Write-Debug -Message "API data has been parsed: $pDNS"
                    $srch = $Domain

                } else{

                    $pDNS = $(Invoke-RestMethod -Uri "https://api.xforce.ibmcloud.com/resolve/$IP" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI/$IP : $pDNS"
                    Write-Verbose -Message "Parsing data..."
                    $pDNS = $pDNS.Passive.Records
                    Write-Debug -Message "API data has been parsed: $pDNS"
                    $srch = $IP
    
                }#End of if-else statment
           
            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed) {
        
                #Clipboard Switch
                if($Clipboard){
        
                    Write-Verbose -Message "Copying data to clipboard."
                    $pDNS | clip
    
                }#End of Clipboard IF

                Return $pDNS

            }#End of proceed if

        }#End of If Statment
    }#End of PROCESS block

    END{}#End of END block


}#End of Get-XFPassiveDNS


function Get-XFReverseDNS {

   <#
    .SYNOPSIS
    Gets reverse DNS info from xForce Exchange

    .DESCRIPTION
    Makes an API call to xForce Exchange using the API key & retreives reverse DNS info for a given IPv4, IPv6 address or domain

    .PARAMETER IP
    Takes valid IPv4 or IPv6 address as input
   
    .PARAMETER Domain
    Takes FQDN as input

    .SWITCH Clipboard
    Copies all output from this function to your clipboard

    .EXAMPLE
    Get-XFReverseDNS -IP 8.8.8.8
    google-public-dns-a.google.com

    .EXAMPLE
    Get-XFReverseDNS -ip 2001:4860:4860::8888
    google-public-dns-a.google.com

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>

   [cmdletbinding()]
    Param (
        [ValidatePattern("(\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")]
        [Parameter(ParameterSetName=’IP’, HelpMessage = "Enter a valid IPv4 or IPv6 address.",Position = 1)][Alias('IPv6','IPv4')][string]$IP,
        [Parameter(ParameterSetName=’Domain’, HelpMessage = "Enter a FQDN.")][Alias('FQDN','Host')][string]$Domain,
        [Alias('CC','CB','Clip')][Switch]$Clipboard
    )

    BEGIN{
    
        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI = "https://api.xforce.ibmcloud.com/resolve"
            
            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block

    }#End of BEGIN block

    PROCESS{
        
        if ($coun = $true){

            #API call
            Write-Verbose -Message "Requesting data from IBM XForce"
        
            try{
        
                    $proceed  = $true
                    if($Domain -ne ""){
            
                        $reverseDNS = $(Invoke-RestMethod -Uri "$API_URI/$domain" -Method: Get -Headers $head)
                        Write-Debug -Message "Queried $API_URI/$domain : $reverseDNS"
                        $rDNSA =  $reverseDNS.A
                        $rDNSAAAA =  $reverseDNS.AAAA
                        $rDNSMX = $reverseDNS.mx.exchange
                        $rDNS = [Ordered]@{
    
                            'A_RECORD' = $rDNSA
                            'AAAA_RECORD' = $rDNSAAAA
                            'MX_RECORD' = $rDNSMX 
    
                        }#End of $rDNS hash table 

                        Write-Verbose -Message "Parsing data..."
                        $rDNS = New-Object -TypeName PSObject -ArgumentList $rDNS
                        Write-Debug -Message "API data has been parsed: $rDNS"
                        $srch = $domain
                    } else {
    
                        $rDNS = $(Invoke-RestMethod -Uri "$API_URI/$IP" -Method: Get -Headers $head)
                        Write-Debug -Message "Queried $API_URI/$IP : $rDNS"
                        Write-Verbose -Message "Parsing data..."
                        $rDNS = $rDNS.RDNS
                        Write-Debug -Message "API data has been parsed: $rDNS"
                        $srch = $IP
    
                } #End If-Else Statment

        
            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){
                #Clipboard switch
                if($Clipboard){
    
                    $rDNS | clip
    
                }#End of Clipboard IF

                Write-Output $rDNS

            }#End of Proceed if
        }#End of If statement
    }#End of PROCESS block

    END{}#End of END block

}#End of Get-XFReverseDNS


function Get-XFReport {

   <#
    .SYNOPSIS
    Gets xForce report information for a inputed IP or domain

    .DESCRIPTION
    Makes an API call to xForce Exchange using the API key and returns a report/score 
    for the inputed IP or domain 

    .PARAMETER IP
    Takes valid IPv4 or IPv6 address as input
   
    .PARAMETER Domain
    Takes FQDN as input

    .SWITCH Clipboard
    Copies all output from this function to your clipboard

    .EXAMPLE
    Get-XFReport -IP 8.8.8.8

    Name                           Value                                                                                       
    ----                           -----                                                                                       
    IP                             8.8.8.8                                                                                     
    Geo_IP                         United States                                                                               
    IP_Score                       1                                                                                           
    Score_Reason                   Security analyst review                                                                     
    Score_Description              Based on the review of an X-Force security analyst.                                         
    Categories                                                                                                                 

   .EXAMPLE
   Get-XFReport -IP 2001:4860:4860::8888

    Name                           Value                                                                                       
    ----                           -----                                                                                       
    IP                             2001:4860:4860:0000:0000:0000:0000:8888                                                     
    Geo_IP                         United States                                                                               
    IP_Score                       1                                                                                           
    Score_Reason                   Content found on multihoster                                                                
    Score_Description              At least one of the websites that is hosted on this IP...
    Categories  
    
    .EXAMPLE
    Get-XFReport -Domain "google.com"

    Name                           Value                                                                                       
    ----                           -----                                                                                       
    URL                            google.com                                                                                  
    URL_Score                                                                                                                  
    Categories                     @{Search Engines / Web Catalogues / Portals=True}
    
    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce                                                                                                               
   #>

   [cmdletbinding()]
    Param (
        [ValidatePattern("(\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")]
        [Parameter(ParameterSetName=’IP’, HelpMessage = "Enter a valid IPv4 or IPv6 address.", Position = 1)][Alias('IPv6','IPv4')][string]$IP,
        [Parameter(ParameterSetName=’Domain’, HelpMessage = "Enter a FQDN.")][Alias('FQDN','Host')][string]$Domain,
        [Alias('CC','CB','Clip')][Switch]$Clipboard
    )


    BEGIN{
    
        Write-Debug -Message "Starting BEGIN block"
        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI_URL = "https://api.xforce.ibmcloud.com/url"
                $API_URI_IP = "https://api.xforce.ibmcloud.com/ipr"

            
            } catch{
                Write-Debug -Message "Moving to Catch statement" 
                $coun = $false
            
            }#End of Try-Catch block
    
    }#End of BEGIN block

    PROCESS{
            

        if ($coun = $true){

             #API call
             Write-Verbose -Message "Requesting data from IBM XForce"

                try{

                    Write-Debug -Message "Starting try statement"
                    $proceed  = $true
                    if($Domain -ne ""){

                        Write-Debug -Message "Domain provided: $Domain"

                        #Domain Report
                        $domR = $(Invoke-RestMethod -Uri "$API_URI_URL/$domain" -Method: Get -Headers $head)
                        Write-Debug -Message "Queried $API_URI_URL/$domain : $domR"
                        Write-Verbose -Message "Parsing data..."
                        $report = [Ordered] @{
                            'URL' = $domR.result.url
                            'URL_Score' = $domR.score
                            'Categories' = $domR.result.cats
                        }#End of hash table
                        $srch = $domain

                    } else{
    
                        Write-Debug -Message "IP provided: $IP"

                        #IP Report
                        $ipR = $(Invoke-RestMethod -Uri "$API_URI_IP/$IP" -Method: Get -Headers $head)
                        Write-Debug -Message "Queried $API_URI_IP/$IP : $ipR"
                        Write-Verbose -Message "Parsing data..."
                        $report = [Ordered] @{
                            'IP' = $ipR.ip
                            'Geo_IP' = $ipR.geo.country
                            'IP_Score' = $ipR.score
                            'Score_Reason' = $ipR.reason
                            'Score_Description' = $ipR.reasonDescription
                            'Categories' = $ipR.cats
                        }#End of hash table

                        $srch = $IP
   
                    }#End of Is-Else Statement
        
                } catch {
            
                    Write-Debug -Message "Starting catch statement"
                    $proceed  = $false
            
                    switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                    }#End of switch block
        
                }#End of try-catch block
        
                if($proceed){
                    $report = New-Object -TypeName PSObject -ArgumentList $report
                    Write-Debug -Message "API data has been parsed: $report"
    
                    #Clipboard switch
                    if($Clipboard){
    
                        $report | clip
    
                }#End of Clipboard IF

                Write-Output $report
        
             }#End of proceed if
        }#End of If Statement
    }#End of PROCESS block

    END{}#End of END block  
    
}#End of Get-XFReport;


function Get-XFIPRepHistory {

   <#
    .SYNOPSIS
    Gets xForce IP reputation history for IP

    .DESCRIPTION
    Makes an API call to xForce Exchange and returns a historical report of risk scores & reasons for the risk score
    based off a valid IPv4 or IPv6 address. The number of results displayed is based off of the Limit parameter or
    15 if no limit is specified. 

    .PARAMETER IP
    Takes valid IPv4 or IPv6 address as input

    .PARAMETER Limit
    Sets the number of results returned. Defaults to 15 if not specified.

    .SWITCH Clipboard
    Copies all output from this function to your clipboard

   .EXAMPLE
   Get-XFIPRepHistory  -IP 8.8.8.8 -Limit 2


        geo                  : @{country=United States; countrycode=US}
        ip                   : 8.8.8.8/32
        cats                 : 
        reason               : Security analyst review
        created              : 2012-05-08T08:23:00.000Z
        categoryDescriptions : 
        reasonDescription    : Based on the review of an X-Force security analyst.
        score                : 1

        geo                  : @{country=United States; countrycode=US}
        ip                   : 8.8.8.8/32
        cats                 : @{Spam=100}
        reason               : Security analyst review
        created              : 2012-05-08T08:21:00.000Z
        categoryDescriptions : @{Spam=This category lists IP addresses that were seen sending out spam.}
        reasonDescription    : Based on the review of an X-Force security analyst.
        score                : 10

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>

   [cmdletbinding()]
    Param (
        [ValidatePattern("(\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")]
        [Parameter(ParameterSetName=’IP’, HelpMessage = "Enter a valid IPv4 or IPv6 address.", Mandatory = $true,Position = 1)][Alias('IPv6','IPv4')][string]$IP,
        [Parameter(HelpMessage = "Enter the number of results to display",Position = 2)][int]$Limit = "15",
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )


    BEGIN{
        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI = "https://api.xforce.ibmcloud.com/ipr/history"
            
            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block    
    
    }#End of BEGIN block

    PROCESS{
    

        if ($coun = $true){

             #API call
             Write-Verbose -Message "Requesting data from IBM XForce"

            try{
            
                $proceed  = $true
                $ipH = $(Invoke-RestMethod -Uri "$API_URI/$IP" -Method: Get -Headers $head).history | Sort-Object -Property created  -Descending | Select-Object -First $Limit
                Write-Debug -Message "Queried $API_URI/$domain : $ipH"
                $srch = $IP
        
            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){

                #Clipboard switch
                if($Clipboard){
    
                    $ipH | clip
    
                }#End of Clipboard IF

                Write-Output $ipH
        
            }#End of proceed if
        }#End of If Statement
    }#End of PROCESS block
    
    END{}#End of END block

}#Get-XFIPRepHistory 


function Get-XFHostedMalware {

   <#
    .SYNOPSIS
    Retirves all malware assioated with IP on xForce Exchange

    .DESCRIPTION
    Retirves all malware assioated with IP on xForce Exchange & displays first 15 results or the number specified in the NumberOfResults parameter

    .PARAMETER IP
    Takes valid IPv4 or IPv6 address as input

    .PARAMETER Domain
    Takes FQDN as input

    .PARAMETER Limit
    Sets the number of results returned. Defaults to 15 if not specified.

    .SWITCH Clipboard
    Copies all output from this function to your clipboard 
   
   .EXAMPLE
   Get-XFIPHostedMalware -IP 190.60.222.157 -Limit 1


    type      : SPM
    md5       : E49011FEF98E32CBBE8E79D832521F04
    domain    : abbeyglassuk.com
    firstseen : 2016-07-20T01:45:00Z
    lastseen  : 2016-07-20T01:45:00Z
    ip        : 0x00000000000000000000ffffbe3cde9d
    count     : 1
    filepath  : 8744-005.zip
    uri       : file://8744-005.zip
    first     : 2016-07-20T01:45:00Z
    last      : 2016-07-20T01:45:00Z
    origin    : SPM
    family    : {Win.Trojan.Locky-30621, Spam Zero-Day}

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>
   
   [cmdletbinding()]
    Param (
        [ValidatePattern("(\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")]
        [Parameter(ParameterSetName=’IP’, HelpMessage = "Enter a valid IPv4 or IPv6 address.", Mandatory = $true,Position = 1)][Alias('IPv6','IPv4')][string]$IP,
        [Parameter(ParameterSetName=’Domain’, HelpMessage = "Enter a FQDN.")][Alias('FQDN','Host')][string]$Domain,
        [Parameter(HelpMessage = "Enter the number of results to display")][int]$Limit = "15",
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )


    BEGIN{
    
        #Getting xForce Key
        Write-Verbose -Message "Retrieving API key for XForce."

        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI_IP = "https://api.xforce.ibmcloud.com/ipr/malware"
                $API_URI_URL = "https://api.xforce.ibmcloud.com/url/malware"
            
            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block
    
    }#End of BEGIN block

    PROCESS{
    

        if ($coun = $true){

             #API call
             Write-Verbose -Message "Requesting data from IBM XForce"


            try{

                $proceed  = $true
                if($Domain -ne ""){
        
                    $mal = $(Invoke-RestMethod -Uri "$API_URI_URL/$Domain" -Method: Get -Headers $head).malware | Select-Object -First $Limit
                    Write-Debug "Queried $API_URI_IP/$Domain : $mal"
                    $srch = $Domain 

                } else {
        
                    $mal= $(Invoke-RestMethod -Uri "$API_URI_IP/$IP" -Method: Get -Headers $head).malware | Select-Object -First $Limit
                    Write-Debug "Queried $API_URI_IP/$IP : $mal" 
                    $srch = $IP
                    
                }#End of if-else

            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){
        
                if($Clipboard){
    
                    $mal | clip
    
                }#End of Clipboard IF

                Write-Output $mal
        
            }#End of proceed if

        }#End If statement

    }#End of PROCESS block

    END{}#End of END block

}#End of Get-XFHostedMalware


function Get-XFWhois {

   <#
    .SYNOPSIS
    Retirves WHOIS info from XForce 

    .DESCRIPTION
    Retirves the WHOIS record from IBM XForce for a given IPv4, IPv6 or domain name.

    .PARAMETER IP
    Takes valid IPv4 or IPv6 address as input
   
    .PARAMETER Domain
    Takes FQDN as input

    .SWITCH Clipboard
    Copies all output from this function to your clipboard

    .EXAMPLE
    Get-XFWhois -Domain google.com

    Name                           Value                                                                                       
    ----                           -----                                                                                       
    Created                        1997-09-15T07:00:00.000Z                                                                    
    Updated                        2015-06-12T17:38:52.000Z                                                                    
    Expires                        2020-09-14T04:00:00.000Z                                                                    
    Org                            Google Inc.                                                                                 
    Contact Name                   Dns Admin                                                                                   
    Contact Email                  dns-admin@google.com                                                                        
    Country                        United States                                                                               
    Registrar                      MarkMonitor, Inc.                                                                           

    .EXAMPLE
    Get-XFWhois -IP 129.42.38.1

    Name                           Value                                                                                       
    ----                           -----                                                                                       
    Created                        1987-07-29T00:00:00.000Z                                                                    
    Updated                        2015-10-20T00:00:00.000Z                                                                    
    Org                            IBM                                                                                         
    Contact Email                  ipreg@us.ibm.com                                                                            
    Country                        United States                                                                               
    RIR                            Administered by ARIN         

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>
   
   [cmdletbinding()]
    Param (
        [ValidatePattern("(\b(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b)|(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))")]
        [Parameter(ParameterSetName=’IP’, HelpMessage = "Enter a valid IPv4 or IPv6 address.",Position=1)][Alias('IPv6','IPv4')][string]$IP,
        [Parameter(ParameterSetName=’Domain’, HelpMessage = "Enter a FQDN.")][Alias('FQDN','Host')][string]$Domain,
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )



    BEGIN{
        
        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI = "https://api.xforce.ibmcloud.com/whois"
            
            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block

    }#End of BEGIN block

    PROCESS{
    

        if ($coun = $true){

             #API call
             Write-Verbose -Message "Requesting data from IBM XForce"

            try{
        
                $proceed  = $true
                if($Domain -ne ""){
        
                    $who = $(Invoke-RestMethod -Uri "$API_URI/$Domain" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI/$domain : $who"
                    Write-Verbose -Message "Parsing data..."

                    $whois = [ordered] @{
    
                        'Created' = $who.createdDate
                        'Updated' = $who.updatedDate
                        'Expires' = $who.expiresDate
                        'Org' = $who.contact.organization
                        'Contact Name' = $who.contact.name
                        'Contact Email' = $who.contactEmail
                        'Country' = $who.contact.country
                        'Registrar' = $who.registrarName

                    }#End of hash table

                    $srch = $Domain
                    Write-Debug -Message "API data parsed: $whois"        
        
                } else {
        
                    $who = $(Invoke-RestMethod -Uri "$API_URI/$IP" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI/$IP : $who"
                    Write-Verbose -Message "Parsing data..."

                    $whois = [ordered] @{

                        'Created' = $who.createdDate
                        'Updated' = $who.updatedDate
                        'Org'  = $who.contact.organization
                        'Contact Email' = $who.contactEmail
                        'Country' = $who.contact.country
                        'RIR' = $who.registrarName

                    }#End of hash table

                    $srch = $IP
                    Write-Debug -Message "API data parsed: $whois"

                }#End of if-else statment
        
            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){
        
                $whois = New-Object -TypeName PSObject -ArgumentList $whois
            
                #Clipboard switch
                if($Clipboard){
    
                    $whois | clip
    
                }#End of Clipboard IF

                Write-Output $whois

            }#End of proceed if
             
        }#End of If statement

    }#End of PROCESS block

    END{}#End of END block

}#End of Get-XFWhois


function Get-XFMalwareForMD5 {

   <#
    .SYNOPSIS
     Gets information from XForce about malware via a MD5 hash

    .DESCRIPTION
    Takes a MD5 hash and returns all information IBM XForce has
    for malware related to that hash

    .PARAMETER MD5
    Takes a valid MD5 hash as input

    .SWITCH Clipboard
    Copies all output from this function to your clipboard


    .EXAMPLE
    Get-XFMalwareForMD5 -MD5 "F2420BE21EAD02AE395EFC76DFFDB5D9" 


    type          : md5
    created       : 2016-07-29T19:00:00Z
    family        : {Spam Zero-Day}
    mimetype      : archive/zip
    md5           : 0xF2420BE21EAD02AE395EFC76DFFDB5D9
    origins       : @{external=; emails=; CnCServers=; downloadServers=; subjects=}
    familyMembers : @{Spam Zero-Day=}
    risk          : high        

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>

   [cmdletbinding()]
    Param (
        [ValidatePattern("^[a-f0-9]{32}$")]
        [Parameter( HelpMessage = "Enter a valid MD5 hash", Mandatory = $true, ValueFromPipeline = $true,Position=1)][Alias('Hash')][string]$MD5,
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )



    BEGIN{
        try{

            $coun = $true
            #Getting xForce Key
            Write-Verbose -Message "Retrieving API key for XForce."
            $myKey = Get-MyAPIKey -XForce

            #Building Header for XForce
            Write-Verbose -Message "Building authenication header."
            $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
            $API_URI = "https://api.xforce.ibmcloud.com/malware"
        
            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block

    }#End of BEGIN block

    PROCESS{
         if ($coun = $true){

            #API call
            Write-Verbose -Message "Requesting data from IBM XForce"

            try{
            
                $proceed  = $true
                $mal = $(Invoke-RestMethod -Uri "$API_URI/$MD5" -Method: Get -Headers $head)
                Write-Debug -Message "Queried $API_URI/$MD5 : $mal"
                $srch = $MD5

                } catch {
            
                    $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){
        
                Write-Verbose -Message "Parsing data..."
                $mal = $mal.malware
                Write-Debug -Message "API data parsed: $mal"
        
                if($Clipboard){
    
                    $mal | clip
    
                }#End of Clipboard IF

                Write-Output $mal
        
            }#End of if proceed statement

        }#End of If statement
    
    }#End of PROCESS block

    END{}#End of END block

}#End of Get-XFMalwareForMD5


function Get-XFMalwareFamily {

   <#
    .SYNOPSIS
     Pulls all malware information for a particular family from IBM XForce

    .DESCRIPTION
    Pulls all malware information for a particular family from IBM XForce

    .PARAMETER Family
    Takes a valid MD5 hash as input

    .SWITCH Clipboard
    Copies all output from this function to your clipboard


    .EXAMPLE
     Get-XFMalwareFamily -Family tsunami


    firstseen : 2012-01-27T00:19:00Z
    malware   : {@{type=md5; created=2014-10-20T23:19:00Z; family=System.Object[]; md5=474B9CCF5AB9D72CA8A333889BBB34F0}, 
                @{type=md5; created=2014-09-25T23:20:00Z; family=System.Object[]; md5=81414A962240B525A5764B587E71F322}, 
                @{type=md5; created=2014-05-22T11:17:00Z; family=System.Object[]; md5=834E90F01DFD01D39824F86D43FDF620}, 
                @{type=md5; created=2014-03-11T21:49:00Z; family=System.Object[]; md5=7980B6E54EB9088791DE2785B289122F}...}
    family    : {tsunami}
    lastseen  : 2014-10-20T23:19:00Z
    count     : 61     

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>

   [cmdletbinding()]
    Param (
        [Parameter( HelpMessage = "Enter a valid malware family", Mandatory = $true, ValueFromPipeline = $true,Position=1)][string]$Family,
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )

    BEGIN{

        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI = "https://api.xforce.ibmcloud.com/malware/familyext"
            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block

    }#End of BEGIN block

    PROCESS{

        if ($coun = $true){
           
            #API call
            Write-Verbose -Message "Requesting data from IBM XForce"

            Try{
            
                $proceed  = $true
                $malFam = $(Invoke-RestMethod -Uri "$API_URI/$Family" -Method: Get -Headers $head)
                Write-Debug -Message "Queried $API_URI/$Family : $malFam"
                $srch = $Family

            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){
        
                if($Clipboard){
    
                    $malFam | clip
    
                }#End of Clipboard IF

                Write-Output $malFam
        
            }#End of if proceed statement

        }#End of If statement 
    
    }#End of PROCESS block

    END{}#End of END block

}#End of Get-XFMalwareFamily


function Find-XFVulnerabilities {

   <#
    .SYNOPSIS
     Finds vulnerabilities given a platform, CVE, Microsoft Security Bulletin ID, US-CERT VU# or a given term

    .DESCRIPTION
     Finds vulnerabilities given a platform, CVE, Microsoft Security Bulletin ID, US-CERT VU#, BID, RHSA or
     search term 

    .PARAMETER Term
    A term that is somewhere in the vulnerability synopsis

    .PARAMETER STDCode
    Takes a CVE, BID, US-CERT VU# and RHSA code as input

    .PARAMETER MSBulletinID
    Takes a Microsoft Security Bulletin ID as input

    .PARAMETER PlatformsAffected
    Takes a appliance, OS or application as input

    .PARAMETER Limit
    Sets the number of results returned. Defaults to 15 if not specified.

    .SWITCH Clipboard
    Copies all output from this function to your clipboard


    .EXAMPLE
    Find-XFVulnerabilities -STDCode "CVE-2016-4170"

    type               : vulnerability
    xfdbid             : 115868
    updateid           : 18039
    updated            : True
    variant            : single
    title              : Adobe Experience Manager cross-site scripting
    description        : Adobe Experience Manager is vulnerable to cross-site scripting, caused by improper validation of 
                         user-supplied input. A remote attacker could exploit this vulnerability using a specially-crafted URL 
                         to execute script in a victim's Web browser within the security context of the hosting Web site, once 
                         the URL is clicked. An attacker could use this vulnerability to steal the victim's cookie-based 
                         authentication credentials.
    risk_level         : 6.1
    cvss               : @{version=3.0; privilegesrequired=None; userinteraction=Required; scope=Changed; 
                         access_vector=Network; access_complexity=Low; confidentiality_impact=Low; integrity_impact=Low; 
                         availability_impact=None; remediation_level=Official Fix}
    temporal_score     : 5.3
    remedy             : Refer to Adobe Security Bulletin APSB16-27 for patch, upgrade or suggested workaround information. See 
                         References.
    remedy_fmt         : <P>Refer to Adobe Security Bulletin APSB16-27 for patch, upgrade or suggested workaround information. 
                         See References.</P>
    reported           : 2016-08-09T00:00:00Z
    tagname            : adobe-experience-cve20164170-xss
    stdcode            : {CVE-2016-4170}
    platforms_affected : {Adobe Experience Manager 6.1.0, Adobe Experience Manager 6.0.0, Adobe Experience Manager 5.6.1, Adobe 
                         Experience Manager 6.2.0}
    exploitability     : Unproven
    consequences       : Cross-Site Scripting
    references         : {@{link_target=https://helpx.adobe.com/security/products/experience-manager/apsb16-27.html; 
                         link_name=Adobe Security Bulletin APSB16-27; description=Security hotfixes available for Adobe 
                         Experience Manager}, @{link_target=http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-4170; 
                         link_name=CVE-2016-4170; description=Cross-site scripting (XSS) vulnerability in Adobe Experience 
                         Manager 5.6.1, 6.0, 6.1, and 6.2 allows remote attackers to inject arbitrary web script or HTML via 
                         unspecified vectors.}}
    signatures         : {@{coverage=Cross_Site_Scripting; coverage_date=2008-11-11T00:00:00Z}}
    report_confidence  : Confirmed
    uuid               : e490e87161201b9af4dc881881040907

    .EXAMPLE
    Find-XFVulnerabilities -MSBulletinID "MS15-065" -Limit 2

    risk_level : 9.3
    title      : Microsoft Internet Explorer code execution
    xfdbid     : 103360
    stdcode    : {CVE-2015-1737}
    reference  : MS15065
    reported   : 2015-06-09T00:00:00Z

    risk_level : 5.8
    title      : Microsoft Internet Explorer privilege escalation
    xfdbid     : 103366
    stdcode    : {CVE-2015-1743, BID-74996}
    reference  : MS15065
    reported   : 2015-06-09T00:00:00Z

    .EXAMPLE
    Find-XFVulnerabilities -PlatformsAffected "Cisco ASA" -Limit 1

    type               : vulnerability
    xfdbid             : 112535
    updateid           : 12724
    inserted           : True
    variant            : single
    title              : Cisco Adaptive Security Appliance DHCPv6 denial of service
    description        : Cisco Adaptive Security Appliance (ASA) Software is vulnerable to a denial of service, caused by an 
                         error in the DHCPv6 relay feature. By sending specially crafted DHCPv8 packets, a remote attacker 
                         could exploit this vlnerability to cause a denial of service.
    risk_level         : 7.5
    cvss               : @{version=3.0; privilegesrequired=None; userinteraction=None; scope=Unchanged; access_vector=Network; 
                         access_complexity=Low; confidentiality_impact=None; integrity_impact=None; availability_impact=High; 
                         remediation_level=Official Fix}
    temporal_score     : 6.5
    remedy             : Refer to Cisco Security Advisory cisco-sa-20160420-asa-dhcpv6 for patch, upgrade or suggested 
                         workaround information. See References.
    remedy_fmt         : <P>Refer to Cisco Security Advisory cisco-sa-20160420-asa-dhcpv6 for patch, upgrade or suggested 
                         workaround information. See References.</P>
    reported           : 2016-04-20T00:00:00Z
    tagname            : cisco-asa-cve20161367-dos
    stdcode            : {CVE-2016-1367}
    platforms_affected : {Cisco ASA 5500}
    exploitability     : Unproven
    consequences       : Denial of Service
    references         : {@{link_target=https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160420-
                         asa-dhcpv6; link_name=Cisco Security Advisory cisco-sa-20160420-asa-dhcpv6; description=Cisco Adaptive 
                         Security Appliance Software DHCPv6 Relay Denial of Service Vulnerability }, 
                         @{link_target=http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2016-1367; link_name=CVE-2016-1367; 
                         description=The DHCPv6 relay implementation in Cisco Adaptive Security Appliance (ASA) Software 9.4.1 
                         allows remote attackers to cause a denial of service (device reload) via crafted DHCPv6 packets, aka 
                         Bug ID CSCus23248.}}
    report_confidence  : Confirmed

    .EXAMPLE
    Find-XFVulnerabilities -Term "Network" -Limit 1

    type               : vulnerability
    xfdbid             : 115881
    updateid           : 18035
    inserted           : True
    variant            : single
    title              : Nagios Network Analyzer cross-site scripting
    description        : Nagios Network Analyzer is vulnerable to cross-site scripting, caused by improper validation of 
                         user-supplied input. A remote attacker could exploit this vulnerability to inject malicious script 
                         into a Web page which would be executed in a victim's Web browser within the security context of the 
                         hosting Web site, once the page is viewed. An attacker could use this vulnerability to steal the 
                         victim's cookie-based authentication credentials.
    risk_level         : 6.1
    cvss               : @{version=3.0; privilegesrequired=None; userinteraction=Required; scope=Changed; 
                         access_vector=Network; access_complexity=Low; confidentiality_impact=Low; integrity_impact=Low; 
                         availability_impact=None; remediation_level=Official Fix}
    temporal_score     : 5.8
    remedy             : Upgrade to the latest version of Nagios Network Analyzer (2.2.2 or later), available from the Nagios 
                         Web site. See References.
    remedy_fmt         : <P>Upgrade to the latest version of Nagios Network Analyzer (2.2.2 or later), available from the 
                         Nagios Web site. See References.</P>
    reported           : 2016-08-08T00:00:00Z
    tagname            : nagios-networkanalyzer-xss
    platforms_affected : {Nagios Network Analyzer 2.2.1}
    exploitability     : High
    consequences       : Cross-Site Scripting
    references         : {@{link_target=http://seclists.org/bugtraq/2016/Aug/82; link_name=BugTraq Mailing List, Tue, 9 Aug 
                         2016 13:48:00 GMT; description=Nagios NA v2.2.1 XSS}, 
                         @{link_target=https://packetstormsecurity.com/files/138246; link_name=Packet Storm Security 
                         [08-08-2016]; description=Nagios Network Analyzer 2.2.1 Cross Site Scripting}, 
                         @{link_target=https://www.nagios.com/products/nagios-network-analyzer/; link_name=Nagios Web site; 
                         description=Nagios Network Analyzer. Netflow Analysis and Monitoring}}
    signatures         : {@{coverage=Cross_Site_Scripting; coverage_date=2008-11-11T00:00:00Z}}
    report_confidence  : Confirmed

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce
   #>
  
   [cmdletbinding()]
    Param (
        [Parameter(ParameterSetName=’Term’,HelpMessage = "Enter term to search on", ValueFromPipeline = $true, Position = 1)][string]$Term,
        [Parameter(ParameterSetName=’STD’,HelpMessage = "Enter CVE, BID, US-CERT VU# or RHSA ID")][string]$STDCode,
        [Alias('MS','MSBulletin','MSBID','MSID')][Parameter(ParameterSetName=’MSID’,HelpMessage = "Enter Microsoft Security Bulletin ID")][string]$MSBulletinID,
        [Alias('OS','Application','App','Plat','Platform')][Parameter(ParameterSetName=’Plat’,HelpMessage = "The appliance, OS or application to search on.")][string]$PlatformsAffected,
        [Parameter(HelpMessage = "Enter the number of results to display", Position = 2)][int]$Limit = "15",
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )

    BEGIN{
        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI = "https://api.xforce.ibmcloud.com/vulnerabilities/fulltext?q"
                $API_URI_STD ="https://api.xforce.ibmcloud.com/vulnerabilities/search"
                $API_URI_MS = "https://api.xforce.ibmcloud.com/vulnerabilities/msid"

            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block

    }#End of BEGIN block

    PROCESS{

        if ($coun = $true){

             #API call
             Write-Verbose -Message "Requesting data from IBM XForce"

            try{
                $proceed  = $true

                #Term query
                if($Term -ne ""){
        
                    $vuln = $(Invoke-RestMethod -Uri "$API_URI=$Term" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI=$Term : $vuln"
                    Write-Verbose -Message "Parsing data..."
                    $vuln = $vuln.rows
                    Write-Debug -Message "API data parsed: $vuln"
                    $srch = $Term
        
                }#End of term if

                #Platform search
                if($PlatformsAffected -ne ""){
        
                    $vuln = $(Invoke-RestMethod -Uri "$API_URI=platforms_affected%3A%22$PlatformsAffected%22" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI=platforms_affected%3A%22$PlatformsAffected%22 : $vuln"
                    Write-Verbose -Message "Parsing data..."
                    $vuln = $vuln.rows 
                    Write-Debug -Message "API data parsed: $vuln"
                    $srch = $PlatformsAffected
        
                }#End of platform if

                #STD Code
                if($STDCode -ne ""){
        
                    $vuln = $(Invoke-RestMethod -Uri "$API_URI_STD/$STDCode" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI_STD/$STDCode : $vuln"
                    $srch = $STDCode
        
                }#End of STD Code if

                #Microsoft Security Bulletin ID
                if($MSBulletinID -ne ""){
        
                    $vuln = $(Invoke-RestMethod -Uri "$API_URI_MS/$MSBulletinID" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI_MS/$MSBulletinID : $vuln"
                    $srch = $MSBulletinID
        
                }#End of Microsoft Security Bulletin if
        
            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){
        
                #Limit Parameter
                $vuln = $vuln | Select-Object -First $Limit

                #Clipboard Switch
                if($Clipboard){
    
                    $vuln | clip
    
                }#End of Clipboard IF

                Write-Output $vuln 
            }#End of proceed if

        }#End of If statement

    }#End of PROCESS block

    END{}#End of END block

}#End of Find-XFvulnerabilities


function Get-XFRecentVulnerabilities {

   <#
    .SYNOPSIS
     Gets to most recent vulnerabilities

    .DESCRIPTION
    Gets to most recent vulnerabilities 

    .PARAMETER Limit
    Sets the number of results returned.

    .SWITCH Clipboard
    Copies all output from this function to your clipboard

    .REMARKS
    In order to use this CMDlet you must first  signup for an IBM XForce account at https://www.ibm.com/account/profile/us?page=reg
    and generate the API key pair as specified at https://api.xforce.ibmcloud.com/doc/#auth. For more information on IBM's 
    XForce API please visit https://api.xforce.ibmcloud.com/doc/. The API key pair can then be set using the Set-MyAPISet
    CMDlet with the XForce switch EX. 
    Set-MyAPISet -Key e551d9e4-ff0a-ccca-41c21-c215893ae74bc -Password 544a42b1c-0e4a-10r4-e7cc-b12d5e9f476a4 -XForce

   #>
   [Alias('XRVuln')]
   [cmdletbinding()]
    Param (
        [Parameter(HelpMessage = "Enter the number of results to display",Position = 1)][int]$Limit,
        [Alias('CC','CB', 'Clip','Copy','C')][Switch]$Clipboard
    )

    BEGIN{

        try{

                $coun = $true
                #Getting xForce Key
                Write-Verbose -Message "Retrieving API key for XForce."
                $myKey = Get-MyAPIKey -XForce

                #Building Header for XForce
                Write-Verbose -Message "Building authenication header."
                $head = New-APIAuthHeader -Key $myKey.api -Password $myKey.pass
                $API_URI = "https://api.xforce.ibmcloud.com/vulnerabilities/"
                $API_URI_LIMT ="https://api.xforce.ibmcloud.com/vulnerabilities/?limit"

            } catch{
            
                $coun = $false
            
            }#End of Try-Catch block

    }#End of BEGIN block

    PROCESS{
    
        if ($coun = $true){

             #API call
             Write-Verbose -Message "Requesting data from IBM XForce"

            try{
        
                $proceed  = $true

                if($Limit -ne ""){
        
                    $vuln = $(Invoke-RestMethod -Uri "$API_URI_LIMT=$Limit" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI_LIMT=$Limit : $vuln" 
        
                } else {
        
                    $vuln = $(Invoke-RestMethod -Uri "$API_URI" -Method: Get -Headers $head)
                    Write-Debug -Message "Queried $API_URI : $vuln" 
        
                }#End of if-else statement
         
            } catch {
            
                $proceed  = $false
            
                switch ($_.Exception.Response.StatusCode.value__) {

                    "401" {Write-Error -Message "(401) Unauthorized. API key pair is wrong, does not exisit, or was not provided during the request. This error may also be caused by inactivity timeout at your webproxy."}
                    "402" {Write-Error -Message "(402) Payment Required. You have exceeded the use of your free API or the data requested is available only to paying users."}
                    "403" {Write-Error -Message "(403) Access Denied. You do not have permissions to access the requested data."}
                    "404" {Write-Error -Message "(404) XForce has no data for $srch"}
                    "429" {Write-Error -Message "(429) Rate Limit Exceeded. You have exceeded the Rate Limit set for your API key."}
                    default {Write-Error -Message "($($_.Exception.Response.StatusCode.value__)) $($_.Exception.Response.StatusDescription)"}
            
                }#End of switch block
        
            }#End of try-catch block

            if($proceed){
        
                #Clipboard Switch
                if($Clipboard){
    
                    $vuln | clip
    
                }#End of Clipboard IF
                Write-Output $vuln
        
            }#End of proceed if

        }#End of If statement

    }#End of PROCESS block

    END{}#End of END block

}#End of Get-XFRecentVulnerabilities