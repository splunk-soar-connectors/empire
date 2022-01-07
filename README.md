[comment]: # "Auto-generated SOAR connector documentation"
# Empire

Publisher: Phantom  
Connector Version: 1\.0\.16  
Product Vendor: Empire  
Product Name: Empire  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 3\.0\.251  

This app supports a variety of actions to interact with the REST API of Empire \- https\://github\.com/powershellempire/empire

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Empire asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  required  | string | Base URL for the Empire REST API \(e\.g\. https\://192\.168\.1\.1\)
**port** |  required  | string | Port that the Empire REST API is listening on \(default\: 1337\)
**verify\_server\_cert** |  optional  | boolean | Verify Server Cert
**username** |  required  | string | Username for accessing the Empire REST API
**password** |  required  | password | Password for accessing the Empire REST API

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[get credentials](#action-get-credentials) - Get compromised credentials stored in Empire  
[execute module](#action-execute-module) - Execute a module or run a shell command in Empire  
[get module](#action-get-module) - Get a module by name in Empire  
[list modules](#action-list-modules) - List all available modules in Empire  
[get results](#action-get-results) - Get results from most recent agent command  
[terminate server](#action-terminate-server) - Kill a listener in Empire  
[terminate endpoint](#action-terminate-endpoint) - Kill an agent on an endpoint in Empire  
[remove endpoint](#action-remove-endpoint) - Remove an agent in Empire  
[list endpoints](#action-list-endpoints) - Returns all current agents in Empire  
[create payload](#action-create-payload) - Create a stager in Empire  
[get payload](#action-get-payload) - Get a stager by name  
[list payloads](#action-list-payloads) - List all current stagers  
[get server options](#action-get-server-options) - Get a list of options for a specified listener type  
[create server](#action-create-server) - Create a new listener  
[get server](#action-get-server) - Get a listener by name  
[list servers](#action-list-servers) - Get all current listeners  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'get credentials'
Get compromised credentials stored in Empire

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.creds\.\*\.username | string |  `user name` 
action\_result\.data\.\*\.creds\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.creds\.\*\.credtype | string | 
action\_result\.data\.\*\.creds\.\*\.notes | string | 
action\_result\.data\.\*\.creds\.\*\.host | string |  `host name` 
action\_result\.data\.\*\.creds\.\*\.sid | string | 
action\_result\.data\.\*\.creds\.\*\.password | string | 
action\_result\.data\.\*\.creds\.\*\.os | string | 
action\_result\.data\.\*\.creds\.\*\.ID | numeric | 
action\_result\.summary\.total\_creds | string |   

## action: 'execute module'
Execute a module or run a shell command in Empire

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**module\_name\_or\_command** |  required  | Name of module to execute or shell command to run | string |  `empire module name` 
**agent\_name** |  required  | Agent on which to execute module | string |  `empire agent name` 
**get\_results** |  required  | Get results of module? | boolean | 
**is\_shell\_command** |  required  | Is this a shell command? | boolean | 
**options** |  optional  | JSON of additional options for module | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.module\_name\_or\_command | string |  `empire module name` 
action\_result\.parameter\.agent\_name | string |  `empire agent name` 
action\_result\.parameter\.options | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.msg | string | 
action\_result\.data\.\*\.taskID | numeric | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.summary\.msg | string | 
action\_result\.summary\.success | boolean | 
action\_result\.data\.\*\.results\_lines | string | 
action\_result\.data\.\*\.results\_lines\.\*\.line | string | 
action\_result\.parameter\.get\_results | boolean | 
action\_result\.summary\.taskID | numeric | 
action\_result\.summary\.AgentName | string | 
action\_result\.parameter\.is\_shell\_command | boolean |   

## action: 'get module'
Get a module by name in Empire

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**module\_name** |  required  | Name of module to get | string |  `empire module name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.module\_name | string |  `empire module name` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.modules\.\*\.Name | string |  `empire module name` 
action\_result\.data\.\*\.modules\.\*\.Language | string | 
action\_result\.data\.\*\.modules\.\*\.Author | string | 
action\_result\.data\.\*\.modules\.\*\.OpsecSafe | boolean | 
action\_result\.data\.\*\.modules\.\*\.Comments | string |  `url` 
action\_result\.data\.\*\.modules\.\*\.NeedsAdmin | boolean | 
action\_result\.data\.\*\.modules\.\*\.Background | boolean | 
action\_result\.data\.\*\.modules\.\*\.MinLanguageVersion | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Domain\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Domain\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Domain\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.DomainController\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.DomainController\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.DomainController\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.ComputerName\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.ComputerName\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.ComputerName\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Agent\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Agent\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Agent\.Value | string |  `empire agent name` 
action\_result\.data\.\*\.modules\.\*\.options\.Delay\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Delay\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Delay\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.CheckShareAccess\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.CheckShareAccess\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.CheckShareAccess\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Threads\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Threads\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Threads\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.NoPing\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.NoPing\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.NoPing\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.ComputerFilter\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.ComputerFilter\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.ComputerFilter\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.Description | string | 
action\_result\.summary\.Language | string | 
action\_result\.summary\.Name | string |  `empire module name` 
action\_result\.summary\.NeedsAdmin | boolean |   

## action: 'list modules'
List all available modules in Empire

Type: **generic**  
Read only: **True**

This action also has an optional parameter to search for a module if you are not sure of the exact name\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search\_string** |  optional  | Option string to search for in module names | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.search\_string | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.modules\.\*\.Name | string |  `empire module name` 
action\_result\.data\.\*\.modules\.\*\.Language | string | 
action\_result\.data\.\*\.modules\.\*\.Author | string | 
action\_result\.data\.\*\.modules\.\*\.OpsecSafe | boolean | 
action\_result\.data\.\*\.modules\.\*\.Comments | string |  `url` 
action\_result\.data\.\*\.modules\.\*\.NeedsAdmin | boolean | 
action\_result\.data\.\*\.modules\.\*\.Background | boolean | 
action\_result\.data\.\*\.modules\.\*\.OutputExtension | string | 
action\_result\.data\.\*\.modules\.\*\.MinLanguageVersion | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Image\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Image\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Image\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Login\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Login\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Login\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Agent\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Agent\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Agent\.Value | string |  `empire agent name` 
action\_result\.data\.\*\.modules\.\*\.options\.Desktop\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Desktop\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Desktop\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.LocalImagePath\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.LocalImagePath\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.LocalImagePath\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Message\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Message\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Message\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.IconType\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.IconType\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.IconType\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Title\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Title\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Title\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.VoiceText\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.VoiceText\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.VoiceText\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.VideoURL\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.VideoURL\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.VideoURL\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Text\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Text\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Text\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Voice\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Voice\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Voice\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.MsgText\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.MsgText\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.MsgText\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.ProcessName\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.ProcessName\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.ProcessName\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Sleep\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Sleep\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Sleep\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Silent\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Silent\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Silent\.Value | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Remove\.Required | boolean | 
action\_result\.data\.\*\.modules\.\*\.options\.Remove\.Description | string | 
action\_result\.data\.\*\.modules\.\*\.options\.Remove\.Value | string | 
action\_result\.summary\.total\_modules | numeric |   

## action: 'get results'
Get results from most recent agent command

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent\_name** |  required  | Agent name for which to get results | string |  `empire agent name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.agent\_name | string |  `empire agent name` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.results\.\*\.AgentName | string |  `empire agent name` 
action\_result\.data\.\*\.results\.\*\.AgentResults | string | 
action\_result\.summary\.AgentName | string |  `empire agent name` 
action\_result\.summary\.AgentResults | string |   

## action: 'terminate server'
Kill a listener in Empire

Type: **generic**  
Read only: **False**

This terminates the listener\(s\) on the empire server\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener\_name** |  optional  | Listener name to kill | string |  `empire listener name` 
**kill\_all** |  required  | Kill all listeners? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.message | string | 
action\_result\.parameter\.kill\_all | boolean | 
action\_result\.parameter\.listener\_name | string |  `empire listener name` 
action\_result\.summary\.success | boolean | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'terminate endpoint'
Kill an agent on an endpoint in Empire

Type: **generic**  
Read only: **False**

This instructs the process on the remote machine to terminate\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent\_name** |  optional  | Agent name to kill | string |  `empire agent name` 
**kill\_all** |  required  | Kill all agents? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.agent\_name | string |  `empire agent name` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.parameter\.kill\_all | boolean | 
action\_result\.summary\.success | boolean |   

## action: 'remove endpoint'
Remove an agent in Empire

Type: **generic**  
Read only: **False**

This removes an agent from the Empire server database\.  It is usually best to kill agent first\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent\_name** |  optional  | Agent name to remove | string |  `empire agent name` 
**remove\_stale** |  required  | Remove all stale agents? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.success | boolean | 
action\_result\.message | string | 
action\_result\.parameter\.agent\_name | string |  `empire agent name` 
action\_result\.parameter\.remove\_stale | boolean | 
action\_result\.summary\.success | boolean | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list endpoints'
Returns all current agents in Empire

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**stale\_only** |  required  | Return only stale agents? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
action\_result\.parameter\.stale\_only | boolean | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.agents\.\*\.nonce | string | 
action\_result\.data\.\*\.agents\.\*\.working\_hours | string | 
action\_result\.data\.\*\.agents\.\*\.results | string | 
action\_result\.data\.\*\.agents\.\*\.internal\_ip | string |  `ip` 
action\_result\.data\.\*\.agents\.\*\.jitter | numeric | 
action\_result\.data\.\*\.agents\.\*\.session\_key | string | 
action\_result\.data\.\*\.agents\.\*\.checkin\_time | string | 
action\_result\.data\.\*\.agents\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.agents\.\*\.delay | numeric | 
action\_result\.data\.\*\.agents\.\*\.profile | string | 
action\_result\.data\.\*\.agents\.\*\.kill\_date | string | 
action\_result\.data\.\*\.agents\.\*\.process\_name | string | 
action\_result\.data\.\*\.agents\.\*\.listener | string |  `empire listener name` 
action\_result\.data\.\*\.agents\.\*\.process\_id | string | 
action\_result\.data\.\*\.agents\.\*\.os\_details | string | 
action\_result\.data\.\*\.agents\.\*\.lost\_limit | numeric | 
action\_result\.data\.\*\.agents\.\*\.ID | numeric | 
action\_result\.data\.\*\.agents\.\*\.taskings | string | 
action\_result\.data\.\*\.agents\.\*\.name | string |  `empire agent name` 
action\_result\.data\.\*\.agents\.\*\.language | string | 
action\_result\.data\.\*\.agents\.\*\.external\_ip | string |  `ip` 
action\_result\.data\.\*\.agents\.\*\.session\_id | string | 
action\_result\.data\.\*\.agents\.\*\.username | string |  `user name` 
action\_result\.data\.\*\.agents\.\*\.lastseen\_time | string | 
action\_result\.data\.\*\.agents\.\*\.language\_version | string | 
action\_result\.data\.\*\.agents\.\*\.high\_integrity | numeric | 
action\_result\.summary\.total\_agents | numeric |   

## action: 'create payload'
Create a stager in Empire

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**stager\_name** |  required  | The stager name to generate | string |  `empire stager name` 
**listener\_name** |  required  | The listener name to generate stager for | string |  `empire listener name` 
**options** |  optional  | JSON of options for stager | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.stager\_name | string |  `empire stager name` 
action\_result\.parameter\.listener\_name | string |  `empire listener name` 
action\_result\.parameter\.options | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.windows/hta\.ProxyCreds\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.ProxyCreds\.Description | string | 
action\_result\.data\.\*\.windows/hta\.ProxyCreds\.Value | string | 
action\_result\.data\.\*\.windows/hta\.Language\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.Language\.Description | string | 
action\_result\.data\.\*\.windows/hta\.Language\.Value | string | 
action\_result\.data\.\*\.windows/hta\.Base64\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.Base64\.Description | string | 
action\_result\.data\.\*\.windows/hta\.Base64\.Value | string | 
action\_result\.data\.\*\.windows/hta\.StagerRetries\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.StagerRetries\.Description | string | 
action\_result\.data\.\*\.windows/hta\.StagerRetries\.Value | string | 
action\_result\.data\.\*\.windows/hta\.Listener\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.Listener\.Description | string | 
action\_result\.data\.\*\.windows/hta\.Listener\.Value | string |  `empire listener name` 
action\_result\.data\.\*\.windows/hta\.OutFile\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.OutFile\.Description | string | 
action\_result\.data\.\*\.windows/hta\.OutFile\.Value | string | 
action\_result\.data\.\*\.windows/hta\.Obfuscate\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.Obfuscate\.Description | string | 
action\_result\.data\.\*\.windows/hta\.Obfuscate\.Value | string | 
action\_result\.data\.\*\.windows/hta\.Proxy\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.Proxy\.Description | string | 
action\_result\.data\.\*\.windows/hta\.Proxy\.Value | string | 
action\_result\.data\.\*\.windows/hta\.Output | string | 
action\_result\.data\.\*\.windows/hta\.UserAgent\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.UserAgent\.Description | string | 
action\_result\.data\.\*\.windows/hta\.UserAgent\.Value | string | 
action\_result\.data\.\*\.windows/hta\.ObfuscateCommand\.Required | boolean | 
action\_result\.data\.\*\.windows/hta\.ObfuscateCommand\.Description | string | 
action\_result\.data\.\*\.windows/hta\.ObfuscateCommand\.Value | string | 
action\_result\.summary\.StagerCreated | string |   

## action: 'get payload'
Get a stager by name

Type: **generic**  
Read only: **True**

Get a single stager using its name\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**stager\_name** |  required  | Name of stager to get | string |  `empire stager name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.stager\_name | string |  `empire stager name` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.stagers\.\*\.Name | string |  `empire stager name` 
action\_result\.data\.\*\.stagers\.\*\.Author | string | 
action\_result\.data\.\*\.stagers\.\*\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.Comments | string |  `url` 
action\_result\.data\.\*\.stagers\.\*\.options\.Listener\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Listener\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Listener\.Value | string |  `empire listener name` 
action\_result\.data\.\*\.stagers\.\*\.options\.OutFile\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutFile\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutFile\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Language\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Language\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Language\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.SafeChecks\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.SafeChecks\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.SafeChecks\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.UserAgent\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.UserAgent\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.UserAgent\.Value | string | 
action\_result\.summary\.total\_stagers | numeric |   

## action: 'list payloads'
List all current stagers

Type: **generic**  
Read only: **True**

List all the stagers available in Empire\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.stagers\.\*\.Name | string |  `empire stager name` 
action\_result\.data\.\*\.stagers\.\*\.Author | string | 
action\_result\.data\.\*\.stagers\.\*\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.Comments | string |  `url` 
action\_result\.data\.\*\.stagers\.\*\.options\.Listener\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Listener\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Listener\.Value | string |  `empire listener name` 
action\_result\.data\.\*\.stagers\.\*\.options\.OutFile\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutFile\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutFile\.Value | string |  `file name` 
action\_result\.data\.\*\.stagers\.\*\.options\.Language\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Language\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Language\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.SafeChecks\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.SafeChecks\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.SafeChecks\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.UserAgent\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.UserAgent\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.UserAgent\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Hijacker\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Hijacker\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Hijacker\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Architecture\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Architecture\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Architecture\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.ProxyCreds\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.ProxyCreds\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.ProxyCreds\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.StagerRetries\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.StagerRetries\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.StagerRetries\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Proxy\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Proxy\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Proxy\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Keyboard\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Keyboard\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Keyboard\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Interpreter\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Interpreter\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Interpreter\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.AppName\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.AppName\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.AppName\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Obfuscate\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Obfuscate\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Obfuscate\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.ObfuscateCommand\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.ObfuscateCommand\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.ObfuscateCommand\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.MinPSVersion | string | 
action\_result\.data\.\*\.stagers\.\*\.OpsecSafe | boolean | 
action\_result\.data\.\*\.stagers\.\*\.Background | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Base64\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Base64\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Base64\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.PowershellPath\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.PowershellPath\.Description | string |  `file name` 
action\_result\.data\.\*\.stagers\.\*\.options\.PowershellPath\.Value | string |  `file path`  `file name` 
action\_result\.data\.\*\.stagers\.\*\.options\.LNKComment\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.LNKComment\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.LNKComment\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Icon\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Icon\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Icon\.Value | string |  `file path`  `file name` 
action\_result\.data\.\*\.stagers\.\*\.options\.AppIcon\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.AppIcon\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.AppIcon\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Delete\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Delete\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Delete\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.BinaryFile\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.BinaryFile\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.BinaryFile\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Arch\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.Arch\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.Arch\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputPath\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputPath\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputPath\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputPs1\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputPs1\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputPs1\.Value | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.HostURL\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.HostURL\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.HostURL\.Value | string |  `url` 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputDocx\.Required | boolean | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputDocx\.Description | string | 
action\_result\.data\.\*\.stagers\.\*\.options\.OutputDocx\.Value | string | 
action\_result\.summary\.total\_stagers | numeric |   

## action: 'get server options'
Get a list of options for a specified listener type

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener\_type** |  required  | Listener Type for which to get options | string |  `empire listener type` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.listener\_type | string |  `empire listener type` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.summary\.listener\_found | string | 
action\_result\.data\.\*\.Required | boolean | 
action\_result\.data\.\*\.Name | string |  `empire listener name` 
action\_result\.data\.\*\.Value | string | 
action\_result\.data\.\*\.Description | string |   

## action: 'create server'
Create a new listener

Type: **generic**  
Read only: **False**

Create a listener in Empire\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener\_type** |  required  | Type of Listener to create | string |  `empire listener type` 
**listener\_name** |  required  | Name for listener | string |  `empire listener name` 
**options** |  optional  | JSON options for a listener \- see output of get server options for examples | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.listener\_type | string |  `empire listener type` 
action\_result\.parameter\.listener\_name | string |  `empire listener name` 
action\_result\.parameter\.options | string | 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.success | string | 
action\_result\.summary\.success | string |   

## action: 'get server'
Get a listener by name

Type: **generic**  
Read only: **True**

Returns the listener specified by the name\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener\_name** |  required  | Listener Name | string |  `empire listener name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.parameter\.listener\_name | string |  `empire listener name` 
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.listeners\.\*\.name | string |  `empire listener name` 
action\_result\.data\.\*\.listeners\.\*\.listener\_category | string | 
action\_result\.data\.\*\.listeners\.\*\.module | string |  `empire listener type` 
action\_result\.data\.\*\.listeners\.\*\.ID | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagerURI\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagerURI\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagerURI\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ProxyCreds\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.ProxyCreds\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ProxyCreds\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.KillDate\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.KillDate\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.KillDate\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Name\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Name\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Name\.Value | string |  `url` 
action\_result\.data\.\*\.listeners\.\*\.options\.Launcher\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Launcher\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Launcher\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultProfile\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultProfile\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultProfile\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ServerVersion\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.ServerVersion\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ServerVersion\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Host\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Host\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Host\.Value | string |  `url` 
action\_result\.data\.\*\.listeners\.\*\.options\.Port\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Port\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Port\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.WorkingHours\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.WorkingHours\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.WorkingHours\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.CertPath\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.CertPath\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.CertPath\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultLostLimit\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultLostLimit\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultLostLimit\.Value | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackChannel\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackChannel\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackChannel\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.UserAgent\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.UserAgent\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.UserAgent\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.BindIP\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.BindIP\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.BindIP\.Value | string |  `ip` 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultJitter\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultJitter\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultJitter\.Value | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagingKey\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagingKey\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagingKey\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultDelay\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultDelay\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultDelay\.Value | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackToken\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackToken\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackToken\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Proxy\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Proxy\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Proxy\.Value | string | 
action\_result\.summary\.listener\_module | string |  `url`   

## action: 'list servers'
Get all current listeners

Type: **generic**  
Read only: **True**

Returns all current Empire listeners\.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 
action\_result\.data\.\*\.listeners\.\*\.name | string |  `empire listener name` 
action\_result\.data\.\*\.listeners\.\*\.listener\_category | string | 
action\_result\.data\.\*\.listeners\.\*\.module | string |  `empire listener type` 
action\_result\.data\.\*\.listeners\.\*\.ID | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagerURI\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagerURI\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagerURI\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ProxyCreds\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.ProxyCreds\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ProxyCreds\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.KillDate\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.KillDate\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.KillDate\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Name\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Name\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Name\.Value | string |  `empire listener name` 
action\_result\.data\.\*\.listeners\.\*\.options\.Launcher\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Launcher\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Launcher\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultProfile\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultProfile\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultProfile\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ServerVersion\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.ServerVersion\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.ServerVersion\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Host\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Host\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Host\.Value | string |  `url` 
action\_result\.data\.\*\.listeners\.\*\.options\.Port\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Port\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Port\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.WorkingHours\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.WorkingHours\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.WorkingHours\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.CertPath\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.CertPath\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.CertPath\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultLostLimit\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultLostLimit\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultLostLimit\.Value | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackChannel\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackChannel\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackChannel\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.UserAgent\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.UserAgent\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.UserAgent\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.BindIP\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.BindIP\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.BindIP\.Value | string |  `ip` 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultJitter\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultJitter\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultJitter\.Value | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagingKey\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagingKey\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.StagingKey\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultDelay\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultDelay\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.DefaultDelay\.Value | numeric | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackToken\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackToken\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.SlackToken\.Value | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Proxy\.Required | boolean | 
action\_result\.data\.\*\.listeners\.\*\.options\.Proxy\.Description | string | 
action\_result\.data\.\*\.listeners\.\*\.options\.Proxy\.Value | string | 
action\_result\.summary\.total\_listeners | numeric | 