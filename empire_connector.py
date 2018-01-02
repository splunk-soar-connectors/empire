# --
# File: empire_connector.py
#
# Copyright (c) Phantom Cyber Corporation, 2017
#
# This unpublished material is proprietary to Phantom Cyber.
# All rights reserved. The methods and
# techniques described herein are considered trade secrets
# and/or confidential. Reproduction or distribution, in whole
# or in part, is forbidden except by express written permission
# of Phantom Cyber Corporation.
#
# --

# Phantom App imports
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult

# Usage of the consts file is recommended
# from empire_consts import *
import ast
import requests
import json
from bs4 import BeautifulSoup
from time import sleep


class RetVal(tuple):
    def __new__(cls, val1, val2):
        return tuple.__new__(RetVal, (val1, val2))


class EmpireConnector(BaseConnector):

    def __init__(self):

        # Call the BaseConnectors init first
        super(EmpireConnector, self).__init__()
        self._state = {}

    def initialize(self):

        self._state = self.load_state()

        config = self.get_config()
        self._token = None
        self._verify = False
        self._base_url = config['base_url'] + ':' + config['port']
        url = self._base_url + '/api/admin/login'
        data = {"username": config['username'], "password": config['password']}
        try:
            self.save_progress("Getting authentication token")
            login_resp = requests.post(url, params=None, json=data, verify=self._verify)
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, "Error acquiring auth token.  Details: {0}".format(str(e)))

        if login_resp.status_code == 401:
            self.save_progress("Incorrect Username or Password for accessing the Empire REST API")
            return phantom.APP_ERROR
        try:
            self._token = login_resp.json()['token']
            self.save_progress("Got authentication successfully.")
        except Exception as e:
            return self.set_status(phantom.APP_ERROR, "Error acquiring auth token.  Details: {0}".format(str(e)))

        return phantom.APP_SUCCESS

    def _process_empty_reponse(self, response, action_result):

        if response.status_code == 200:
            return RetVal(phantom.APP_SUCCESS, {})

        return RetVal(action_result.set_status(phantom.APP_ERROR, "Empty response and no information in the header"), None)

    def _process_html_response(self, response, action_result):

        # An html response, treat it like an error
        status_code = response.status_code

        try:
            soup = BeautifulSoup(response.text, "html.parser")
            error_text = soup.text
            split_lines = error_text.split('\n')
            split_lines = [x.strip() for x in split_lines if x.strip()]
            error_text = '\n'.join(split_lines)
        except:
            error_text = "Cannot parse error details"

        message = "Status Code: {0}. Data from server:\n{1}\n".format(status_code,
                error_text)

        message = message.replace('{', '{{').replace('}', '}}')

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_json_response(self, r, action_result):

        # Try a json parse
        try:
            resp_json = r.json()
        except Exception as e:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Unable to parse JSON response. Error: {0}".format(str(e))), None)

        # Please specify the status codes here
        if 200 <= r.status_code < 399:
            if resp_json.get('error', None) is None:
                return RetVal(phantom.APP_SUCCESS, resp_json)

        # You should process the error returned in the json
        message = "Error from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _process_response(self, r, action_result):

        # store the r_text in debug data, it will get dumped in the logs if the action fails
        if hasattr(action_result, 'add_debug_data'):
            action_result.add_debug_data({'r_status_code': r.status_code})
            action_result.add_debug_data({'r_text': r.text})
            action_result.add_debug_data({'r_headers': r.headers})

        # Process each 'Content-Type' of response separately

        # Process a json response
        if 'json' in r.headers.get('Content-Type', ''):
            return self._process_json_response(r, action_result)

        # Process an HTML resonse, Do this no matter what the api talks.
        # There is a high chance of a PROXY in between phantom and the rest of
        # world, in case of errors, PROXY's return HTML, this function parses
        # the error and adds it to the action_result.
        if 'html' in r.headers.get('Content-Type', ''):
            return self._process_html_response(r, action_result)

        # it's not content-type that is to be parsed, handle an empty response
        if not r.text:
            return self._process_empty_reponse(r, action_result)

        # everything else is actually an error at this point
        message = "Can't process response from server. Status Code: {0} Data from server: {1}".format(
                r.status_code, r.text.replace('{', '{{').replace('}', '}}'))

        return RetVal(action_result.set_status(phantom.APP_ERROR, message), None)

    def _make_rest_call(self, endpoint, action_result, headers=None, params=None, data=None, method="get"):

        config = self.get_config()

        resp_json = None

        try:
            request_func = getattr(requests, method)
        except AttributeError:
            return RetVal(action_result.set_status(phantom.APP_ERROR, "Invalid method: {0}".format(method)), resp_json)

        # Create a URL to connect to
        url = self._base_url + '/api/' + endpoint + '?token={0}'.format(self._token)

        try:
            r = request_func(
                            url,
                            json=data,
                            headers=headers,
                            verify=config.get('verify_server_cert', False),
                            params=params)
        except Exception as e:
            return RetVal(action_result.set_status( phantom.APP_ERROR, "Error making rest call to server. Details: {0}".format(str(e))), resp_json)

        return self._process_response(r, action_result)

    def _handle_test_connectivity(self, param):

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # NOTE: test connectivity does _NOT_ take any parameters
        # i.e. the param dictionary passed to this handler will be empty.
        # Also typically it does not add any data into an action_result either.
        # The status and progress messages are more important.

        self.save_progress("Testing connectivity by getting Empire Version")
        # make rest call
        ret_val, response = self._make_rest_call('version', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            self.save_progress("Test Connectivity Failed. Error: {0}".format(action_result.get_message()))
            return action_result.get_status()

        # Return success
        try:
            self.save_progress("Test Connectivity Passed.  Version: {0}".format(response["version"]))
        except:
            self.save_progress("Test Connectivity Passed")
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_credentials(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        ret_val, response = self._make_rest_call('creds', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_creds'] = str(len(response["creds"]))

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_execute_module(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        agent_name = param['agent_name']
        module_name = param['module_name_or_command']
        get_results = param['get_results']

        is_shell_command = param['is_shell_command']
        if is_shell_command:
            endpoint = 'agents/{0}/shell'.format(agent_name)
            data = {"command": module_name}
        else:
            endpoint = 'modules/{0}'.format(module_name)
            options = param.get('options', None)
            if options:
                try:
                    data = ast.literal_eval(options)
                    data["Agent"] = agent_name
                except Exception as e:
                    return action_result.set_status(phantom.APP_ERROR, "Error building options dictionary: {0}".format(e))
            else:
                data = {"Agent": agent_name}

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, data=data, method="post")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        if response.get("success", False) and get_results:
            summary = action_result.update_summary({})
            summary['success'] = response.get("success", False)
            summary['msg'] = response.get("msg", "No message")
            summary['taskID'] = response.get("taskID", 0)
            sleep(5)
            iteration_count = 1
            while True:
                self.save_progress("Checking for agent results. Iteration: {0}".format(iteration_count))
                ret_val, response = self._make_rest_call('agents/{0}/results'.format(agent_name), action_result, params=None, headers=None)

                agent_results = self._parse_results(response)

                if not is_shell_command and len(agent_results) > 0 and "Job" not in agent_results[-1]["line"]:
                    summary['AgentName'] = response["results"][0]["AgentName"]
                    # summary['AgentResults'] = agent_results_string
                    action_result.add_data({"results_lines": agent_results})

                    # Delete the agent results
                    ret_val, response = self._make_rest_call('agents/{0}/results'.format(agent_name), action_result, params=None, headers=None, method="delete")
                    if (phantom.is_fail(ret_val)):
                        self.save_progress("Deleting agent results failed: {0}".format(action_result.get_message()))
                        return action_result.get_status()

                    return action_result.set_status(phantom.APP_SUCCESS)

                elif is_shell_command and len(agent_results) > 0:
                    summary['AgentName'] = response["results"][0]["AgentName"]
                    # summary['AgentResults'] = agent_results_string
                    action_result.add_data({"results_lines": agent_results})

                    # Delete the agent results
                    ret_val, response = self._make_rest_call('agents/{0}/results'.format(agent_name), action_result, params=None, headers=None, method="delete")
                    if (phantom.is_fail(ret_val)):
                        self.save_progress("Deleting agent results failed: {0}".format(action_result.get_message()))
                        return action_result.get_status()

                    return action_result.set_status(phantom.APP_SUCCESS)

                if iteration_count > 9:
                    summary['AgentName'] = response["results"][0]["AgentName"]
                    summary['AgentResults'] = response["results"][0]["AgentResults"][0]
                    action_result.add_data({"results_lines": agent_results})

                    return action_result.set_status(phantom.APP_ERROR, "Unable to retrieve agent results beyond starting job.")

                iteration_count += 1
                sleep(6)

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = response.get("success", False)
        summary['msg'] = response.get("msg", "No message")
        summary['taskID'] = response.get("taskID", 0)

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _parse_results(self, response):

        agent_results_string = response["results"][0]["AgentResults"][0]
        agent_results = []
        bad_chars = '[]"'
        for item in agent_results_string.split(","):
            for item2 in item.split("\\r\\n"):
                for c in bad_chars:
                    item2 = item2.replace(c, "")
                if item2.strip() != '' and item2.strip() != '\\n':
                    agent_results.append({"line": item2.strip()})

        return agent_results

    def _handle_get_module(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        module_name = param['module_name']

        endpoint = 'modules/{0}'.format(module_name)

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})

        module_info = response.get("modules", None)
        if module_info:
            module_name = module_info[0].get("Name", "None Returned")
            summary['Name'] = module_name
            module_language = module_info[0].get("Language", "None Returned")
            summary['Language'] = module_language
            module_admin = module_info[0].get("NeedsAdmin", "None Returned")
            summary['NeedsAdmin'] = module_admin

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_modules(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        search_string = param.get("search_string", None)

        if search_string is not None:
            endpoint = 'modules/search'
            method = 'post'
            data = {"term": search_string}
        else:
            endpoint = 'modules'
            method = 'get'
            data = None

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, data=data, method=method)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_modules'] = len(response["modules"])

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_agent_results(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        agent_name = param['agent_name']

        # make rest call
        ret_val, response = self._make_rest_call('agents/{0}/results'.format(agent_name), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        agent_results = self._parse_results(response)
        action_result.add_data({"results_lines": agent_results})

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['AgentName'] = response["results"][0]["AgentName"]
        summary['AgentResults'] = response["results"][0]["AgentResults"]

        # Delete the agent results
        ret_val, response = self._make_rest_call('agents/{0}/results'.format(agent_name), action_result, params=None, headers=None, method="delete")
        if (phantom.is_fail(ret_val)):
            self.save_progress("Deleting agent results failed: {0}".format(action_result.get_message()))
            return action_result.get_status()
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_kill_agent(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        agent_name = param.get('agent_name', None)
        kill_all = param.get('kill_all', False)
        if (agent_name is not None and not kill_all):
            endpoint = 'agents/{0}/kill'.format(agent_name)
        elif kill_all:
            endpoint = 'agents/all/kill'
        else:
            return action_result.set_status(phantom.APP_ERROR, "Incorrect parameters supplied for building endpoint for kill agents.")
        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)
        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = response.get("success", "No value returned")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_remove_agent(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        agent_name = param.get('agent_name', None)
        remove_stale = param.get('remove_stale', False)
        if (agent_name is not None and not remove_stale):
            endpoint = 'agents/{0}'.format(agent_name)
        elif remove_stale:
            endpoint = 'agents/stale'
        else:
            return action_result.set_status(phantom.APP_ERROR, "Incorrect parameters supplied for building endpoint for remove agents.")
        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="delete")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)
        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = response.get("success", "No value returned")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_kill_listener(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        listener_name = param.get('listener_name', None)
        kill_all = param.get('kill_all', False)
        if (listener_name is not None and not kill_all):
            endpoint = 'listeners/{0}'.format(listener_name)
        elif kill_all:
            endpoint = 'listeners/all'
        else:
            return action_result.set_status(phantom.APP_ERROR, "Incorrect parameters supplied for building endpoint for kill listeners.")
        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, method="delete")

        if (phantom.is_fail(ret_val)):
            # the call to the 3rd party device or service failed, action result should contain all the error details
            # so just return from here
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)
        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = response.get("success", "No value returned")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_execute_command(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        agent_name = param.get('agent_name', None)
        task_all = param['task_all']

        if task_all:
            endpoint = 'agents/all/shell'
        elif agent_name and not task_all:
            endpoint = 'agents/{0}/shell'.format(agent_name)
        else:
            return action_result.set_status(phantom.APP_ERROR, "Incorrect parameters supplied for building endpoint for execute shell command.")

        command = param['command']
        data = {"command": command}

        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None, data=data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Now post process the data,  uncomment code as you deem fit

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = response.get("success", "No value returned")

        # Return success, no need to set the message, only the status
        # BaseConnector will create a textual message based off of the summary dictionary
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_agents(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        stale = param.get("stale_only", None)
        if stale:
            endpoint = 'agents/stale'
        else:
            endpoint = 'agents'
        # make rest call
        ret_val, response = self._make_rest_call(endpoint, action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['total_agents'] = len(response.get("agents", []))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_stager(self, param):

        # Implement the handler here
        # use self.save_progress(...) to send progress messages back to the platform
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # Required values can be accessed directly
        stager_name = param['stager_name']
        listener_name = param['listener_name']
        # Optional values should use the .get() function
        options = param.get('options', None)

        if options is None:
            data = {"StagerName": stager_name, "Listener": listener_name}
        else:
            try:
                data = ast.literal_eval(options)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Incorrect json provided for options: {0}".format(e))
            data["Listener"] = listener_name
            data["StagerName"] = stager_name

        # make rest call
        ret_val, response = self._make_rest_call('stagers', action_result, params=None, headers=None, data=data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        action_result.add_data(response)
        summary = action_result.update_summary({})
        summary['StagerCreated'] = "True"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_stager(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))
        stager_name = param['stager_name']
        # make rest call
        ret_val, response = self._make_rest_call('stagers/{0}'.format(stager_name), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        if len(response.get("stagers", 0)) >= 1:
            summary['stager_found'] = True
        else:
            summary['stager_found'] = False

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_stagers(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call('stagers', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_stagers'] = len(response.get("stagers", 0))

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_listener_options(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        listener_type = param['listener_type']

        # make rest call
        ret_val, response = self._make_rest_call('listeners/options/{0}'.format(listener_type), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        try:
            for each_option in response["listeneroptions"]:
                data_to_add = {}
                data_to_add["Name"] = each_option
                data_to_add.update(response["listeneroptions"][each_option])
                action_result.add_data(data_to_add)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, "Unable to parse server options: {0}".format(e))

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['listener_found'] = "True"

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_create_listener(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        action_result = self.add_action_result(ActionResult(dict(param)))

        listener_type = param['listener_type']
        listener_name = param['listener_name']
        options = param.get('options', None)

        if options is None:
            data = {"Name": listener_name}
        else:
            try:
                data = ast.literal_eval(options)
            except Exception as e:
                return action_result.set_status(phantom.APP_ERROR, "Incorrect json provided for options: {0}".format(e))
            data["Name"] = listener_name

        # make rest call
        ret_val, response = self._make_rest_call('listeners/{0}'.format(listener_type), action_result, params=None, headers=None, data=data, method="post")

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['success'] = response.get("success", "Failed")

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_get_listener(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        listener_name = param['listener_name']

        # make rest call
        ret_val, response = self._make_rest_call('listeners/{0}'.format(listener_name), action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)
        summary = action_result.update_summary({})
        listener_info = response.get("listeners", ["None returned"])[0]
        if listener_info != "None returned":
            summary['listener_module'] = listener_info.get("module", "None")
            summary['listener_type'] = listener_info.get("listener_type", "None")
        else:
            summary["listener_module"] = listener_info

        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_list_listeners(self, param):

        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))

        # Add an action result object to self (BaseConnector) to represent the action for this param
        action_result = self.add_action_result(ActionResult(dict(param)))

        # make rest call
        ret_val, response = self._make_rest_call('listeners', action_result, params=None, headers=None)

        if (phantom.is_fail(ret_val)):
            return action_result.get_status()

        # Add the response into the data section
        action_result.add_data(response)

        # Add a dictionary that is made up of the most important values from data into the summary
        summary = action_result.update_summary({})
        summary['total_listeners'] = len(response.get("listeners", 0))

        return action_result.set_status(phantom.APP_SUCCESS)

    def handle_action(self, param):

        ret_val = phantom.APP_SUCCESS

        # Get the action that we are supposed to execute for this App Run
        action_id = self.get_action_identifier()

        self.debug_print("action_id", self.get_action_identifier())

        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        elif action_id == 'get_credentials':
            ret_val = self._handle_get_credentials(param)
        elif action_id == 'execute_module':
            ret_val = self._handle_execute_module(param)
        elif action_id == 'get_module':
            ret_val = self._handle_get_module(param)
        elif action_id == 'list_modules':
            ret_val = self._handle_list_modules(param)
        elif action_id == 'get_agent_results':
            ret_val = self._handle_get_agent_results(param)
        elif action_id == 'kill_agent':
            ret_val = self._handle_kill_agent(param)
        elif action_id == 'remove_agent':
            ret_val = self._handle_remove_agent(param)
        elif action_id == 'execute_command':
            ret_val = self._handle_execute_command(param)
        elif action_id == 'list_agents':
            ret_val = self._handle_list_agents(param)
        elif action_id == 'create_stager':
            ret_val = self._handle_create_stager(param)
        elif action_id == 'get_stager':
            ret_val = self._handle_get_stager(param)
        elif action_id == 'list_stagers':
            ret_val = self._handle_list_stagers(param)
        elif action_id == 'get_listener_options':
            ret_val = self._handle_get_listener_options(param)
        elif action_id == 'create_listener':
            ret_val = self._handle_create_listener(param)
        elif action_id == 'get_listener':
            ret_val = self._handle_get_listener(param)
        elif action_id == 'list_listeners':
            ret_val = self._handle_list_listeners(param)
        elif action_id == 'kill_listener':
            ret_val = self._handle_kill_listener(param)
        return ret_val

    def finalize(self):

        # Save the state, this data is saved accross actions and app upgrades
        self.save_state(self._state)
        return phantom.APP_SUCCESS


if __name__ == '__main__':

    import sys
    import pudb
    import argparse

    pudb.set_trace()

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if (username is not None and password is None):

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if (username and password):
        try:
            print ("Accessing the Login page")
            r = requests.get("https://127.0.0.1/login", verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = 'https://127.0.0.1/login'

            print ("Logging into Platform to get the session id")
            r2 = requests.post("https://127.0.0.1/login", verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print ("Unable to get session id from the platfrom. Error: " + str(e))
            exit(1)

    if (len(sys.argv) < 2):
        print "No test json specified as input"
        exit(0)

    with open(sys.argv[1]) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = EmpireConnector()
        connector.print_progress_message = True

        if (session_id is not None):
            in_json['user_session_token'] = session_id

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print (json.dumps(json.loads(ret_val), indent=4))

    exit(0)
