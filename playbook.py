import phantom.rules as phantom
import json
from datetime import datetime, timedelta

def on_start(container):
    
    # call 'decision_2' block
    decision_2(container)
    # call 'decision_3' block
    decision_3(container)
    # call 'domain_reputation' block
    domain_reputation(container)
    # call 'create_ticket' block
    create_ticket(container)
    # call 'decision_7' block
    decision_7(container)

    return

def decision_2(container, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.fileHash", "!=", "null"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        file_reputation(container, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def decision_3(container, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.requestURL", "!=", "null"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_url(container, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)
        url_reputation(container, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def detonate_url(container, filtered_artifacts=None, filtered_results=None):

    parameters = []

    if parameters:
        phantom.act("detonate url", parameters=parameters, callback=update_ticket_2, name="detonate_url")    
    
    return

def domain_reputation(container, filtered_artifacts=None, filtered_results=None):

    # collect data for 'domain_reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.sourceDnsDomain', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'domain_reputation' call
    for container_item in container_data:
        parameters.append({
            'domain': container_item[0],
            # context (artifact id) is added for action results to be associated with the artifact
            'context':{'artifact_id': container_item[1]},
        })

    if parameters:
        phantom.act("domain reputation", parameters=parameters, assets=['opendns_investigate_bh'], callback=decision_4, name="domain_reputation")    
    
    return

def file_reputation(container, filtered_artifacts=None, filtered_results=None):

    # collect data for 'file_reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.fileHash', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'file_reputation' call
    for container_item in container_data:
        parameters.append({
            'hash': container_item[0],
            # context (artifact id) is added for action results to be associated with the artifact
            'context':{'artifact_id': container_item[1]},
        })

    if parameters:
        phantom.act("file reputation", parameters=parameters, assets=['reversinglabs_bh'], callback=decision_6, name="file_reputation")    
    
    return

def decision_4(action, success, container, results, handle, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["domain_reputation:action_result.data.*.security_info.dga_score", ">=", 85],
            ["domain_reputation:action_result.data.*.security_info.rip_score", ">=", 85],
            ["domain_reputation:action_result.data.*.security_info.asn_score", ">=", 85],
        ],
        logical_operator='and')

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        send_email(action, success, container, results, handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def send_email(action, success, container, results, handle, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['action_name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    if parameters:
        phantom.act("send email", parameters=parameters, name="send_email")    
    
    return

def decision_6(action, success, container, results, handle, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        action_results=results,
        conditions=[
            ["file_reputation:action_result.data.*.xref.*.scanner_match", "==", "file_reputation:action_result.data.*.xref.*.scanner_count"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        send_email_2(action, success, container, results, handle, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def send_email_2(action, success, container, results, handle, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['action_name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    if parameters:
        phantom.act("send email", parameters=parameters, name="send_email_2")    
    
    return

def url_reputation(container, filtered_artifacts=None, filtered_results=None):

    # collect data for 'url_reputation' call
    container_data = phantom.collect2(container=container, datapath=['artifact:*.cef.requestURL', 'artifact:*.id'])

    parameters = []
    
    # build parameters list for 'url_reputation' call
    for container_item in container_data:
        parameters.append({
            'url': container_item[0],
            # context (artifact id) is added for action results to be associated with the artifact
            'context':{'artifact_id': container_item[1]},
        })

    if parameters:
        phantom.act("url reputation", parameters=parameters, assets=['virustotal_bh'], callback=update_ticket, name="url_reputation")    
    
    return

def create_ticket(container, filtered_artifacts=None, filtered_results=None):

    parameters = []

    if parameters:
        phantom.act("create ticket", parameters=parameters, name="create_ticket")    
    
    return

def update_ticket(action, success, container, results, handle, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['action_name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    if parameters:
        phantom.act("update ticket", parameters=parameters, name="update_ticket")    
    
    return

def update_ticket_2(action, success, container, results, handle, filtered_artifacts=None, filtered_results=None):
    
    #phantom.debug('Action: {0} {1}'.format(action['action_name'], ('SUCCEEDED' if success else 'FAILED')))

    parameters = []

    if parameters:
        phantom.act("update ticket", parameters=parameters, name="update_ticket_2")    
    
    return

def decision_7(container, filtered_artifacts=None, filtered_results=None):

    # collect filtered artifact ids for 'if' condition 1
    matched_artifacts_1, matched_results_1 = phantom.condition(
        container=container,
        conditions=[
            ["artifact:*.cef.cs6Label", "==", "vault_id"],
        ])

    # call connected blocks if filtered artifacts or results
    if matched_artifacts_1 or matched_results_1:
        detonate_file(container, filtered_artifacts=matched_artifacts_1, filtered_results=matched_results_1)

    return

def detonate_file(container, filtered_artifacts=None, filtered_results=None):

    parameters = []
    
    parameters.append({
        'vault_id': "",
        'file_name': "",
        'vm': "",
        'force_analysis': "",
        'private': "",
    })

    if parameters:
        phantom.act("detonate file", parameters=parameters, assets=['threatgrid_bh'], name="detonate_file")    
    
    return

def on_finish(container, summary):

    # This function is called after all actions are completed.
    # Summary and/or action results can be collected here.

    # summary_json = phantom.get_summary()
    # summary_results = summary_json['result']
    # for result in summary_results:
            # action_run_id = result['id']
            # action_results = phantom.get_action_results(action_run_id=action_run_id)

    return
