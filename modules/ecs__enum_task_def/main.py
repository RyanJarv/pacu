#!/usr/bin/env python3
from botocore.exceptions import ClientError

import argparse
import os
import json

from pacu.aws import get_boto3_client
from pacu.io import print

module_info = {
    # Name of the module (should be the same as the filename)
    'name': 'ecs__enum_task_def',

    # Name and any other notes about the author
    'author': 'Nicholas Spagnola of Rhino Security Labs',

    # Category of the module. Make sure the name matches an existing category.
    'category': 'ENUM',

    # One liner description of the module functionality. This shows up when a user searches for modules.
    'one_liner': 'Parses task definitions from ECS tasks',

    # Description about what the module does and how it works
    'description': 'This module will pull task definitions for ECS clusters.',

    # A list of AWS services that the module utilizes during its execution
    'services': ['ECS'],

    # For prerequisite modules, try and see if any existing modules return the data that is required for your module before writing that code yourself, that way, session data can stay separated and modular.
    'prerequisite_modules': ['ecs__enum'],

    # Module arguments to autocomplete when the user hits tab
    'arguments_to_autocomplete': ['--task_definitions'],
}

parser = argparse.ArgumentParser(add_help=False, description=module_info['description'])
parser.add_argument('--task_definitions',required=False,default=None,help='A comma separated list of ECS task defintion ARNs (arn:aws:ecs:us-east-1:273486424706:task-definition/first-run-task-definition:latest)')

def main(args, pacu_main):
    session = pacu_main.session

    ###### Don't modify these. They can be removed if you are not using the function.
    args = parser.parse_args(args)

    fetch_data = pacu_main.fetch_data
    ######

    task_definitions = []
    summary_data = {"task_definitions": 0}

    if args.task_definitions is not None:
        for task_def in args.task_definitions.split(','):
            task_definitions.append({
                'Task Defintion ID': task_def
            })
    else:
        if fetch_data(['ECS', 'TaskDefinitions'], module_info['prerequisite_modules'][0], '--taskdef') is False:
            print('Pre-req module not run successfully. Exiting...')
            return None
        task_definitions = session.ECS['TaskDefinitions']

    if not os.path.exists('sessions/{}/downloads/ecs_task_def_data/'.format(session.name)):
        os.makedirs('sessions/{}/downloads/ecs_task_def_data/'.format(session.name))

    if task_definitions:
        print("Targeting {} task definition(s)...".format(len(task_definitions)))

        for task_def in task_definitions:
            region = task_def.split(':')[3]
            client = get_boto3_client('ecs', region)

            try:
                task_def_data = client.describe_task_definition(
                    taskDefinition=task_def,
                )
            except ClientError as error:
                code = error.response['Error']['Code']
                print('FAILURE: ')
                if code == 'AccessDenied':
                    print('  Access denied to DescribeTaskDefinition.')
                    print('Skipping the rest of the task definitions...')
                    break
                else:
                    print('  ' + code)
            
            formatted_data = "{}@{}\n{}\n\n".format(
                task_def,
                region,
                json.dumps(task_def_data['taskDefinition'], indent=4)
            )
           
            with open('sessions/{}/downloads/ecs_task_def_data/all_task_def.txt'.format(session.name), 'a+') as data_file:
                data_file.write(formatted_data)
            with open('sessions/{}/downloads/ecs_task_def_data/{}.txt'.format(session.name, task_def.split('/')[1].split(':')[0]), 'w+') as data_file:
                data_file.write(formatted_data.replace('\\t', '\t').replace('\\n', '\n').rstrip())
            summary_data['task_definitions'] += 1

    return summary_data

def summary(data, pacu_main):
    session = pacu_main.session

    output = '  ECS Task Definition Data for {} task definition(s) was written to ./sessions/{}/downloads/ecs_task_def_data/'.format(data['task_definitions'],session.name)
    return output