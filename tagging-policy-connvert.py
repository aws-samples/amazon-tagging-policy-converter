# -*- coding: utf-8 -*-
#
# @Time: 2022/04/23
#
# @update: 2022/07/21
# @File: tagging-policy-convert.py

"""
This script is used to convert tagging policies to
IAM policies and able to enfore tags in the policies if required.
"""
from optparse import OptionParser
import os
import json
import jsonpath
import string
import random
import copy
import re



# tag key sensitive
CASE_SEN_BASE = {
"Sid": "",
"Effect": "Deny",
"Action": [],
"Resource": [],
"Condition": {
    "ForAllValues:StringNotEquals": {
        "aws:TagKeys": ""
    },
    "Null": {}
}
}
# tag value restrict
VALUE_RSTRICT_BASE = {
    "Sid": "",
    "Effect": "Deny",
    "Action": [],
    "Resource": [],
    "Condition": {
        "StringNotLike": {},
        "Null": {}
    }
}
# tag must have
TAG_MUST_HAVE_BASE={
"Sid": "",
"Effect": "Deny",
"Action": [],
"Resource": [],
"Condition": {
    "Null": {}
}
}

MANAGED_POLICY_LIMIT = 6144

# GET all letters + numbers
#letters_numbers = string.ascii_letters + string.digits
letters_numbers = string.digits
# length of the random string
rand_len = 4

def get_str_length(policy):
    """
    Caculate the number of character for a given string.
    The permission boundary policy can't exceed 6144 characters.
    """
    str_policy  = str(policy).split(' ')
    num = 0
    for alpha in str_policy:
        num = num + len(alpha)

    return num

if __name__ == '__main__':
    usage = "Usage: \n%prog -f TaggingPolicyFileLocation -e true/false[default is false]"

    parser = OptionParser(usage,version='%prog 1.0') 


    parser.add_option('-f','--TagPolicyFile',  
                      help='interaction Tagging Policy file location: [example: ./tagging-policy-01.json]')  
    parser.add_option('-e','--enforce',  
                      help='interaction if tag enforcement is required: [example: true]')  

    options, args = parser.parse_args()
    #print(options)
    if not options.TagPolicyFile:
        parser.error("you must input option, {} -h for more detail".format(os.path.basename(__file__)))
        exit(1)
    tag_file = options.TagPolicyFile
    try:
        with open (tag_file, "r", encoding="utf-8") as jsonfile:
            file = json.load(jsonfile)
    except FileNotFoundError as e:
        print(e)
        exit(1)
    except Exception as e:
        print("File {0} is not in vaild json format!!\n{1}".format(tag_file,str(e)))
        exit(1)
    # check if the json is compliance with tagging policy format (tags) 
    if not jsonpath.jsonpath(file, '$.tags') or type(file["tags"]) != dict:
        raise(ValueError('{} is not in proper tagging policy format'.format(tag_file)))
    else:
        policy_base_document_json = {"Version": "2012-10-17", "Statement": []}
        for key, value in file.get('tags').items():
            # if there is no enforced_for section in the 
            # tagging policy, the policy is not effective.
            if not jsonpath.jsonpath(value, '$.enforced_for') or \
                jsonpath.jsonpath(value, '$.enforced_for') and not value["enforced_for"].get("@@assign"):
                print(f'{key} does not contain enforce resource or enforce resource does not contain value, \
                skip this tag policy.')
                continue
            else:
                policy_action_list = []
                policy_resource_list = []
                policy_service_list = []
                policy_action_enforce_list = []
                service_name = None
                resource_name = None
                ## handle the policy action, policy resource and enforce policy action
                try:
                    for resource_value in jsonpath.jsonpath(value, '$.enforced_for')[0]['@@assign']:
                        service_name = resource_value.split(":")[0]
                        resource_name = resource_value.split(":")[1]
                        policy_service_list.append(service_name)
                        policy_resource_list.append("arn:aws-cn:{}:*:*:{}/*"\
                            .format(service_name, resource_name))
                        # handle the ec2:instance 
                        if resource_value.split(":")[0] == "ec2" and resource_value.split(":")[1] == "instance":
                            policy_action_enforce_list.append ("{}:run{}*"\
                                .format(service_name,resource_name))
                        # elif resource_value.split(":")[0] == "ec2" and resource_value.split(":")[1] == "volume":
                        else:
                           policy_action_enforce_list.append ("{}:create{}*"\
                                .format(service_name,resource_name))
                    for policy_service in set(policy_service_list):
                        policy_action_list.append(f"{policy_service}:CreateTags")
                    # if tag_key exits in the tagging policy
                    if jsonpath.jsonpath(value, '$.tag_key'):
                        random_sid_sufix = "".join(random.choices(letters_numbers, k=rand_len))
                        case_sensitive_policy = copy.deepcopy(CASE_SEN_BASE)
                        case_sensitive_policy["Sid"] = "CaseSen{0}{1}".format(key,random_sid_sufix).replace(" ", "")
                        case_sensitive_policy["Action"] = policy_action_list
                        case_sensitive_policy["Resource"] = policy_resource_list
                        case_sensitive_policy["Condition"]["ForAllValues:StringNotEquals"]["aws:TagKeys"] = key
                        case_sensitive_policy["Condition"]["Null"][f"aws:RequestTag/{key}"] = "false"
                        policy_base_document_json["Statement"].append(case_sensitive_policy)
                    # if tag_value exits in the tagging policy
                    if jsonpath.jsonpath(value, '$.tag_value'):
                        random_sid_sufix = "".join(random.choices(letters_numbers, k=rand_len))
                        value_restrict_policy = copy.deepcopy(VALUE_RSTRICT_BASE)
                        value_restrict_policy["Sid"] = "Restrict{0}{1}".format(key,random_sid_sufix).replace(" ", "")
                        value_restrict_policy["Action"] = policy_action_list
                        value_restrict_policy["Resource"] = policy_resource_list
                        value_restrict_policy["Condition"]["StringNotLike"][f"aws:RequestTag/{key}"] = jsonpath.jsonpath(value, '$.tag_value')[0]\
                                                                                                        .get("@@assign")
                        value_restrict_policy["Condition"]["Null"][f"aws:RequestTag/{key}"] = "false"
                        policy_base_document_json["Statement"].append(value_restrict_policy)
                    # if tag enforcement is required
                    if options.enforce and re.match("true",options.enforce,flags=re.IGNORECASE):
                        # if len(policy_action_enforce_list) < len(policy_resource_list):
                        #     print("Currently we only support EC2 instance and volume enforce tag convert, exit...")
                        #     exit(1)
                        random_sid_sufix = "".join(random.choices(letters_numbers, k=rand_len))
                        enforce_tag_policy = copy.deepcopy(TAG_MUST_HAVE_BASE)
                        enforce_tag_policy["Sid"] = "TagMust{0}{1}".format(key,random_sid_sufix).replace(" ", "")
                        enforce_tag_policy["Resource"] = policy_resource_list
                        enforce_tag_policy["Action"] = policy_action_enforce_list
                        enforce_tag_policy["Condition"]["Null"][f"aws:RequestTag/{key}"] = "true"
                        policy_base_document_json["Statement"].append(enforce_tag_policy)
                except TypeError as e:
                    print('{} is not in proper tagging policy format'.format(tag_file))
                    exit(1)

        policy_length = get_str_length(policy_base_document_json)
        # check if there is policy statement exits in the policy
        if not policy_base_document_json["Statement"]:
            raise(ValueError('{} either does not contain effective tag policy or not in proper tagging policy format'.format(tag_file)))

        # check if the policy length exceeds the max size.
        if policy_length > MANAGED_POLICY_LIMIT:
            print("Error: The size of the policy is {} which is greater than policy max size {}.\
                Please reduce the tag key numbers and try it again."\
                .format(policy_length, MANAGED_POLICY_LIMIT))
            while input("Do You still Want To export the IAM policy file? [y/n]") == "y":
                break
            else:
                exit(1)
        OUT_FILE = "{}-IAMBased.json".format(tag_file.split("/")[-1].split(".")[0])
        # check if tag enforcement is required.
        if options.enforce and re.match("true",options.enforce,flags=re.IGNORECASE):
            OUT_FILE = "{}-IAMBased-TagEnforce.json".format(tag_file.split("/")[-1].split(".")[0])
        with open ( OUT_FILE, "w", encoding="utf-8") as wf:
            json.dump(policy_base_document_json, 
                    wf,
                    indent=2,
                    ensure_ascii=False
                    )
        print("Mission Completed, please check the output file: {}, policy size {}".format(OUT_FILE, policy_length))

