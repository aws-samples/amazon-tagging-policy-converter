# Tagging Policy convertor

This repo is used to convert tagging policies to
IAM policies and able to enforce tags in the policies if required.


## Repo Structure
* tagging-policy-connvert.py  <= This is the script for converting tagging policies to IAM policies and also could be enforce tags if required.
* requirements.txt <= python module required.
* samples <= an exmaple tagging policy

## User Guide
* install required python3 lib
```
pip install -r requirements.txt
```
* script help usage 
```
tagging-policy-connvert.py -h
Usage: 
tagging-policy-connvert.py -f TaggingPolicyFileLocation -e true/false[default is false]

Options:
  --version             show program's version number and exit
  -h, --help            show this help message and exit
  -f TAGPOLICYFILE, --TagPolicyFile=TAGPOLICYFILE
                        interaction Tagging Policy file location: [example:
                        ./tagging-policy-01.json]
  -e ENFORCE, --enforce=ENFORCE
                        interaction if tag enforcement is required: [example:
                        true]
```

* Only convert tagging policy, not enforcing tags 
```
tagging-policy-connvert.py -f sample/test-tagging-policy.json
Mission Completed, please check the output file: test-tagging-policy-IAMBased.json, policy size 806
```

* Convert tagging policy and enforcing tags
```
python3 tagging-policy-connvert.py -f samples/test-tagging-policy.json -e true
Mission Completed, please check the output file: test-tagging-policy-IAMBased-TagEnforce.json, policy size 1232
```

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the LICENSE file.

