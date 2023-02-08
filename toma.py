#!/usr/bin/python3

from sys import argv
from os.path import *
import yaml

# ============================ CLI ARGUMENTS HELPERS ============================
def parse_argv(argv):
	print("[DBG] In parse_argv: argv:", argv)
	args = {"resource_spec" : "",
			"score" : False,
			"autofix" : False,
			"enforce" : False,
			"sec_std" : "default",
			"rules_filename" : "rules.yaml",
			"output_filename" : ""}
			
	for i in range(len(argv)):
		match(argv[i]):
			case "toma.py":
				pass
			case "--help" | "-h" :
				print_usage()
				exit(0)
			case "--file" | "-f":
				# need to store the next item
				if i+1 < len(argv):
					args["resource_spec"] = argv[i+1]
				else:
					print("[ERROR] Config filename not specified.")
					exit(1)
			case "--score" | "-s":
				args["score"] = True
			case "--autofix" | "-a":
				args["autofix"] = True
			case "--enforce" | "-e":
				args["enforce"] = True
			case "--security-standard" | "-t":
				if i+1 < len(argv):
					args["sec_std"] = argv[i+1]
				else:
					print("[ERROR] Security standard not specified.")
					exit(1)
			case "--output" | "-o":
				if i+1 < len(argv):
					args["output_filename"] = argv[i+1]
				else:
					print("[ERROR] Output filename not specified.")
					exit(1)
			case "--rules" | "-r":
				if i+1 < len(argv):
					args["rules_filename"] = argv[i+1]
				else:
					print("[ERROR] Rules filename not specified.")
					exit(1)
			case _:
				pass
	return args

def check_args(args):
	spec_file = args["resource_spec"]
	rules_file = args["rules_filename"]
	
	# resource spec file checks
	if not exists(spec_file) or not isfile(spec_file):
		print_error("Specified resource spec file doesn't exists or it isn't a regular file")
		exit(1)
	# rules file checks
	elif not exists(rules_file) or not isfile(rules_file):
		print_error("Specified rules file doesn't exists or it isn't a regular file")
		exit(1)
	else:
		print_notify("CLI arguments checked.")
	return 
# =============================================================================

# ============================ PRINTING HELPERS ============================
def print_usage():
	print("TO IMPLEMENT HELP")

def print_error(*s):
	error = "[ERROR] "
	for i in range(len(s)):
		error = error + s[i]
	print(error)

def print_debug(*s):
	dbg = "[DEBUG] "
	for i in range(len(s)):
		dbg = dbg + s[i]
	print(dbg)
	
def print_notify(*s):
	msg = "[*] "
	for i in range(len(s)):
		msg = msg + s[i]
	print(msg)
	
def print_separator(*s):
	msg = ""
	for i in range(len(s)):
		msg = msg + s[i]
	n = 60 - len(msg)
	m = int(n/2)
	print('=' * m, msg, '=' * m)

def print_config_dict(elem, depth):
	for k,v in elem.items():
		# first prints the key 
		
		# if finds a dict
		if isinstance(v, dict):
			print('\t' * depth, f"{k}:")
			print_config_dict(v, depth+1)
		# if finds a list
		elif isinstance(v, list):
			print('\t' * depth, f"{k}:")
			print_config_list(v, depth+1)
		# if finds just a value
		else:
			print('\t' * depth, f"{k}: {v}")
	return

def print_config_list(elem, depth):
	for i in range(len(elem)):
		if isinstance(elem[i], dict):
			print_config_dict(elem[i], depth+1)
		elif isinstance(elem[i], list):
			print('\t' * depth, f"{elem[i]}: ")
			print_config_list(v, depth+1)
		else:
			print('\t' * depth, f"- {elem[i]}")
	return

def print_config(config):
	if isinstance(config, dict):
		print_config_dict(config, 0)
	elif isinstance(config, list):
		print_config_list(config, 0)
	else:
		print_error("Configuration not supported")
	return
# ==========================================================================

# ============================ YAML HELPERS ============================
# the resulting object could be a list or dict
def import_yaml(filename):
	yaml_doc = {}
	try:
		with open(filename, 'r') as file_obj:
			print_notify("Successfully opened YAML file: ", filename)
			try:
				yaml_doc = yaml.load(file_obj, Loader=yaml.Loader)
				print_notify("Successfully loaded YAML file: ", filename)
			except yaml.YAMLError as e:
				print_error("YAML file not correctly loaded: ", filename)
				exit(1)
	except FileNotFoundError as e:
			print_error("YAML file not found: ", filename)
			exit(1)
	return yaml_doc
# =======================================================================

# ========================= RESOURCE SPEC HELPERS ========================

# reads the resourceSpec in order to find the PodSpec
# Deployment  -> DeploymentSpec spec  -> PodTemplateSpec template -> PodSpec spec
# Job         -> JobSpec spec         -> PodTemplateSpec template -> PodSpec spec
# StatefulSet -> StatefulSetSpec spec -> PodTemplateSpec template -> PodSpec spec
def find_podspec(resource_spec):
	
	if not isinstance(resource_spec, dict):
		print_error("Resource spec not recognized (it's not a dictionary)")
		exit(1)
	
	pod_spec = {}
	try:
		spec_kind = resource_spec["kind"]
		if spec_kind == "Pod":
			pod_spec = resource_spec["spec"]
		elif spec_kind == "Deployment" or spec_kind == "Job" or spec_kind == "StatefulSet":
			pod_spec = resource_spec["spec"]
			pod_spec = pod_spec["template"]
			pod_spec = pod_spec["spec"]
		else:
			print_error("Resource not recognized (it's not a Pod nor a Deployment, Job or StatefulSet)")
			exit(1)
	except KeyError as e:
		print_error("Spec is missing some important fields.")
		
	return pod_spec
# =======================================================================

# ========================= RULES HELPERS ===============================
def print_rules_list(rules):
	for rule in rules:
		print('\t', rule["field"], " | \t", rule["allowed_values"])

def print_rules(rules):
	#check if it's not a dict exit
	if not isinstance(rules, dict):
		print_error("The rules aren't arranged in a dict.")
		exit(1)
	# iterate over keys and print the rule list
	for sec_std, rule_list in rules.items():
		print_separator("SECURITY STANDARD: ", sec_std)
		print("")
		print_rules_list(rule_list)
		print("")
	print_separator()
	return
	
# drops every rule below the choosen security standard, defaults to the whole
def cut_rules(rules, sec_std):
	found = False
	to_del = []
	for key in rules.keys():
		if found:
			to_del.append(key)
		elif key == sec_std:
				found = True
	for key in to_del:
		del rules[key]
	return

# =======================================================================

# ========================= SCORE HELPERS ===============================
RIGHT_FIELD = 0
MISSING_FIELD = 1
WRONG_FIELD = 2

def contained(string, substring):
	if string.find(substring) < -1:
		return True
	else: 
		return False

# return the field if found, False otherwise
def find_field(pod_spec, field_string):
	fields = field_string.split(sep='.')
	print("in find_field, fields = ", fields)
	target = pod_spec
	try:
		for f in fields:
			target = target[f]
			print("target = ", f)
	except KeyError as e:
		return False
	return target

def check_field_values(field_values, field_allowed_values):
	if isinstance(field_values, list):
		if set(field_values).issubset(set(field_allowed_values)):
			return True
		else:
			return False
	else:
		if field_values in field_allowed_values:
			return True
		else:
			return False

def check_standard_rule(pod_spec, rule):
	field_string = rule["field"]
	field_allowed_values = rule["allowed_values"]
	# if field not present target will be False, otherwise the element
	field_values = find_field(pod_spec, field_string)
	# some rules allows fields to not be defined
	print("field string: ", field_string)
	print("alloed values: ", field_allowed_values)
	print("field  values: ", field_values)
	can_be_nd = "not defined" in rule["allowed_values"]
	print("can be not specified: ", can_be_nd)
	# if not present but can be absent
	if not field_values and can_be_nd:
		return RIGHT_FIELD
	# if not present but required
	elif not field_values and not can_be_nd:
		return MISSING_FIELD
	# if values are correct True, otherwise False
	elif check_field_values(field_values, field_allowed_values) == True:
		return RIGHT_FIELD
	else:
		return WRONG_FIELD

#def check_containers_rule(pod_spec, rule):


def compute_spec_score(pod_spec, rules):
	# prepares score result dict
	score = {}
	for sec_std, rule_list in rules.items():
		score[sec_std] = {"n_total_rules": len(rule_list), "rules_missing": [], "rules_wrong": []}
		rules_missing = score[sec_std]["rules_missing"]
		rules_wrong = score[sec_std]["rules_wrong"]
		
		# checks the rules keeping track of the missing and wrong fields
		result = -1
		for rule in rule_list:
			print_debug("Checking rule: ", rule["field"])
			if contained(rule["field"], "containers[*]"):
				print_debug("It's a container rule")
				result = check_containers_rule(pod_spec, rule)
			else:
				print_debug("It's a standard rule")
				result = check_standard_rule(pod_spec, rule)
			
			if result == MISSING_FIELD:
				print_debug("It's missing.")
				rules_missing.append(rule)
			elif result == WRONG_FIELD:
				print_debug("It's wrong.")
				rules_wrong.append(rule)
			else:
				pass
	
	return score

# =======================================================================

# ============================ MAIN FUNCTION ============================

if __name__ == '__main__':
	# arguments parsing
	cli_args = parse_argv(argv)
	print_separator("CLI ARGS")
	print_config(cli_args)
	check_args(cli_args)
	print_separator("")
	
	# import YAML files
	resource_spec = import_yaml(cli_args["resource_spec"])
	pod_spec = find_podspec(resource_spec)
	rules = import_yaml(cli_args["rules_filename"])
	
	# print to tty
	print_separator("RESOURCE SPEC")
	print_config(resource_spec)
	
	print_separator("POD SPEC")
	print_config(pod_spec)
	
	print_separator("RULES")
	print_rules(rules)
	cut_rules(rules, cli_args["sec_std"])
	print_separator("CUT RULES")
	print_rules(rules)
	
	score = compute_spec_score(resource_spec, rules)
	print_separator("SCORE")
	print("")
	print_config(score)