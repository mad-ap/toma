#! /usr/local/bin/python3

from sys import argv
from os import path, getcwd
import yaml
# comment branch
# ============================ CLI ARGUMENTS HELPERS ============================
def parse_argv(argv):
	args = {"resource_spec" : "",
			"score" : False,
			"autofix" : False,
			"enforce" : False,
			"sec_std" : "default",
			"rules_filename" : "rules.yaml",
			"output_filename" : ""}

	for i in range(len(argv)):
		match (argv[i]):
			case "toma.py":
				pass
			case "--help" | "-h":
				print_usage()
				exit(0)
			case "--file" | "-f":
				# need to store the next item
				if i+1 < len(argv):
					args["resource_spec"] = argv[i+1]
				else:
					print("[ERROR] Resource spec filename not specified.")
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
			# ignores not known parameters
			case _:
				pass
	return args

def check_args(args):
	spec_file = args["resource_spec"]
	rules_file = args["rules_filename"]

	# resource spec file checks
	if not path.exists(spec_file) or not path.isfile(spec_file):
		print_error("Specified resource spec file doesn't exists or it isn't a regular file")
		exit(1)
	# rules file checks
	elif not path.exists(rules_file) or not path.isfile(rules_file):
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
	print('\n', '=' * m, msg, '=' * m, end="\n\n")

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
		print('\t' * depth, "- ")
		if isinstance(elem[i], dict):
			print_config_dict(elem[i], depth+1)
		elif isinstance(elem[i], list):
			print('\t' * depth, f"- {elem[i]}: ")
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

# ============================ STRING HELPERS ============================
def contained(string, substring):
	if string.find(substring) > -1:
		return True
	else:
		return False

def cut_containers_string(field_string):
	guilty = "containers[*]."
	start = field_string.find(guilty)
	return field_string[start + len(guilty):]

# ============================ YAML HELPERS ============================
# load YAML file returning the associated structure
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

# dumps the YAML into the specified output file
def export_yaml(resource_spec, output_filename):
	with open(output_filename, 'w') as output_file_object:
		print_notify("Successfully opened file for writing: ", output_filename)
		try:
			yaml.dump(resource_spec, output_file_object, default_flow_style=False, sort_keys=False)
			print_notify("Successfully saved YAML file: ", output_filename)
		except yaml.YAMLError as error:
			print_error("Problems saving the YAML file: ", output_filename)
			exit(1)
	return

# ========================= RESOURCE SPEC HELPERS ========================

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

def get_containers_spec(pod_spec, field_string):
	fields = field_string.split(sep='.')
	print("in get container spec, fields = ", fields)
	target = pod_spec
	try:
		for f in fields:
			if f == "containers[*]":
				return target["containers"]
			else:
				target = target[f]
				print("target = ", f)
	except KeyError as e:
		return False
	return target

# reads the ResourceSpec and returns the (inner) PodSpec
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
			pod_spec = resource_spec
		elif spec_kind == "Deployment" or spec_kind == "Job" or spec_kind == "StatefulSet":
			pod_spec = resource_spec["spec"]
			pod_spec = pod_spec["template"]
		else:
			print_error("Resource not recognized (it's not a Pod nor a Deployment, Job or StatefulSet)")
			exit(1)
	except KeyError as e:
		print_error("The spec is missing some important fields.")
		exit(1)
	return pod_spec

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
		print_rules_list(rule_list)
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
	if found == False:
		print_error("Security standard not present.")
	return

# =======================================================================

# ========================= SCORE HELPERS ===============================
RIGHT_FIELD = 0
MISSING_FIELD = 1
WRONG_FIELD = 2

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

def classify_field(field_values, rule):
	field_allowed_values = rule["allowed_values"]
	can_be_nd = "not defined" in rule["allowed_values"]

	print("field allowed_values: ", field_allowed_values)
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

def check_standard_rule(pod_spec, rule):
	field_string = rule["field"]
	# if field not present target will be False, otherwise the element
	field_values = find_field(pod_spec, field_string)
	# some rules allows fields to not be defined
	print("field string: ", field_string)
	print("field values: ", field_values)

	return classify_field(field_values, rule)

def check_containers_rule(pod_spec, rule):
	field_string = rule["field"]
	field_allowed_values = rule["allowed_values"]

	# try to navigate until find containers field
	containers_spec = get_containers_spec(pod_spec, field_string)
	n_containers = len(containers_spec)

	print("In checking containers rule")
	print("field string: ", field_string)
	print("allowed_values: ", field_allowed_values)

	n_right_fields = 0
	n_wrong_fields = 0
	n_missing_fields = 0

	# cutting field string after containers[*]
	field_string = cut_containers_string(field_string)
	for c in containers_spec:
		field_values = find_field(c, field_string)
		classification = classify_field(field_values, rule)

		if classification == RIGHT_FIELD:
			n_right_fields += 1
		elif classification == WRONG_FIELD:
			n_wrong_fields += 1
		elif classification == MISSING_FIELD:
			n_missing_fields += 1
		else:
			print_error("Cannot classify field")

	# just if they're all ok they are right
	if n_right_fields == n_containers:
		return RIGHT_FIELD
	# if there are more wrong we consider it wrong
	elif n_wrong_fields > n_missing_fields:
		return WRONG_FIELD
	else:
		return MISSING_FIELD

# computes the score returning a score dictionary
# for every security standard return 3 lists: right, wrong and missing rules
def compute_spec_score(pod_spec, rules):
	# prepares score result dict
	# sec_std = { n_total_rules:
	#			  rules_right: []
	#             rules_missing: []
	#             rules_wrong: [] }
	score = {}
	for sec_std, rule_list in rules.items():
		score[sec_std] = {"n_total_rules": len(rule_list),"rules_right": [], "rules_missing": [], "rules_wrong": []}
		rules_missing = score[sec_std]["rules_missing"]
		rules_wrong = score[sec_std]["rules_wrong"]
		rules_right = score[sec_std]["rules_right"]

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

			if result == RIGHT_FIELD:
				print_debug("It's right.")
				rules_right.append(rule)
			elif result == MISSING_FIELD:
				print_debug("It's missing.")
				rules_missing.append(rule)
			elif result == WRONG_FIELD:
				print_debug("It's wrong.")
				rules_wrong.append(rule)
			else:
				pass

	return score

def print_score(score):
	total_total = 0
	total_missed = 0
	total_wrong = 0
	total_percentage = 0.0

	print_separator("SCORE RESULTS")
	for sec_std, result in score.items():
		# metrics
		total = result["n_total_rules"]
		missed = len(result["rules_missing"])
		wrong = len(result["rules_wrong"])
		percentage = int(((total - missed - wrong) / total) * 100)
		total_total += total
		total_missed += missed
		total_wrong += wrong

		wrong_rules_list = result["rules_wrong"]
		missing_rules_list = result["rules_missing"]
		# printing
		print(f"Security standard: {sec_std}\nThe spec is {percentage}% compliant.")
		print(f"Rules {total} | Wrong {wrong} | Missed {missed}")

		if len(wrong_rules_list) > 0:
			print("\nWrong rules:")
			print_rules_list(wrong_rules_list)
		if len(missing_rules_list) > 0:
			print("\nMissing rules:")
			print_rules_list(missing_rules_list)
		print("")

	total_percentage = int(((total_total - total_missed - total_wrong) / total_total) * 100)
	print(f"In total the spec is {total_percentage}% compliant.")
	print(f"Total rules {total_total} | Total wrong {total_wrong} | Total missed {total_missed}")

# ========================= AUTOFIX HELPERS ===============================

# adds the field with value, in spec
def add_field(spec, field_string, value):
	target = spec
	fields = field_string.split('.')

	print("in add_field with fields: ", fields)
	print("present fields: ")
	i = 0

	# advancing in existing fields
	while i < len(fields[:-1]) and fields[i] in target.keys():
		target = target[fields[i]]
		print(fields[i], " --> ", end='')
		i += 1
	print("")

	print("not present fields: ")
	# advancing in non existing fields creating them
	while i < len(fields[:-1]):
		target[fields[i]] = {}
		target = target[fields[i]]
		print(fields[i], " --> ", end='')
		i += 1
	print("target --> ", target)
	print(fields[i])

	target[fields[i]] = value
	return

def fix_missing_field(resource_spec, rule):
	field_string = rule["field"]
	value = rule["allowed_values"][0]
	print("in fix_missing_field ---> ", field_string, value)

	# if containers[*] rule
	if contained(field_string, "containers[*]"):
		print("it's a container missing rule")
		# first we find the containers field
		containers_spec = get_containers_spec(resource_spec, field_string)
		# then we cut the field string for obtaining the fields to search in the containers
		field_string = cut_containers_string(field_string)

		for container in containers_spec:
			print("container: ", container)
			print("adding missing rule --> ", field_string, value)
			add_field(container, field_string, value)
	# if standard rule
	else:
		print("it's a standard missing rule")
		add_field(resource_spec, field_string, value)

def fix_wrong_field(resource_spec, rule):
	field_string = rule["field"]
	value = rule["allowed_values"][0]
	print("in fix_wrong_field ---> ", field_string, value)

	# if containers[*] rule
	if contained(field_string, "containers[*]"):
		print("it's a container wrong rule")
		# first we find the containers field
		containers_spec = get_containers_spec(resource_spec, field_string)
		# then we cut the field string for obtaining the fields to search in the containers
		field_string = cut_containers_string(field_string)

		for container in containers_spec:
			print("container: ", container)
			print("adding wrong rule --> ", field_string, value)
			add_field(container, field_string, value)
	# if standard rule
	else:
		print("it's a standard wrong rule")
		add_field(resource_spec, field_string, value)

# this will autofix the resource spec dict based on the score result
def fix_spec(resource_spec, score):
	print("In fix_spec")
	for sec_std, result in score.items():
		print("security standard: ", sec_std)
		wrong_rules_list = result["rules_wrong"]
		missing_rules_list = result["rules_missing"]

		for rule in missing_rules_list:
			fix_missing_field(resource_spec, rule)

		for rule in wrong_rules_list:
			fix_wrong_field(resource_spec, rule)

# ========================= ENFORCE HELPERS ===============================

# based on the right rules of the PodSpec, return the associated TracingPolicy structure
def create_policy(score):
	print_debug("In create_policy")
	# grabs policy filenames
	filenames = []
	cwd = getcwd()
	for sec_std_scores in score.values():
		rules_list = sec_std_scores.get("rules_right")
		print("Right rules: ", rules_list)
		for rule in rules_list:
			policy_filename = rule.get("policy")
			if policy_filename is not None:
				policy_filename = cwd + '/' + policy_filename
				filenames.append(policy_filename)
	print("POLICY FILENAMES: ", filenames)
	# open every policy filename and takes kprobes
	kprobes = []
	for policy_filename in filenames:
		policy_kprobes = import_yaml(policy_filename)
		policy_kprobes = policy_kprobes.get("kprobes")
		if policy_kprobes is not None:
			print("kprobes to be added: ", policy_kprobes)
			# if we find multiple kprobes we concatenate
			if isinstance(policy_kprobes, list):
				print_notify("KPROBES ARE A LIST")
				kprobes += policy_kprobes
			#if we find a single kprobe we append
			else:
				kprobes.append(policy_kprobes)
		else:
			print_error("Policy ", policy_filename, "doesn't have the field kprobes")
	print_separator("KPROBES")
	for kp in kprobes:
		print(kp)

	print_config(kprobes)
	# add to list and return
	tracing_policy = {}
	tracing_policy["apiVersion"] = "cilium.io/v1alpha1"
	tracing_policy["kind"] = "TracingPolicy"
	tracing_policy["metadata"] = {"name": "toma-generated-tracingpolicy"}
	tracing_policy["spec"] = {"kprobes": []}
	tracing_policy["spec"]["kprobes"] = kprobes
	return tracing_policy

# ============================ MAIN FUNCTION ============================

if __name__ == '__main__':
	cli_args = {}
	if len(argv) < 2:
		print_usage()
		exit(0)
	else:
		# arguments parsing
		cli_args = parse_argv(argv[1:])
		print_separator("CLI ARGS")
		print_config(cli_args)
		check_args(cli_args)
		print_separator("")

	# import YAML files
	print_notify("Loading resource spec file...")
	resource_spec = import_yaml(cli_args["resource_spec"])
	pod_spec = find_podspec(resource_spec)
	print_notify("Loading rules file...")
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

	scorer = cli_args["score"]
	score = compute_spec_score(pod_spec, rules)
	if scorer:
		print_separator("SCORE")
		print("")
		print_config(score)
		print_score(score)

	autofix = cli_args["autofix"]
	output_filename = cli_args["output_filename"]
	if autofix:
		fixed_pod_spec = fix_spec(pod_spec, score)

		if output_filename != "":
			print_notify("Saving fixed resource spec to: ", output_filename)
			export_yaml(resource_spec, output_filename)
		else:
			print_config(resource_spec)

	enforce = cli_args["enforce"]
	if enforce:
		policy = create_policy(score)
		print_config(policy)
		print_notify("Saving enforce policy to: ", output_filename)
		export_yaml(policy, output_filename)
