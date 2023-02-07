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
			"sec_std" : "Default",
			"output_filename" : ""}
			
	for i in range(len(argv)):
		match(argv[i]):
			case "toma.py":
				pass
			case "--help" | "-h" :
				print_usage()
				exit(0)
			case "--file" | "-f":
				print("[DBG] CASE --file triggered")
				# need to store the next item
				if i+1 < len(argv):
					args["resource_spec"] = argv[i+1]
				else:
					print("[ERROR] Config filename not specified.")
					exit(1)
			case "--score" | "-s":
				print("[DBG] CASE --score triggered")
				args["score"] = True
			case "--autofix" | "-a":
				print("[DBG] CASE --autofix triggered")
				args["autofix"] = True
			case "--enforce" | "-e":
				print("[DBG] CASE --enforce triggered")
				args["enforce"] = True
			case "--security-standard" | "-t":
				print("[DBG] CASE --security-standard triggered")
				if i+1 < len(argv):
					args["sec_std"] = argv[i+1]
				else:
					print("[ERROR] Security standard not specified.")
					exit(1)
			case "--output" | "-o":
				print("[DBG] CASE --output triggered")
				if i+1 < len(argv):
					args["output_filename"] = argv[i+1]
				else:
					print("[ERROR] Output filename not specified.")
					exit(1)
			case _:
				print(f"[INFO] Argument {argv[i]} not recognized.")
	return args
	
# =============================================================================

# ============================ PRINTING HELPERS ============================
def print_usage():
	print("TO IMPLEMENT HELP")

def print_error(error):
	block = "[ERROR] "
	print(block, error)

def print_debug(dbg):
	block = "[DEBUG] "
	print(block, dbg)
	
def print_notify(msg):
	block = "[*] "
	print(msg, block)
	
def print_separator(string):
	n = 50
	m = int(n/2)
	print('=' * m, string, '=' * m)

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
			print_notify("Successfully opened YAML file.")
			try:
				yaml_doc = yaml.load(file_obj, Loader=yaml.Loader)
				print_notify("Successfully loaded YAML file.")
			except yaml.YAMLError as e:
				print_error("YAML file not correctly loaded.")
				exit(1)
	except FileNotFoundError as e:
			print_error("YAML file not found.")
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

# ============================ MAIN FUNCTION ============================

if __name__ == '__main__':
	# program start
	cli_args = parse_argv(argv)
	print_separator("CLI ARGS")
	print_config(cli_args)
	print_separator("")
	
	# import YAML files
	resource_spec = import_yaml(cli_args["resource_spec"])
	pod_spec = find_podspec(resource_spec)
	
	# print to tty
	print_separator("RESOURCE SPEC")
	print_config(resource_spec)
	print_separator("POD SPEC")
	
	