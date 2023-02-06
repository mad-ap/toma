#!/usr/bin/python3

from sys import argv
from os.path import *
import yaml

# ============================ CLI ARGUMENTS HELPERS ============================
def print_usage():
	print("TO IMPLEMENT HELP")

def print_error(error):
	block = "[ERROR] "
	print(block, error)

def print_debug(dbg):
	block = "[DEBUG] "
	print(block, dbg)

def parse_argv(argv):
	print("[DBG] In parse_argv: argv:", argv)
	args = {"config_file" : "",
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
					args["config_file"] = argv[i+1]
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

# ============================ YAML HELPERS ============================
def import_yaml_dict(filename):
	yaml_dict = {}
	try:
		with open(filename, 'r') as file_obj:
			try:
				yaml_dict = yaml.load(file_obj, Loader=yaml.Loader)
			except yaml.YAMLError as e:
				print_error("Configuration file not correctly loaded.")
				exit(1)
	except FileNotFoundError as e:
			print_error(e)
			exit(1)
	return yaml_dict
# =======================================================================

def print_config_dict(elem, depth):
	for k,v in elem.items():
		if isinstance(v, dict):
			print('\t' * depth, f"{k}: ")
			print_config_dict(v, depth+1)
		elif isinstance(v, list):
			print('\t' * depth, f"{k}: ")
			print_config_list(v, depth+1)
		else:
			print('\t' * depth, f"{k}: {v}")
	return

def print_config_list(elem, depth):
	for i in range(len(elem)):
		if isinstance(elem[i], dict):
			print('\t' * depth, f"{elem[i]}: ")
			print_config_dict(elem[i], depth+1)
		elif isinstance(elem[i], list):
			print('\t' * depth, f"{elem[i]}: ")
			print_config_list(v, depth+1)
		else:
			print('\t' * depth, f"- {elem[i]}")
	return

def print_config(config, depth):
	if isinstance(config, dict):
		print_config_dict(config, depth)
	elif isinstance(config, list):
		print_config_list(config, depth)
	else:
		print_error("Configuration not supported")
	return

# ========================= SPEC & RULES HELPERS ========================

# reads the resourceSpec in order to find the PodSpec
# Deployment  -> DeploymentSpec spec  -> PodTemplateSpec template -> PodSpec spec
# Job         -> JobSpec spec         -> PodTemplateSpec template -> PodSpec spec
# StatefulSet -> StatefulSetSpec spec -> PodTemplateSpec template -> PodSpec spec
def import_podspec(filename):
	resource_spec = import_yaml_dict(filename)
	
	if not isinstance(resource_spec, dict):
		print_error("Resource not recognized")
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
			print_error("Resource not recognized")
			exit(1)
	except KeyError as e:
		print_error("Spec is missing some important fields.")
		
	return pod_spec
# =======================================================================

# ============================ MAIN FUNCTION ============================

if __name__ == '__main__':
	# program start
	args = parse_argv(argv)
	print_config(args, 0)
	
	# import YAML files
	podspec = import_podspec(args["config_file"])
	
	#rules = import_rules()
	print_config(podspec, 0)
	config = import_yaml_dict(args["config_file"])
	