#!/usr/bin/python3

from sys import argv

# ============================ CLI ARGUMENTS HELPERS ============================
def print_usage():
	print("TO IMPLEMENT HELP")


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
	
def print_config(args):
	print("Toma will load with this configuration:")
	for k,v in args.items():
		print(f"{k} =====> {v}")

# =============================================================================






# ============================ MAIN FUNCTION ============================

if __name__ == '__main__':
	args = parse_argv(argv)
	print_config(args)