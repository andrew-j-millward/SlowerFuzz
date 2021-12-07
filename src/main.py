import sys

sys.path.append('../')
sys.path.append('../FTS')
sys.path.append('../fuzzing')
sys.path.append('../slowfuzz')
sys.path.append('../woff')
import argparse, random, math, os, shutil, signal
from subprocess import STDOUT, TimeoutExpired
from time import sleep
from subprocess import Popen, PIPE, run


#methods for libFuzzer
def initializeEnv(name):
	"""
	Method to take a environment name and attempt to set it up using the setup shell script we provided.
	Each setup script is very simple and needs no explanation as it is documented in libFuzzer itself.
	"""

	# Check if environement is already set up
	if not os.path.isdir('../' + name + '_tmp'):

		# Run process to execute script
		shellStream = os.popen('sh libFuzzerSetup/setup_' + name + '.sh')
		out = shellStream.read()

		# Print output
		print(out)

	# Environment is already setup, so no execution necessary
	else:
		print('Environment already set up... Continuing...')


def runLibFuzzer(name, timeout_period, seeds=[1], verbose=False):
	"""
	Method to run libFuzzer on a given set of seeds for a specific number of iterations (timeout_period).
	The run statistics will be aggregated and output in terms of coverage and memory since those are
	the statistics of interest of libFuzzer.
	"""

	coverage = {}
	memory = {}

	# Run for every seed
	for i in range(len(seeds)):

		# Generate subprocess to execute binary with given parameters
		subpro = run('../' + name + '_tmp/' + str(name) + '-fsanitize_fuzzer -seed=' + str(seeds[i]) + ' -runs=' + str(
			timeout_period), stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)

		# Split output of subprocess
		output = subpro.stderr.split('\n')

		# Extract the last mention of coverage's value
		for j in range(len(output)):
			if 'cov:' in output[-j - 1]:
				parsed1 = output[-j - 1].split('cov: ')
				parsed2 = parsed1[1].split(' ft:')
				coverage[seeds[i]] = int(parsed2[0])
				break

		# Extract the last mention of rss's (memory) value
		for j in range(len(output)):
			if 'rss: ' in output[-j - 1]:
				parsed1 = output[-j - 1].split('rss: ')
				parsed2 = parsed1[1].split('Mb')
				memory[seeds[i]] = int(parsed2[0])
				break
	if verbose:
		print(coverage, memory)
	return coverage, memory

def runOptimization(depth, path, time, seeds, range_dict, libfuzzer, verbose=False):
	"""
	Method for computing the optimal seed. Given a specific number of iterations and seeds
	to test, find the best seed for a given coverage and return that seed and the records.
	"""

	coverage_records = {}

	# Iterate through all generations
	for i in range(depth):

		# If we are using libFuzzer, run the libFuzzer method
		if libfuzzer: 
			coverage, memory = runLibFuzzer(path, time, seeds, verbose)
		
		# If we are using SlowFuzz, run the SlowFuzz method
		else: 
			coverage = runSlowFuzz(path, time, seeds, verbose)

		# Grab coverage records
		coverage_records = {**coverage_records, **coverage}

		# Refine seeds with specialized method
		seeds, range_dict = refineSeeds(range_dict, coverage)

	# Grab maximum seed
	optimal_seed = max(coverage_records, key=coverage_records.get)

	# Return best seed
	return optimal_seed, coverage_records


#methods for slowFuzz
def runSlowFuzz(name, timeout_period, seeds=[1], verbose=False):
	"""
	Method to run SlowFuzz with a set of seeds and specified number of iterations.
	The slowdown of each seed will be returned in a results dict (slowdown).
	"""
	# dictionary to store the slowdown for each seed operated on 
	slowdown = {}
	# running slowFuzz with seed
	for i in range(len(seeds)):
		# running shell command
		output = run("""
				./driver corpus -artifact_prefix=out -print_final_stats=1 \
				-detect_leaks=0 -rss_limit_mb=10000 -shuffle=0 \
				-runs={0} -max_len=64 -death_node=1 \
				-seed={1}
				""".format(timeout_period, seeds[i]), stdout=PIPE, stderr=PIPE, shell=True, universal_newlines=True)
		# taking output and splitting by line
		output = output.stderr.split('\n')
		for j in range(len(output)):
			#find line that contains output value of interest
			if 'slowest_unit_time_sec:' in output[-j - 1]:
				# split line to find slowdown score
				parsed1 = output[-j - 1].split('slowest_unit_time_sec: ')
				slowdown[seeds[i]] = int(parsed1[1])
				break
	if verbose:
		print(slowdown)
	# return slowdown dict
	return slowdown

def refineSeeds(range_dict, coverage):
	"""
	Method which takes a mapping of seeds to a range of potential values and a mapping of seeds to their 
	respective score. The scores are sorted with the top 5 seeds kept. 5 new seeds are generated for
	each of the 5 optimal ones. The new seeds are returned along with new lower and upper bounds for
	optimizations of each seed.
	"""
	# take the top 5 seeds based on score
	optimal_seeds = sorted(coverage, key=coverage.get)[-5:]
	new_seeds = []
	new_range_dict = {}
	
	for i in range(5):
		tmp_range_block = []
		if optimal_seeds[i] not in range_dict: continue
		
		# obtain lower and upper bounds for the current seed to which new seeds can be generated
		lower = range_dict[optimal_seeds[i]][0]
		upper = range_dict[optimal_seeds[i]][1]
		
		# select 5 random seeds in this range for the optimal seed
		for j in range(5):
			new_seeds.append(random.randint(lower, upper))
			# store the recently added seed
			tmp_range_block.append(new_seeds[-1])
		
		#sort the seeds added this iteration
		tmp_range_block = sorted(tmp_range_block)
		
		# add the first seed range to be lower and the smaller of the average of the smallest 2 seeds and the upper boundary
		seed_ranges = [(lower, min(math.ceil((tmp_range_block[0] + tmp_range_block[1]) / 2), upper))]
		
		# adding 3 additional seed ranges, max of lower and the upper of the most recently added range to the min of upper 
		# and the average of the most recent added ranges
		for j in range(1, 4):
			seed_ranges.append((max(lower, seed_ranges[-1][1] + 1),
								min(math.ceil((tmp_range_block[j] + tmp_range_block[j + 1]) / 2), upper)))
		# add the final seed range
		seed_ranges.append((seed_ranges[-1][1] + 1, upper))
		
		# add these ranges to the result range dictionary
		for i in range(len(tmp_range_block)):
			new_range_dict[tmp_range_block[i]] = seed_ranges[i]
	return new_seeds, new_range_dict

def initializeSeeds(seeds):
	"""
	Method to create an initial array of seeds and ranges for which their ancestors can be in. Takes in a number of initial seeds and returns
	an array of seeds, an array of seed ranges, and a dictionary that maps the range to each specific seed.
	"""
	# initial random numbers for seeds
	seeds = sorted([random.randint(1, 9999999999) for i in range(seeds)])
	# initial seed range is 1 to the average of the first 2 seeds 
	seed_ranges = [(1, min(math.ceil((seeds[0] + seeds[1]) / 2), 9999999999))]
	
	# calculate the seed ranges for each seed
	for i in range(1, len(seeds) - 1):
		seed_ranges.append(
			(max(1, seed_ranges[i - 1][1] + 1), min(math.ceil((seeds[i] + seeds[i + 1]) / 2), 9999999999)))
	seed_ranges.append((seed_ranges[-1][1] + 1, 9999999999))
	
	# create dict to map ranges to seeds
	range_dict = {seeds[i]: seed_ranges[i] for i in range(len(seeds))}
	return seeds, seed_ranges, range_dict

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='This script optimizes evolutionary fuzzing by introducing structured randomness and eliminating inefficient paths early on.',
		formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-d', '--depth', type=int, metavar='', help='Number of elimination rounds',
						default=5)
	parser.add_argument('-e', '--explorationdepth', type=int, metavar='',
						help='Once the fuzzing heuristic completes, now explore the best seed obtained',
						default=3750000)
	parser.add_argument('-t', '--time', type=int, metavar='',
						help='Maximum exploration steps before analyzing the results',
						default=10000)
	parser.add_argument('-s', '--seeds', type=int, metavar='', help='Number of seeds per elimination round',
						default=25)
	parser.add_argument('-c', '--carryOver', type=int, metavar='',
						help='Number of seed ranges to carry over to the next round',
						default=25)
	parser.add_argument('-p', '--path', type=str, metavar='',
						help='Path to target. I.e. input "woff2-2016-05-06" will lead to ..FTSwoff2-2016-05-06',
						default='woff2-2016-05-06')
	parser.add_argument('-l', '--libfuzzer', action='store_true', help='Use libFuzzer instead for coverage testing')
	parser.add_argument('-b', '--build', type=str, metavar='', help='Path to build file for SlowFuzz implementation',
						default='isort')
	parser.add_argument('-v', '--verbose', action='store_true', help='Print debugging information')

	args = parser.parse_args()

	# Generate initial seeds
	seeds, seed_ranges, range_dict = initializeSeeds(args.seeds)
	if args.verbose:
		print(seeds, seed_ranges, range_dict)

	# If we are testing on libFuzzer instead of slowFuzz directly...
	if args.libfuzzer:

		if args.verbose:
			print('Running using traditional libFuzzer...')
			print('Using path: ' + args.path)

		tests = ['boringssl-2016-02-12', 'c-ares-CVE-2016-5180', 'freetype2-2017', 'guetzli-2017-3-30',
				 'harfbuzz-1.3.2', 'json-2017-02-12', 'lcms-2017-03-21', 'libarchive-2017-01-04',
				 'libjpeg-turbo-07-2017', 'libpng-1.2.56', 'libssh-2017-1272', 'libxml2-v2.9.2',
				 'llvm-libcxxabi-2017-01-27', 'openssl-1.0.1f', 'openssl-1.0.2d', 'openssl-1.1.0c',
				 'openthread-2018-02-27', 'pcre2-10.00', 'proj4-2017-08-14', 're2-2014-12-09', 'sqlite-2016-11-14',
				 'vorbis-2017-12-11', 'woff2-2016-05-06', 'wpantund-2018-02-27']
		debug_test = ['woff']

		# Initialize and Run
		if args.path == 'clean':
			if args.verbose:
				print('Reset branch triggered... Removing all testing environments')
			for i in range(len(tests)):
				if os.path.isdir('../' + tests[i] + '_tmp'):
					shutil.rmtree('../' + tests[i] + '_tmp')
		elif args.path in tests or args.path in debug_test:
			if args.path in tests:
				initializeEnv(args.path)
			# obtain optimized results from the initial seeds
			optimal_seed, coverage_records = runOptimization(args.depth, args.path, args.time, seeds,
						range_dict, args.libfuzzer, verbose=args.verbose)
			if args.verbose:
				print("Optimal seed {0} obtained, yielding coverage {1} after {2} iterations.".format(optimal_seed,
						coverage_records[optimal_seed], args.time))
			# obtain the results from the optimized seed
			coverage, memory = runLibFuzzer(args.path, args.explorationdepth, seeds=[optimal_seed],
						verbose=args.verbose)
			if args.verbose:
				print(
					"Optimal seed {0} yields coverage {1} after {2} iterations ({3} total iterations, including heuristic).".format(
						optimal_seed, coverage[optimal_seed], args.explorationdepth, args.explorationdepth + (args.time * args.depth * args.seeds)))

	# slowfuzz build
	else:
		if args.verbose:
			print("Running using SlowFuzz build...")
			print("Using implementation at: ", args.build)
		# build the application being tested
		os.chdir('../slowfuzz/apps/{0}/'.format(args.build))
		os.system('make fuzzer')
		os.system('make')
		# find the optimal seed from the initial ones
		optimal_seed, slowdown_records = runOptimization(args.depth, args.path, args.time, seeds, range_dict, args.libfuzzer, verbose=args.verbose)
		if args.verbose:
			print("Optimal seed {0} obtained, yielding slowdown {1} after {2} iterations.".format(optimal_seed, slowdown_records[optimal_seed], args.time))
		# obtain the results from the optimal seed
		slowdown = runSlowFuzz(args.path, args.explorationdepth, seeds=[optimal_seed],verbose=args.verbose)
		if args.verbose:
			print(
				"Optimal seed {0} yields slowdown {1} after {2} iterations ({3} total iterations, including heuristic).".format(
					optimal_seed, slowdown[optimal_seed],
					args.explorationdepth, args.explorationdepth + (args.time * args.depth * args.seeds)))
