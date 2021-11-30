import sys, os
sys.path.append('../')
sys.path.append('../FTS')
sys.path.append('../fuzzing')
sys.path.append('../slowfuzz')
sys.path.append('../woff')
import argparse, random, math, os, shutil, signal, csv
from subprocess import STDOUT, TimeoutExpired
from time import sleep
from subprocess import Popen, PIPE, run
import main

def runDefaultLibFuzzer(name, timeout_period):
	coverage = 0
	memory = 0
	seed = 0
	subpro = run('../' + name + '_tmp/' + str(name) + '-fsanitize_fuzzer ' + '-runs=' + str(timeout_period), stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
	output = subpro.stderr.split('\n')
	for j in range(len(output)):
		if 'cov: ' in output[-j-1]:
			parsed1 = output[-j-1].split('cov: ')
			parsed2 = parsed1[1].split(' ft:')
			coverage = int(parsed2[0])
			break
	for j in range(len(output)):
		if 'rss: ' in output[-j-1]:
			parsed1 = output[-j-1].split('rss: ')
			parsed2 = parsed1[1].split('Mb')
			memory = int(parsed2[0])
			break
	for j in range(len(output)):
		if 'Seed: ' in output[j]:
			parsed1 = output[j].split('Seed: ')
			seed = int(parsed1[1])
			break
	return coverage, memory, seed

def write(name, data):
	try:
		with open(name, 'a', newline='') as csv_file:
			file_write = csv.writer(csv_file)
			file_write.writerow(data)
			csv_file.close()

	except Exception as exception:
		print(exception)

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
						description='This script optimizes evolutionary fuzzing by introducing structured randomness and eliminating inefficient paths early on.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-d', '--depth', type=int, metavar='', help='Number of elimination rounds',
						default=5)
	parser.add_argument('-e', '--explorationdepth', type=int, metavar='', help='Once the fuzzing heuristic completes, now explore the best seed obtained',
						default=3750000)
	parser.add_argument('-t', '--time', type=int, metavar='', help='Maximum exploration steps before analyzing the results',
						default=10000)
	parser.add_argument('-s', '--seeds', type=int, metavar='', help='Number of seeds per elimination round',
						default=25)
	parser.add_argument('-c', '--carryOver', type=int, metavar='', help='Number of seed ranges to carry over to the next round',
						default=25)
	parser.add_argument('-p', '--path', type=str, metavar='', help='Path to target. I.e. input "woff2-2016-05-06" will lead to ../FTSwoff2-2016-05-06',
						default='woff2-2016-05-06')
	parser.add_argument('-l', '--libfuzzer', action='store_true', help='Use libFuzzer instead for coverage testing')
	parser.add_argument('-b', '--build', type=str, metavar='', help='Path to build file for SlowFuzz implementation',
						default='isort')
	parser.add_argument('-v', '--verbose', action='store_true', help='Print debugging information')
	parser.add_argument('-r', '--remove', action='store_true', help='Remove old CSV before starting')
	parser.add_argument('-n', '--number', type=int, metavar='', help='Number of tests per case (new vs old)',
						default=25)
	parser.add_argument('-o', '--output', type=str, metavar='', help='CSV output file name (without extension)',
						default='output')

	args = parser.parse_args()

	if args.libfuzzer:
		if args.verbose:
			print("Running tests on libFuzzer...")

			if args.verbose:
				print('Using path: ' + args.path)

		# Remove CSV if it exists and set to reset
		if os.path.exists(str(args.output) + '.csv') and args.remove:
			os.remove(str(args.output) + '.csv')

		# Setup CSV headers
		if not os.path.exists(str(args.output) + '.csv'):
			write(str(args.output) + ".csv", ["Optimal Seed", "Optimal Coverage", "Default Random Seed", "Default Random Coverage", "Maximum Total Number of Iterations", 
											  "Optimal Memory Consumption", "Default Random Memory Consumption"])

		# Run n iterations
		for i in range(args.number):

			# Generate initial seeds
			seeds, seed_ranges, range_dict = main.initializeSeeds(args.seeds)

			tests = ['boringssl-2016-02-12', 'c-ares-CVE-2016-5180', 'freetype2-2017', 'guetzli-2017-3-30', 'harfbuzz-1.3.2', 'json-2017-02-12', 'lcms-2017-03-21', 'libarchive-2017-01-04',
					 'libjpeg-turbo-07-2017', 'libpng-1.2.56', 'libssh-2017-1272', 'libxml2-v2.9.2', 'llvm-libcxxabi-2017-01-27', 'openssl-1.0.1f', 'openssl-1.0.2d', 'openssl-1.1.0c',
					 'openthread-2018-02-27', 'pcre2-10.00', 'proj4-2017-08-14', 're2-2014-12-09', 'sqlite-2016-11-14', 'vorbis-2017-12-11', 'woff2-2016-05-06', 'wpantund-2018-02-27']
			debug_test = ['woff']

			# Initialize and run both systems
			if args.path in tests or args.path in debug_test:

				# Initialize
				main.initializeEnv(args.path)

				# Run new implementation
				optimal_seed, coverage_records = main.runOptimizationLibFuzzer(args.depth, args.path, args.time, seeds, range_dict)
				if args.verbose:
					print("{0}: Optimal seed {1} obtained, yielding coverage {2} after {3} iterations.".format(i, optimal_seed, coverage_records[optimal_seed], args.time))
				optimal_coverage, optimal_memory = main.runLibFuzzer(args.path, args.explorationdepth, seeds=[optimal_seed])
				if args.verbose:
					print("{0}: Optimal seed {1} yields coverage {2} after {3} iterations ({4} total iterations, including heuristic).".format(i, optimal_seed, optimal_coverage[optimal_seed], 
						args.explorationdepth, args.explorationdepth+(args.time*args.depth*args.seeds), optimal_memory[optimal_seed]))

				# Run old implementation
				coverage, memory, seed = runDefaultLibFuzzer(args.path, args.explorationdepth+(args.time*args.depth*args.seeds))
				if args.verbose:
					print("{0}: Default random seed {1} yields coverage {2} after {3} iterations.".format(i, seed, coverage, args.explorationdepth+(args.time*args.depth*args.seeds)))

				# Write results back to CSV
				write(str(args.output) + '.csv', [optimal_seed, optimal_coverage[optimal_seed], seed, coverage, args.explorationdepth+(args.time*args.depth*args.seeds), optimal_memory[optimal_seed], memory])

	else:
		print("Running tests on SlowFuzz")