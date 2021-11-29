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

def initializeEnv(name):
	if not os.path.isdir('../' + name + '_tmp'):
		shellStream = os.popen('sh libFuzzerSetup/setup_' + name + '.sh')
		out = shellStream.read()
		print(out)
	else:
		print('Environment already set up... Continuing...')

def runTest(name, timeout_period, seeds=[1]):
	coverage = {}
	for i in range(len(seeds)):
		subpro = run('../' + name + '_tmp/' + str(name) + '-fsanitize_fuzzer -seed=' + str(seeds[i]) + ' -runs=' + str(timeout_period), stdout=PIPE, stderr=PIPE, universal_newlines=True, shell=True)
		output = subpro.stderr.split('\n')
		for j in range(len(output)):
			if 'cov:' in output[-j-1]:
				parsed1 = output[-j-1].split('cov: ')
				parsed2 = parsed1[1].split(' ft:')
				coverage[seeds[i]] = int(parsed2[0])
				break
	print(coverage)
	return coverage

def runSlowFuzz(build, seeds):
	seed_scores = {}
	for x in seeds.keys():
		output = run("""
		./driver corpus -artifact_prefix=out -print_final_stats=1 \
		-detect_leaks=0 -rss_limit_mb=10000 -shuffle=0 \
		-runs=1000 -max_len=64 -death_node=1 \
		-seed={0}
		""".format(x),stdout=PIPE, stderr=PIPE,shell=True,universal_newlines=True)
		output = output.stderr.split('\n')
		for l in output:
			if 'cov' in l:
				cov = l.split('cov: ')[1].split(' ft:')[1].split()
				seed_scores[x] = int(cov[0])
				break
	print(seed_scores)
	return seed_scores

def generateSeedsSlowFuzz(orig_seeds, ranges):
	new_seeds = []
	new_range_dict = {}
	for i in range(5):
		tmp_range_block = []
		lower = ranges[orig_seeds[i]][0]
		upper = ranges[orig_seeds[i]][1]
		for j in range(5):
			new_seed =random.randint(lower, upper)
			new_seeds.append(new_seed)
			tmp_range_block.append(new_seed)
		tmp_range_block = sorted(tmp_range_block)
		seed_ranges = [(lower, min(math.ceil((tmp_range_block[0]+tmp_range_block[1])/2), upper))]
		for j in range(1,4):
			seed_ranges.append((max(lower, seed_ranges[-1][1]+1), min(math.ceil((tmp_range_block[j]+tmp_range_block[j+1])/2), upper)))
		seed_ranges.append((seed_ranges[-1][1]+1, upper))
		for i in range(len(tmp_range_block)):
			new_range_dict[tmp_range_block[i]] = seed_ranges[i]
	seed_dict = {}
	for x in new_seeds: seed_dict[x] = 0
	return seed_dict, new_range_dict

def refineSeedsLibFuzzer(range_dict, coverage):
	optimal_seeds = sorted(coverage, key=coverage.get)[-5:]
	new_seeds = []
	new_range_dict = {}
	for i in range(5):
		tmp_range_block = []
		lower = range_dict[optimal_seeds[i]][0]
		upper = range_dict[optimal_seeds[i]][1]
		for j in range(5):
			new_seeds.append(random.randint(lower, upper))
			tmp_range_block.append(new_seeds[-1])
		tmp_range_block = sorted(tmp_range_block)
		seed_ranges = [(lower, min(math.ceil((tmp_range_block[0]+tmp_range_block[1])/2), upper))]
		for j in range(1,4):
			seed_ranges.append((max(lower, seed_ranges[-1][1]+1), min(math.ceil((tmp_range_block[j]+tmp_range_block[j+1])/2), upper)))
		seed_ranges.append((seed_ranges[-1][1]+1, upper))
		for i in range(len(tmp_range_block)):
			new_range_dict[tmp_range_block[i]] = seed_ranges[i]
	return new_seeds, new_range_dict

def initializeSeeds(seeds):
	seeds = sorted([random.randint(1,9999999999) for i in range(seeds)])
	seed_ranges = [(1, min(math.ceil((seeds[0]+seeds[1])/2),9999999999))]
	for i in range(1, len(seeds)-1):
		seed_ranges.append((max(1, seed_ranges[i-1][1]+1), min(math.ceil((seeds[i]+seeds[i+1])/2),9999999999)))
	seed_ranges.append((seed_ranges[-1][1]+1, 9999999999))
	range_dict = {seeds[i]:seed_ranges[i] for i in range(len(seeds))}
	return seeds, seed_ranges, range_dict

def runOptimization(depth, path, time, seeds, range_dict):
	coverage_records = {}
	for i in range(depth):
		coverage = runTest(path, time, seeds)
		coverage_records = {**coverage_records, **coverage}
		seeds, range_dict = refineSeedsLibFuzzer(range_dict, coverage)
	optimal_seed = max(coverage_records, key=coverage_records.get)
	return optimal_seed, coverage_records

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
	parser.add_argument('-p', '--path', type=str, metavar='', help='Path to target. I.e. input "woff2-2016-05-06" will lead to ..FTSwoff2-2016-05-06',
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

		tests = ['boringssl-2016-02-12', 'c-ares-CVE-2016-5180', 'freetype2-2017', 'guetzli-2017-3-30', 'harfbuzz-1.3.2', 'json-2017-02-12', 'lcms-2017-03-21', 'libarchive-2017-01-04',
				 'libjpeg-turbo-07-2017', 'libpng-1.2.56', 'libssh-2017-1272', 'libxml2-v2.9.2', 'llvm-libcxxabi-2017-01-27', 'openssl-1.0.1f', 'openssl-1.0.2d', 'openssl-1.1.0c',
				 'openthread-2018-02-27', 'pcre2-10.00', 'proj4-2017-08-14', 're2-2014-12-09', 'sqlite-2016-11-14', 'vorbis-2017-12-11', 'woff2-2016-05-06', 'wpantund-2018-02-27']
		debug_test = ['woff']

		# Initialize and Run
		if args.path == 'clean':
			if args.verbose:
				print('Reset branch triggered... Removing all testing environments')
			for i in range(len(tests)):
				if os.path.isdir('../' + tests[i] + '_tmp'):
					shutil.rmtree('../' + tests[i] + '_tmp')
		elif args.path in tests or args.path in debug_test:
			initializeEnv(args.path)
			optimal_seed, coverage_records = runOptimization(args.depth, args.path, args.time, seeds, range_dict)
			if args.verbose:
				print("Optimal seed {0} obtained, yielding coverage {1} after {2} iterations.".format(optimal_seed, coverage_records[optimal_seed], args.time))
			coverage = runTest(args.path, args.explorationdepth, seeds=[optimal_seed])
			if args.verbose:
				print("Optimal seed {0} yields coverage {1} after {2} iterations ({3} total iterations, including heuristic).".format(optimal_seed, coverage[optimal_seed], 
					args.explorationdepth, args.explorationdepth+(args.time*args.depth*args.seeds)))		

	#slowfuzz build
	else:
		if args.verbose:
			print("Running using SlowFuzz build...")
			print("Using implementation at: ", args.build)
		os.chdir('../slowfuzz/apps/{0}/'.format(args.build))
		os.system('make fuzzer')
		os.system('make')
		optimal_seeds = {}
		for x in seeds: optimal_seeds[x] = 0
		seed_scores = runSlowFuzz(args.build, optimal_seeds)
		
		#prune seeds at rate determined by specified depth
		#number of seeds to drop per round = args.seeds / (args.depth - 1)
		#this will leave a final round of the best performing seeds
		for _ in range(args.depth):
			optimal_seeds = sorted(seed_scores, key=seed_scores.get)[-5:]
			new_seeds, range_dict = generateSeedsSlowFuzz(optimal_seeds, range_dict)
			seed_scores = runSlowFuzz(args.build, new_seeds)
			if args.verbose:
				print("SCORES: ",seed_scores)
