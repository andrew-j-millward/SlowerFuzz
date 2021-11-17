import sys
sys.path.append('../')
sys.path.append('../FTS')
sys.path.append('../fuzzing')
sys.path.append('../slowfuzz')
sys.path.append('../woff')
import argparse, random, math

if __name__ == '__main__':
	parser = argparse.ArgumentParser(
		description='This script optimizes evolutionary fuzzing by introducing structured randomness and eliminating inefficient paths early on.', formatter_class=argparse.ArgumentDefaultsHelpFormatter)
	parser.add_argument('-d', '--depth', type=int, metavar='', help='Number of elimination rounds',
						default=10)
	parser.add_argument('-t', '--time', type=int, metavar='', help='Maximum time per exploration before analyzing the results',
						default=10)
	parser.add_argument('-s', '--seeds', type=int, metavar='', help='Number of seeds per elimination round',
						default=25)
	parser.add_argument('-c', '--carryOver', type=int, metavar='', help='Number of seed ranges to carry over to the next round',
						default=25)
	parser.add_argument('-p', '--path', type=str, metavar='', help='Path to target. I.e. input "woff2-2016-05-06" will lead to ../FTS/woff2-2016-05-06',
						default='woff2-2016-05-06')
	parser.add_argument('-l', '--libfuzzer', action='store_true', help='Use libFuzzer instead for coverage testing')

	args = parser.parse_args()

	# Generate initial seeds
	seeds = sorted([random.randint(0,9999999999) for i in range(args.seeds)])
	seed_ranges = [(0, min(math.ceil((seeds[0]+seeds[1])/2),9999999999))]
	for i in range(1, len(seeds)-1):
		seed_ranges.append((max(0, seed_ranges[i-1][1]+1), min(math.ceil((seeds[i]+seeds[i+1])/2),9999999999)))
	print(seeds, seed_ranges)

	# Initialize environment
	if args.path == 'woff2-2016-05-06':
		pass

	# Perform eliminations
	for i in range(args.depth):
		pass

