

import sys
sys.path.append('..')
sys.path.append('..FTS')
sys.path.append('..fuzzing')
sys.path.append('..slowfuzz')
sys.path.append('..woff')
import argparse, random, math, os, shutil
from subprocess import STDOUT, check_output, TimeoutExpired

def initializeEnv(name):
    shellStream = os.popen('sh libFuzzerSetup/setup_' + name + '.sh')
    out = shellStream.read()
    print(out)

def runTest(name, timeout_period):
    out = ''
    try:
        out = check_output('../' + name + '_tmp/' + name + '-fsanitize_fuzzer', stderr = STDOUT, timeout = timeout_period)
        out_formatted = ''.join(map(chr, out))
        print(out_formatted)
    except TimeoutExpired as e:
        print('Error: Time limit exceeded, terminated..')
        print(out)

    f = open('report.txt','w')
    f.write(strOutput)
    f.close()

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
    parser.add_argument('-p', '--path', type=str, metavar='', help='Path to target. I.e. input "woff2-2016-05-06" will lead to ..FTSwoff2-2016-05-06',
                        default='woff2-2016-05-06')
    parser.add_argument('-l', '--libfuzzer', action='store_true', help='Use libFuzzer instead for coverage testing')
    parser.add_argument('-b', '--build', type=str, metavar='', help='Path to build file for SlowFuzz implementation',
                        default='isort')

    args = parser.parse_args()

    # Generate initial seeds
    seeds = sorted([random.randint(0,9999999999) for i in range(args.seeds)])
    seed_ranges = [(0, min(math.ceil((seeds[0]+seeds[1])/2),9999999999))]
    for i in range(1, len(seeds)-1):
        seed_ranges.append((max(0, seed_ranges[i-1][1]+1), min(math.ceil((seeds[i]+seeds[i+1])/2),9999999999)))
    print(seeds, seed_ranges)

    # If we are testing on libFuzzer instead of slowFuzz directly...
    if args.libfuzzer:

        print('Running using traditional libFuzzer...')
        print('Using path: ' + args.path)

        tests = ['boringssl-2016-02-12', 'c-ares-CVE-2016-5180', 'freetype2-2017', 'guetzli-2017-3-30', 'harfbuzz-1.3.2', 'json-2017-02-12', 'lcms-2017-03-21', 'libarchive-2017-01-04',
                 'libjpeg-turbo-07-2017', 'libpng-1.2.56', 'libssh-2017-1272', 'libxml2-v2.9.2', 'llvm-libcxxabi-2017-01-27', 'openssl-1.0.1f', 'openssl-1.0.2d', 'openssl-1.1.0c',
                 'openthread-2018-02-27', 'pcre2-10.00', 'proj4-2017-08-14', 're2-2014-12-09', 'sqlite-2016-11-14', 'vorbis-2017-12-11', 'woff2-2016-05-06', 'wpantund-2018-02-27']

        # Initialize environment
        if args.path == 'clean':
            print('Reset branch triggered... Removing all testing environments')
            for i in range(len(tests)):
                if os.path.isdir('../' + tests[i] + '_tmp'):
                    shutil.rmtree('../' + tests[i] + '_tmp')
        elif args.path == 'boringssl-2016-02-12':
            initializeEnv(args.path)
            runTest(args.path, args.time)
        elif args.path == 'c-ares-CVE-2016-5180':
            initializeEnv(args.path)
        elif args.path == 'freetype2-2017':
            initializeEnv(args.path)
        elif args.path == 'guetzli-2017-3-30':
            initializeEnv(args.path)
        elif args.path == 'harfbuzz-1.3.2':
            initializeEnv(args.path)
        elif args.path == 'json-2017-02-12':
            initializeEnv(args.path)
        elif args.path == 'lcms-2017-03-21':
            initializeEnv(args.path)
        elif args.path == 'libarchive-2017-01-04':
            initializeEnv(args.path)
        elif args.path == 'libjpeg-turbo-07-2017':
            initializeEnv(args.path)
        elif args.path == 'libpng-1.2.56':
            initializeEnv(args.path)
        elif args.path == 'libssh-2017-1272':
            initializeEnv(args.path)
        elif args.path == 'libxml2-v2.9.2':
            initializeEnv(args.path)
        elif args.path == 'llvm-libcxxabi-2017-01-27':
            initializeEnv(args.path)
        elif args.path == 'openssl-1.0.1f':
            initializeEnv(args.path)
        elif args.path == 'openssl-1.0.2d':
            initializeEnv(args.path)
        elif args.path == 'openssl-1.1.0c':
            initializeEnv(args.path)
        elif args.path == 'openthread-2018-02-27':
            initializeEnv(args.path)
        elif args.path == 'pcre2-10.00':
            initializeEnv(args.path)
        elif args.path == 'proj4-2017-08-14':
            initializeEnv(args.path)
        elif args.path == 're2-2014-12-09':
            initializeEnv(args.path)
        elif args.path == 'sqlite-2016-11-14':
            initializeEnv(args.path)
        elif args.path == 'vorbis-2017-12-11':
            initializeEnv(args.path)
        elif args.path == 'woff2-2016-05-06':
            initializeEnv(args.path)
        elif args.path == 'wpantund-2018-02-27':
            initializeEnv(args.path)
        elif args.path == 'all':
            initializeEnv(args.path)

        # Perform eliminations
        for i in range(args.depth):
            pass
    #slowfuzz build
    else:
        print("Running using SlowFuzz build...")
        print("Using implementation at: ", args.build)

        os.chdir('../slowfuzz/apps/{0}/'.format(args.build))
        os.system('make fuzzer')
        os.system('make')
        for x in seeds:
            os.system("""
            ./driver corpus -artifact_prefix=out -print_final_stats=1 \
            -detect_leaks=0 -rss_limit_mb=10000 -shuffle=0 \
            -runs=1000 -max_len=64 -death_mode=1 \
            -seed={0}
            """.format(x))
