# SlowerFuzz

## Introduction

[libFuzzer](https://llvm.org/docs/LibFuzzer.html) is a commonly used fuzzing package intended for providing a framework for application testing and evaluation. It helps to determine inputs that users could use that may lead to vulnerabilities in the underlying application by receiving high code coverage to explore more potential paths. For this project, we are assuming that we have access to code coverage statistics but no access to any input formatting information, thus forcing us to use evolution-based fuzzing. 

[SlowFuzz](https://arxiv.org/pdf/1708.08437.pdf) is a different take on libFuzzer that, rather than optimizing for code coverage, instead uses the execution time as a feedback mechanism. As a result, SlowFuzz instead seeks to find the input that most slows down a given application. This is both useful for attackers and security analysists as it exposes potentially unexpected inputs that could stall services when requests are limited. Security analysists are able to analyze these inputs, determine where the program went slowed down using that input, and then optimize the code to reduce the bottleneck.

Our modification for these projects, otherwise known as SlowerFuzz, utilizes a novel seed-selection heuristic that takes a wide range of low-search-depth seed samples (10,000 generations), selects the most locally optimal sample, and then runs across many more iterations. The basic premise for this application was that if a seed performs better early on, it could potentially perform better after many iterations as well since many seeds fizzle out early on, especially when inputs require some specific form. 

## Requirements
- [clang-4.0/clang++-4.0](https://releases.llvm.org/4.0.0/tools/clang/docs/ReleaseNotes.html)
- [libFuzzer](https://github.com/google/fuzzing)/[fuzzer](https://github.com/google/fuzzing/blob/master/tutorial/libFuzzerTutorial.md)
- [SlowFuzz](https://github.com/nettrino/slowfuzz)
- python3

## Installation

### Brief Overview

Setup a Ubuntu 16.04 Virtual Machine environment to begin. 

Follow the instructions on clang-4.0/clang++-4.0's documentation to install. This repository contains a version of libFuzzer and SlowFuzz that was current at the time of testing for simplicity. If you would like to update them, you can clone the git repositories present within each of the above tutorials.

Now, verify that the installation of clang/clang++ is correct by running the test cases present within each of libFuzzer and SlowFuzz's documentation.

**Note:** Sometimes it may be difficult to obtain a compatible version of clang/clang++. In such an instance we have provided a woff binary that is precompiled for Ubuntu 16.04 systems, so by simply cloning this repository, you should be able to reproduce the most basic level of functionality.

You are now ready to run SlowerFuzz.

### Exact Steps

```
mkdir SlowFuzzerEnv
cd SlowFuzzerEnv
sudo apt-get update
sudo apt-get --yes install git
git clone https://github.com/google/fuzzing.git fuzzing
git clone https://github.com/google/fuzzer-test-suite.git FTS
sudo apt-get install autoconf
sudo apt-get install clang++
./fuzzing/tutorial/libFuzzer/install-deps.sh
./fuzzing/tutorial/libFuzzer/install-clang.sh
git clone https://github.com/sba6/SlowFuzzMods.git
cd SlowFuzzMods/src/
```

## Usage

```
cd src/
python3 -v -l -p woff
```

The above script will run the precompiled woff environment in a specialized folder. It will run libFuzzer (-l) with verbosity enabled (-v) and the path of woff (-p woff). The default configuration runs 5 elimination rounds of 25 seeds each, eliminates the worst 20 seeds, randomly selects 5 seeds per 5 remaining in close proximity, and then selects the best seed overall once finished. Then, the program, by default, runs that optimal seed on 3750000 iterations of the base algorithm from libFuzzer. An example output is shown below.

```
...
Running using traditional libFuzzer...
Using path: woff
Environment already set up... Continuing... 
{5518762689: 23, 5025436356: 26, ...}
...
{432284352: 22, ...}
Optimal seed 824630719 obtained, yielding coverage 73 after 10000 iterations.
{824630719: 73}
Optimal seed 824630719 yields coverage 660 after 3750000 iterations (5000000 total iterations, including heuristic).
```

This scheme also works for SlowFuzz by simply omitting the -l and -p options. 

We have also included a testing script for convenience of running many iterations to evaluate performance. This can be run in the following manner:

```
cd src/
python3 runTests.py -v -l -p woff -n 5
```

The above command will run 5 iterations of both our heuristic and the default configuration. The results of this run will be output into an `output.csv` file, containing each seed used, either selected by our heuristic or randomly selected by libFuzzer itself, the coverage after a total 5000000 iterations of each, and the peak memory consumption used by the algorithm in the process of fuzzing. As before, this is also implemented for the program's SlowFuzz counterpart but instead optimizes for the execution time statistic rather than the coverage.
