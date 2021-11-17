# Create temp directory
cd ../../;
rm -rf llvm-libcxxabi-2017-01-27_tmp;
mkdir -p llvm-libcxxabi-2017-01-27_tmp;
cd llvm-libcxxabi-2017-01-27_tmp;

# Run setup script in new directory
sh ../FTS/llvm-libcxxabi-2017-01-27/build.sh