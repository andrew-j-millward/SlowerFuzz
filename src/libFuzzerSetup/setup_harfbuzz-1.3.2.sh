# Create temp directory
cd ../;
rm -rf harfbuzz-1.3.2_tmp;
mkdir -p harfbuzz-1.3.2_tmp;
cd harfbuzz-1.3.2_tmp;

# Run setup script in new directory
sh ../FTS/harfbuzz-1.3.2/build.sh