# Create temp directory
cd ../../;
rm -rf pcre2-10.00_tmp;
mkdir -p pcre2-10.00_tmp;
cd pcre2-10.00_tmp;

# Run setup script in new directory
sh ../FTS/pcre2-10.00/build.sh