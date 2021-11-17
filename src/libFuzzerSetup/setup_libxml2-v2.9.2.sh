# Create temp directory
cd ../../;
rm -rf libxml2-v2.9.2_tmp;
mkdir -p libxml2-v2.9.2_tmp;
cd libxml2-v2.9.2_tmp;

# Run setup script in new directory
sh ../FTS/libxml2-v2.9.2/build.sh