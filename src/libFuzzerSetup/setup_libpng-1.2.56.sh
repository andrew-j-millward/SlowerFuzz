# Create temp directory
cd ../../;
rm -rf libpng-1.2.56_tmp;
mkdir -p libpng-1.2.56_tmp;
cd libpng-1.2.56_tmp;

# Run setup script in new directory
sh ../FTS/libpng-1.2.56/build.sh