# Create temp directory
cd ../../;
rm -rf libarchive-2017-01-04_tmp;
mkdir -p libarchive-2017-01-04_tmp;
cd libarchive-2017-01-04_tmp;

# Run setup script in new directory
sh ../FTS/libarchive-2017-01-04/build.sh