# Create temp directory
cd ../../;
rm -rf sqlite-2016-11-14_tmp;
mkdir -p sqlite-2016-11-14_tmp;
cd sqlite-2016-11-14_tmp;

# Run setup script in new directory
sh ../FTS/sqlite-2016-11-14/build.sh