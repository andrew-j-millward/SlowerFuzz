# Create temp directory
cd ../;
rm -rf libjpeg-turbo-07-2017_tmp;
mkdir -p libjpeg-turbo-07-2017_tmp;
cd libjpeg-turbo-07-2017_tmp;

# Run setup script in new directory
sh ../FTS/libjpeg-turbo-07-2017/build.sh