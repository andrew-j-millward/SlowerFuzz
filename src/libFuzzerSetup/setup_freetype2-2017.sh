# Create temp directory
cd ../;
rm -rf freetype2-2017_tmp;
mkdir -p freetype2-2017_tmp;
cd freetype2-2017_tmp;

# Run setup script in new directory
sh ../FTS/freetype2-2017/build.sh