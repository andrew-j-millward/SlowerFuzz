# Create temp directory
cd ../;
rm -rf boringssl-2016-02-12_tmp;
mkdir -p boringssl-2016-02-12_tmp;
cd boringssl-2016-02-12_tmp;

# Run setup script in new directory
sh ../FTS/boringssl-2016-02-12/build.sh