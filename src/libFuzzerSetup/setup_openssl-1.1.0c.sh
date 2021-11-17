# Create temp directory
cd ../../;
rm -rf openssl-1.1.0c_tmp;
mkdir -p openssl-1.1.0c_tmp;
cd openssl-1.1.0c_tmp;

# Run setup script in new directory
sh ../FTS/openssl-1.1.0c/build.sh