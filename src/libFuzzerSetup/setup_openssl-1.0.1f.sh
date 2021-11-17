# Create temp directory
cd ../../;
rm -rf openssl-1.0.1f_tmp;
mkdir -p openssl-1.0.1f_tmp;
cd openssl-1.0.1f_tmp;

# Run setup script in new directory
sh ../FTS/openssl-1.0.1f/build.sh