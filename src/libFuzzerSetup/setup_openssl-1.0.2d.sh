# Create temp directory
cd ../../;
rm -rf openssl-1.0.2d_tmp;
mkdir -p openssl-1.0.2d_tmp;
cd openssl-1.0.2d_tmp;

# Run setup script in new directory
sh ../FTS/openssl-1.0.2d/build.sh