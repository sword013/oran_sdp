cd flexric
rm -rf build
mkdir build
cd build
cmake ../
make -j`nproc`
sudo make install
cd ../..
