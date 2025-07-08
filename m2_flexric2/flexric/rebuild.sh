rm -rf build/
mkdir build
cd build
cmake ../
make -j`8`
sudo make install
cd ..
#cp flexric.conf /usr/local/etc/flexric/flexric.conf
