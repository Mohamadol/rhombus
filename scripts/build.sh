. scripts/common.sh

for deps in eigen3 emp-ot emp-tool hexl SEAL-3.7
do
  if [ ! -d $BUILD_DIR/include/$deps ] 
  then
 echo -e "${RED}$deps${NC} seems absent in ${BUILD_DIR}/include/, please re-run scripts/build-deps.sh"
 exit 1
  fi
done

for deps in zstd.h 
do
  if [ ! -f $BUILD_DIR/include/$deps ] 
  then
 echo -e "${RED}$deps${NC} seems absent in ${BUILD_DIR}/include/, please re-run scripts/build-deps.sh"
 exit 1
  fi
done

cd $BUILD_DIR/
cmake .. -DCMAKE_BUILD_TYPE=Release -DSCI_BUILD_NETWORKS=ON -DSCI_BUILD_TESTS=OFF -DOPENSSL_ROOT_DIR=$BUILD_DIR -DCMAKE_PREFIX_PATH=$BUILD_DIR -DUSE_APPROX_RESHARE=ON -DUSE_RANDOM_DEVICE=ON

make resnet50-cheetah -j4 
make resnet50-rhombus -j4

make sqnet-cheetah -j4
make sqnet-rhombus -j4

# rhombus module test
make rhombus_matmul
make rhombus_matvec

# Patch out rdseed instructions from libstdc++ (SEAL/HEXL pull in std::random_device
# which contains guarded rdseed code). Replace with xor+clc so the dispatch falls back
# to /dev/urandom on all CPUs.
python3 -c "
import glob, os
for path in glob.glob('$BUILD_DIR/bin/*'):
    if not os.path.isfile(path) or not os.access(path, os.X_OK): continue
    with open(path, 'rb') as f: data = f.read()
    data = data.replace(b'\x0f\xc7\xf8', b'\x31\xc0\xf8')
    data = data.replace(b'\x0f\xc7\xfa', b'\x31\xd2\xf8')
    with open(path, 'wb') as f: f.write(data)
"
echo -e "${GREEN}[success] build finished${NC}"