. scripts/common.sh

if [ ! $# -eq 2 ]
then
  echo -e "${RED}Please specify the network to run.${NC}"
  echo "Usage: run-client.sh [cheetah|rhombus] [resnet50|sqnet]"
else
  if ! contains "cheetah rhombus" $1; then
    echo -e "Usage: run-client.sh ${RED}[cheetah|rhombus]${NC} [resnet50|sqnet]"
 exit 1
  fi

  if ! contains "resnet50 sqnet" $2; then
    echo -e "Usage: run-client.sh [cheetah|rhombus] ${RED}[resnet50|sqnet]${NC}"
 exit 1
  fi
  # create a data/ to store the Ferret output
  mkdir -p data
  echo -e "Runing ${GREEN}$BUILD_DIR/bin/$2-$1${NC}, which might take a while...."
  cat pretrained/$2_input_scale12_pred*.inp | $BUILD_DIR/bin/$2-$1 r=2 k=$FXP_SCALE ell=$SS_BITLEN nt=$NUM_THREADS p=$SERVER_PORT 
  # 1>$1-$2_client.log
  # echo -e "Computation done, check out the log file ${GREEN}$1-$2_client.log${NC}"
fi