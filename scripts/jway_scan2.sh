#!/bin/bash
set -e
cd /home/claude/uvw_attack
S=/tmp/claude-0/-home-claude/eb45358c-0a59-5730-962a-e2da8f38d9ec/scratchpad/jet
P=211; N0=40; K0=15
run() { local j=$1 d=$2 r=$3 kl=$4
  python3 jet_jway.py $P $N0 $K0 $j $kl $d $r jway 7 $S/jw.bin >/dev/null
  local A=$(./rankp $S/jw.bin $P | sed 's/.*kernel=\([0-9]*\).*/\1/')
  python3 jet_jway.py $P $N0 $K0 $j $kl $d $r ctrl_block 7 $S/jwc.bin >/dev/null
  local B=$(./rankp $S/jwc.bin $P | sed 's/.*kernel=\([0-9]*\).*/\1/')
  echo "j=$j (d,r)=($d,$r) k_l=$kl : kernel_struct=$A kernel_ctrl=$B excess=$((A-B))"
}
echo "== (3,2) cubic =="; run 2 3 2 11; run 3 3 2 11; run 4 3 2 11
echo "== (4,3) =="; run 2 4 3 11; run 3 4 3 11
echo "== (5,4) =="; run 3 5 4 10; run 4 5 4 10
echo DONE
