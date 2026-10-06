#!/bin/bash

op=$1
src=$2
num_cores=`lscpu | grep ^CPU\(s\) | awk '{print $2}'`
mem_percent=0.7
fp=32
liveness="-lncheck final"

for arg in "$op"; do
    case $arg in
        trans)
	    java -cp tla2tools.jar pcal.trans ${src}.tla
	    ;;
	run)
#            java -Xmx140G -XX:+UseParallelGC -jar tla2tools.jar -workers ${num_cores} -fpmem ${mem_percent} ${liveness} -config ${src}.cfg -fp ${fp} ${src}.tla 2>&1 | tee tlc_fp${fp}.log
	     java -XX:MaxDirectMemorySize=150G -Dtlc2.tool.fp.FPSet.impl=tlc2.tool.fp.OffHeapDiskFPSet -XX:+UseParallelGC -jar tla2tools.jar -workers ${num_cores} -fpmem ${mem_percent} ${liveness} -config ${src}.cfg -fp ${fp} ${src}.tla 2>&1 | tee tlc_fp${fp}.log
	    ;;
  esac
done
