 for n in /home/reto/hapviewer/examples/demo/*gz; do export IP=`basename $n|sed 's/\.gz//'`; export START=`date  +%s`;echo -n $IP: ;../bin/haplibtest $n $IP > /dev/null && echo -n ...dot done... && dot -Tjpg test99.dot > $IP.jpg && echo -n "...jpg done in " || echo -n FAIL: $n with IP $IP; END=`date +%s`;DIFF=`expr $END - $START`; echo $DIFF s; rm test99.dot; rm temp.hpg; done