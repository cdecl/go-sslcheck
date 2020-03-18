#!/bin/bash

ROOT_DIR=$(cd $(dirname $0) && pwd)
#ROOT_DIR=/root/service/ssl-expcheck

##############################################################################################
# ssl-chceck  
$ROOT_DIR/ssl-check > result.log

##############################################################################################
# Make Html file
echo "" > $ROOT_DIR/result.html
echo "<style> table.list { border: 1px solid #444444; border-collapse: collapse; }" >> $ROOT_DIR/result.html
echo "td.list { border: 1px solid #444444; padding: 5px; font-family: 'Malgun Gothic', monospace, serif; } </style>" >> $ROOT_DIR/result.html

echo '<table class=list>' >> $ROOT_DIR/result.html
sed -r 's/\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|([^|]*)\|/<tr><td class=list>\1<\/td><td class=list>\2<\/td><td class=list>\3<\/td><td class=list>\4<\/td><td class=list>\5<\/td><td class=list>\6<\/td><\/tr>/g' $ROOT_DIR/result.log | grep -v +  >> $ROOT_DIR/result.html

echo '</table>' >> $ROOT_DIR/result.html



