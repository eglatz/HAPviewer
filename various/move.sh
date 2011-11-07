#!/bin/sh

CURRENTPATH="`basename $PWD`"
PROTO="$CURRENTPATH"
FILENAME="$1"
REFERENCEDIR="$2"
MOVEDIR="$3"

echo FILENAME: $FILENAME
echo REFERENCEDIR: $REFERENCEDIR
echo MOVEDIR: $MOVEDIR

if [ $# != 3 ]
then
	echo "Usage: move.sh FILENAME REFERENCEDIR MOVEDIR"
	exit
fi

MD51=`cat "$FILENAME"|sha256sum`
MD52=`cat "$2/$PROTO/$FILENAME"|sha256sum`

if [ "$MD51" = "$MD52" ]
then
	echo SAME
	mv "$FILENAME" "$MOVEDIR/$PROTO/$FILENAME"
else
	echo DIFFERENT
	eog "$FILENAME" &
	eog -n "$REFERENCEDIR/$PROTO/$FILENAME" &
	compare "$FILENAME" "$REFERENCEDIR/$PROTO/$FILENAME" diff.png &&
	eog -n diff.png
	rm diff.png
	zenity --question --text="Selbes Bild?"
	if [ "$?" = "0" ]
	then
		echo MOVE IT
		mv "$FILENAME" "$MOVEDIR/$PROTO/$FILENAME"
	fi


fi
