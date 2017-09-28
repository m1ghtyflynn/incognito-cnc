#!/bin/bash

# Will get you an autor00t
OPTION='/bin/cat'
OPTION2='/etc/passwd'
OPTION3='/etc/shadow'

HOST='target host'
PORT='22'

# Instructions
# Run tool as user
# Run tool as root
# Autor00t!!!!

CONNECTION='$HOST $PORT'

OUTPUT=`$OPTION $OPTION2`

echo $OUTPUT

OUTPUT2=`$OPTION $OPTION3`

echo $OUTPUT2
