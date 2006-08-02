#!/bin/sh

set -e

PYVER=2.4
PYTHON=python$PYVER

if [ `basename $PWD` == "generate" ]; then
  TP=${TELEPATHY_PYTHON:=$PWD/../../telepathy-python}
else
  TP=${TELEPATHY_PYTHON:=$PWD/../telepathy-python}
fi

export PYTHONPATH=$TP:$PYTHONPATH

if test -d generate; then cd generate; fi
cd xml-pristine

echo "Generating pristine XML in generate/xml-pristine..."
$PYTHON $TP/tools/genxml.py ../gabble.def
