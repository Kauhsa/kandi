#!/bin/bash
fswatch -o src templates | xargs -n1 -I{} make dist/kandi.html dist/kandi.pdf
