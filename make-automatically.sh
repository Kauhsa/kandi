#!/bin/bash
func="make dist/kandi.html dist/kandi.pdf"
$func
fswatch -o src templates | xargs -n1 -I{} $func
