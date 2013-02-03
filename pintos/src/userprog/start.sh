rm -f filesys.dsk
pintos-mkdisk filesys.dsk --filesys-size=2
pintos -f -q
pintos -p ../../examples/echo -a echo -- -q
pintos -p ../../examples/bubsort -a bubsort -- -q
pintos -p ../../examples/cat -a cat -- -q
pintos -p ../../examples/cmp -a cmp -- -q
pintos -p ../../examples/cp  -a cp -- -q
pintos -p ../../examples/echo -a echo -- -q
pintos -p ../../examples/halt -a halt -- -q
pintos -p ../../examples/hex-dump -a hex-dump -- -q
pintos -p ../../examples/insult -a insult -- -q
pintos -p ../../examples/lineup -a lineup -- -q
pintos -p ../../examples/ls -a ls -- -q
pintos -p ../../examples/matmul -a matmul -- -q
pintos -p ../../examples/mcat -a mcat -- -q
pintos -p ../../examples/mcp  -a mcp -- -q
pintos -p ../../examples/mkdir -a mkdir -- -q
pintos -p ../../examples/pwd -a pwd -- -q
pintos -p ../../examples/recursor -a recursor -- -q
pintos -p ../../examples/rm -a rm -- -q
pintos -p ../../examples/shell -a shell -- -q
pintos -p ../../examples/echo.c -a echo.c -- -q