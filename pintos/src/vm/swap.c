#include <stdio.h>
#include "swap.h"

bool
swap_page_in(struct thread *t UNUSED)
{
  printf("swapping not yet supported.\n");
  return false;
}
