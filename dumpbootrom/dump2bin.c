#include <stdio.h>
#include <stdint.h>
 
// Usage:
//   dump2bin <dump.txt

// 60001000: 00000000 00000000 60008044 fffffff8
// :        :        :        :        :
// 0        1         2         3         4
// 012345679012345678901234567890123456789012345

void main() {
  char line[1024];

  FILE *f = fopen("bootrom.bin", "wb");

  for (;fgets(line, 1024, stdin);) {
    uint32_t addr = strtol(line, 0, 16);
    uint32_t w[4];
    w[0] = strtoul(line+10, 0, 16);
    w[1] = strtoul(line+19, 0, 16);
    w[2] = strtoul(line+28, 0, 16);
    w[3] = strtoul(line+37, 0, 16);

    int i;
    for (i=0; i<16; i++)
      fwrite(((uint8_t *)w)+i, 1, 1, f);

  }
  fclose(f);
}
