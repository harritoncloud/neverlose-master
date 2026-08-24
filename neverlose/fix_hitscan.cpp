#include "fix_hitscan.h"

void apply_hitscan_fix()
{
    // Intentionally disabled: the old patch replaced only 9 bytes of an
    // 11-byte control-flow sequence and left an invalid instruction tail.
}
