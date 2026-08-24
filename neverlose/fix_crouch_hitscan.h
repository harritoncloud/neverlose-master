#pragma once

struct crouch_hitscan_status
{
    bool body = false;
    bool head = false;
};

// Narrows only capsule edge points for crouched historical records.
crouch_hitscan_status apply_crouch_hitscan_fix();
