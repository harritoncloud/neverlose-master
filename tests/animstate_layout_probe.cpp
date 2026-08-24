#include <cstddef>
#include <cstdio>

struct FixedAnimState {
    unsigned char pad_0000[24];
    float anim_update_timer;
    unsigned char pad_001C[92];
    float eye_yaw;
    float pitch;
    float abs_yaw;
    float abs_yaw_last;
    unsigned char pad_0088[28];
    float duck_amount;
    unsigned char pad_00A8[80];
    float feet_speed_forwards_or_sideways;
    float feet_speed_unknown_forwards_or_sideways;
    unsigned char pad_0100[28];
    float stop_to_full_running_fraction;
    unsigned char pad_0120[532];
    float min_yaw;
    float max_yaw;
};

struct LibraryAnimState {
    char pad0[0x18];
    float anim_update_timer;
    char pad1[0xC];
    float started_moving_time;
    float last_move_time;
    char pad2[0x10];
    float last_lby_time;
    char pad3[0x8];
    float run_amount;
    char pad4[0x10];
    void* entity;
    void* active_weapon;
    void* last_active_weapon;
    float last_client_side_animation_update_time;
    int last_client_side_animation_update_framecount;
    float eye_timer;
    float eye_angles_y;
    float eye_angles_x;
    float goal_feet_yaw;
    float current_feet_yaw;
    float torso_yaw;
    float last_move_yaw;
    float lean_amount;
    char pad5[0x4];
    float feet_cycle;
    float feet_yaw_rate;
    char pad6[0x4];
    float duck_amount;
    float landing_duck_amount;
    char pad7[0x4];
    float current_origin[3];
    float last_origin[3];
    float velocity_x;
    float velocity_y;
    char pad8[0x4];
    float unknown_float1;
    char pad9[0x8];
    float unknown_float2;
    float unknown_float3;
    float unknown;
    float velocity;
    float jump_fall_velocity;
    float clamped_velocity;
    float feet_speed_forwards_or_sideways;
    float feet_speed_unknown_forwards_or_sideways;
    float last_time_started_moving;
    float last_time_stopped_moving;
    bool on_ground;
    bool hit_in_ground_animation;
    char pad10[0x4];
    float time_since_in_air;
    float last_origin_z;
    float head_from_ground_distance_standing;
    float stop_to_full_running_fraction;
    char pad11[0x4];
    float magic_fraction;
    char pad12[0x3C];
    float world_force;
    char pad13[0x1CA];
    float min_yaw;
    float max_yaw;
};

int main() {
    static_assert(sizeof(FixedAnimState) == 0x33C);
    static_assert(offsetof(FixedAnimState, min_yaw) == 0x334);
    static_assert(offsetof(FixedAnimState, max_yaw) == 0x338);
    static_assert(sizeof(FixedAnimState) == sizeof(LibraryAnimState));
    static_assert(
        offsetof(FixedAnimState, max_yaw) ==
        offsetof(LibraryAnimState, max_yaw));

    std::printf("Fixed size=0x%zX min=0x%zX max=0x%zX\n",
        sizeof(FixedAnimState),
        offsetof(FixedAnimState, min_yaw),
        offsetof(FixedAnimState, max_yaw));
    std::printf(
        "Library size=0x%zX eye=0x%zX feet=0x%zX duck=0x%zX speed=0x%zX run=0x%zX min=0x%zX max=0x%zX\n",
        sizeof(LibraryAnimState),
        offsetof(LibraryAnimState, eye_angles_y),
        offsetof(LibraryAnimState, goal_feet_yaw),
        offsetof(LibraryAnimState, duck_amount),
        offsetof(LibraryAnimState, feet_speed_forwards_or_sideways),
        offsetof(LibraryAnimState, stop_to_full_running_fraction),
        offsetof(LibraryAnimState, min_yaw),
        offsetof(LibraryAnimState, max_yaw));
}
