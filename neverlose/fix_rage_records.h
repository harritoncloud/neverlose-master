#pragma once

// Installs the selected record/rage patch bundle for the audited print1 build.
// Returns false without writing when any dependency or patch site is unknown.
bool apply_rage_record_patches();
