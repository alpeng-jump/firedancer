#include "tiles.h"

// todo stash link name hash
static void
unprivileged_init( fd_topo_t *      topo,
                   fd_topo_tile_t * tile,
                   void *           scratch ) {
    (void)topo;
    (void)tile;
    (void)scratch;
}

fd_topo_run_tile_t fd_tile_archive = {
    .name                     = "archive",
    .mux_flags                = FD_MUX_FLAG_DEFAULT,
    .burst                    = 1UL,
    .mux_ctx                  = NULL,
    .populate_allowed_seccomp = NULL,
    .populate_allowed_fds     = NULL,
    .scratch_align            = NULL,
    .scratch_footprint        = NULL,
    .privileged_init          = NULL,
    .unprivileged_init        = NULL,
};
