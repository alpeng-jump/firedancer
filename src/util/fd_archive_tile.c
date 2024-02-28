#include "../tango/cnc/fd_cnc.h"

int
main( int     argc,
      char ** argv ) {
        
  fd_boot( &argc, &argv );

  FD_LOG_NOTICE(( "Init fd_archive" ));

  char const * _cnc        = fd_env_strip_cmdline_cstr ( &argc, &argv, "--cnc",       NULL, NULL                        );
  char const * _pcap_path  = fd_env_strip_cmdline_cstr ( &argc, &argv, "--pcap_path", NULL, NULL                        );
  ulong        orig        = fd_env_strip_cmdline_ulong( &argc, &argv, "--orig",      NULL, 0UL                         );
  char const * _mcache     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--mcache",    NULL, NULL                        );
  char const * _dcache     = fd_env_strip_cmdline_cstr ( &argc, &argv, "--dcache",    NULL, NULL                        );
  ulong        cr_max      = fd_env_strip_cmdline_ulong( &argc, &argv, "--cr-max",    NULL, 0UL                         ); /*   0 <> use default */
  long         lazy        = fd_env_strip_cmdline_long ( &argc, &argv, "--lazy",      NULL, 0L                          ); /* <=0 <> use default */
  uint         seed        = fd_env_strip_cmdline_uint ( &argc, &argv, "--seed",      NULL, (uint)(ulong)fd_tickcount() );

  if( FD_UNLIKELY( !_cnc ) ) FD_LOG_ERR(( "--cnc not specified" ));
  FD_LOG_NOTICE(( "Joining --cnc %s", _cnc ));
  fd_cnc_t * cnc = fd_cnc_join( fd_wksp_map( _cnc ) );
  if( FD_UNLIKELY( !cnc ) ) FD_LOG_ERR(( "fd_cnc_join failed" ));

  if( FD_UNLIKELY( !_pcap_path ) ) FD_LOG_ERR(( "--pcap_path not specified" ));
  FD_LOG_NOTICE(( "Using --pcap_path %s", _pcap_path ));

  if( FD_UNLIKELY( !_mcache ) ) FD_LOG_ERR(( "--mcache not specified" ));
  FD_LOG_NOTICE(( "Joining --mcache %s", _mcache ));
  fd_frag_meta_t * mcache = fd_mcache_join( fd_wksp_map( _mcache ) );
  if( FD_UNLIKELY( !mcache ) ) FD_LOG_ERR(( "fd_mcache_join failed" ));

  if( FD_UNLIKELY( !_dcache ) ) FD_LOG_ERR(( "--dcache not specified" ));
  FD_LOG_NOTICE(( "Joining --dcache %s", _dcache ));
  uchar * dcache = fd_dcache_join( fd_wksp_map( _dcache ) );
  if( FD_UNLIKELY( !dcache ) ) FD_LOG_ERR(( "fd_dcache_join failed" ));

  FD_LOG_NOTICE(( "Using --cr-max %lu, --lazy %li", cr_max, lazy ));

  FD_LOG_NOTICE(( "Creating rng --seed %u", seed ));
  fd_rng_t _rng[1];
  fd_rng_t * rng = fd_rng_join( fd_rng_new( _rng, seed, 0UL ) );

  FD_LOG_NOTICE(( "Creating scratch" ));
  ulong  page_sz  = FD_SHMEM_HUGE_PAGE_SZ;
  ulong  page_cnt = 1UL;
  ulong  cpu_idx  = fd_tile_cpu_id( fd_tile_idx() );
  void * scratch  = fd_shmem_acquire( page_sz, page_cnt, cpu_idx );
  if( FD_UNLIKELY( !scratch ) ) FD_LOG_ERR(( "fd_shmem_acquire failed (need at least %lu free huge pages on numa node %lu)",
                                             page_cnt, fd_shmem_numa_idx( cpu_idx ) ));

  FD_LOG_NOTICE(( "Run fd_archive" ));

  int err = fd_archive_tile( cnc, _pcap_path, orig, mcache, dcache, cr_max, lazy, rng, scratch);
  if( FD_UNLIKELY( err ) ) FD_LOG_ERR(( "fd_archive_tile failed (%i)", err ));

  FD_LOG_NOTICE(( "Fini fd_archive" ));

  fd_shmem_release( scratch, page_sz, page_cnt );
  fd_rng_delete( fd_rng_leave( rng ) );
  fd_wksp_unmap( fd_dcache_leave( dcache ) );
  fd_wksp_unmap( fd_mcache_leave( mcache ) );
  fd_wksp_unmap( fd_cnc_leave   ( cnc    ) );

  fd_halt();
  return err;
}
