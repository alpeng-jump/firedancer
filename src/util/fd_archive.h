#ifndef HEADER_fd_src_util_archive_fd_archive_h
#define HEADER_fd_src_util_archive_fd_archive_h

/* fd_archive provides services to archive data from mcache and dcache
   into a pcapng file */

#include "../fd_util_base.h"
#include "../tango/mcache/fd_mcache.h"
#include "../tango/dcache/fd_dcache.h"
#include "../tango/cnc/fd_cnc.h"
#include "../util/net/fd_pcapng.h"

#define FD_ARCHIVE_CNC_SIGNAL_ACK (4UL)

/* FD_ARCHIVE_TILE_SCRATCH_ALIGN specifies the alignment needed for  
   an archive tile scratch region. */

#define FD_ARCHIVE_TILE_SCRATCH_ALIGN (128UL)

FD_PROTOTYPES_BEGIN

/* fd_archive_tile archives packets from the mcache and dcache to a pcapng file.
   This function is designed to be called when the CNC is in the BOOT state and 
   will transition the CNC to RUN state during operation, and finally to BOOT on halt.
   
   The caller is responsible for ensuring the lifecycle of cnc, mcache, dcache,
   rng, and scratch span the entire operation of this function.
*/

FD_FN_CONST ulong
fd_archive_tile_scratch_align( void );

int
fd_archive_tile(  fd_cnc_t *              cnc,        /* Local join to the replay's command-and-control */
                  const char *            pcap_path,  /* Path to the pcapng file for output */      
                  const fd_frag_meta_t *  mcache,     /* Local join to mcache that producer caches metadata for frags produced */
                  const uchar *           dcache,     /* Local join to dcache that producer writes frag payloads to*/
                  ulong                   cr_max,     /* Maximum number of flow control credits, 0 means use a reasonable default */
                  long                    lazy,       /* Lazyiness, <=0 means use a reasonable default */
                  fd_rng_t *              rng,        /* Local join to the rng this replay should use */
                  void *                  scratch );  /* Tile scratch memory */

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_util_archive_fd_archive_h */
