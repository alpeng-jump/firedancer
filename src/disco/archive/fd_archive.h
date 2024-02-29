#ifndef HEADER_fd_src_disco_archive_fd_archive_h
#define HEADER_fd_src_disco_archive_fd_archive_h

/* fd_archive provides services to archive data from mcache and dcache
   into a pcapng file */

#include "../fd_disco_base.h"
#include "../tango/mcache/fd_mcache.h"
#include "../tango/dcache/fd_dcache.h"
#include "../tango/cnc/fd_cnc.h"
#include "../util/net/fd_pcapng.h"

#define FD_ARCHIVE_CNC_SIGNAL_ACK (4UL)

/* FD_ARCHIVE_TILE_IN_MAX specifies the maximum number of in-mcaches that
   can be joined to an archive tile. */

#define FD_ARCHIVE_TILE_IN_MAX FD_FRAG_META_ORIG_MAX

/* FD_ARCHIVE_* are user provided flags specifying how to run the archive
   tile. 
   
   FD_ARCHIVE_FLAG_DEFAULT 
      Default archive operating mode.
*/

#define FD_ARCHIVE_FLAG_DEFAULT   0

/* FD_ARCHIVE_TILE_SCRATCH_ALIGN specifies the alignment needed for  
   an archive tile scratch region. */

#define FD_ARCHIVE_TILE_SCRATCH_ALIGN (128UL)
#define FD_ARCHIVE_TILE_SCRATCH_FOOTPRINT(in_cnt)                                   \
  FD_LAYOUT_FINI( FD_LAYOUT_APPEND( FD_LAYOUT_APPEND( FD_LAYOUT_INIT,               \
    alignof(fd_archive_tile_in_t), (in_cnt)*sizeof(fd_archive_tile_in_t) ),         \
    alignof(uchar *), 1024UL ),                                                     \
    FD_ARCHIVE_TILE_SCRATCH_ALIGN )
    

FD_PROTOTYPES_BEGIN

/* fd_archive_tile archives packets from the mcache and dcache to a pcapng file.
   This function is designed to be called when the CNC is in the BOOT state and 
   will transition the CNC to RUN state during operation, and finally to BOOT on halt.
   
   The caller is responsible for ensuring the lifecycle of cnc, mcache, dcache,
   rng, and scratch span the entire operation of this function. */

FD_FN_CONST ulong
fd_archive_tile_scratch_align( void );

int 
fd_archive_tile( fd_cnc_t *                  cnc,         /* Local join to the archive's command-and-control */
                 ulong                       flags,       /* Any of FD_ARCHIVE_FLAG_* specifying how to run archive */  
                 ulong                       in_cnt,      /* Number of input mcaches to read from, inputs are indexed [0,in_cnt) */
                 fd_frag_meta_t const **     in_mcache,   /* in_mcache[in_idx] is the local join to input in_idx's mcache */
                 ulong **                    in_fseq,     /* in_fseq  [in_idx] is the local join to input in_idx's fseq */
                 fd_frag_meta_t const *      mcache,      /* Local join to mcache that producer caches metadata for frags produced */
                 uchar const **              in_dcache,   /* in_dcache[in_idx] is the local join to input in_idx's dcache */
                 uchar const *               dcache,      /* Local join to dcache that producer writes frag payloads to*/
                 char const *                pcap_path,   /* Path to the pcapng file for output */              
                 ulong                       cr_max,      /* Maximum number of flow control credits, 0 means use a reasonable default */                             
                 long                        lazy,        /* Lazyiness, <=0 means use a reasonable default */
                 fd_rng_t *                  rng,         /* Local join to the rng this archive should use */
                 void *                      scratch,     /* Tile scratch memory */
                 void *                      ctx );       /* User supplied context to be passed to the read and process functions */               

FD_PROTOTYPES_END

#endif /* HEADER_fd_src_disco_archive_fd_archive_h */
