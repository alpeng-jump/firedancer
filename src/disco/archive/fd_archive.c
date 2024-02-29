#include "fd_archive.h"

#include <stdio.h>
#include <errno.h>

/* A fd_archive_tile_in has all the state needed retrieving frags from an in 
    It fits on exactly one cache line. */

struct __attribute__((aligned(64))) fd_archive_tile_in {
    fd_frag_meta_t const *  mcache;   /* local join to this in's mcache */
    uchar const *           dcache;   /* local join to this in's dcache */
    ulong                   depth;    /* depth of the mcache / positive integer power of 2  */
    uint                    idx;      /* index of this in the list of providers, [0, in_cnt) */
    ulong                   seq;      /* estimate of where this consumer currently is */
    fd_frag_meta_t  const * mline;    /* location where the caller can verify if it has been overrun by producer */
    ulong *                 fseq;     /* local join to the fseq used to return flow control credits to the in */
}; 

typedef struct fd_archive_tile_in fd_archive_tile_in_t;

ulong 
fd_archive_tile_scratch_align( void ) {
    return FD_ARCHIVE_TILE_SCRATCH_ALIGN;
}

ulong fd_archive_tile_scratch_footprint( ulong in_cnt ) {
    if( FD_UNLIKELY( in_cnt >FD_ARCHIVE_TILE_IN_MAX  ) ) return 0UL;
    ulong l = FD_LAYOUT_INIT;
    l = FD_LAYOUT_APPEND( l, alignof(fd_archive_tile_in_t), in_cnt*sizeof(fd_archive_tile_in_t)     ); /* in */
    l = FD_LAYOUT_APPEND( l, alignof(uchar *),              1024UL                                  ); /* dc_scratch */
    return FD_LAYOUT_FINI( l, fd_archive_tile_scratch_align() );
}

int 
fd_archive_tile( fd_cnc_t *                  cnc,
                 ulong                       flags,
                 ulong                       in_cnt,
                 fd_frag_meta_t const **     in_mcache,
                 ulong **                    in_fseq,
                 fd_frag_meta_t const *      mcache,
                 uchar const **              in_dcache,
                 uchar const *               dcache,
                 char const *                pcap_path,        
                 ulong                       cr_max,                                  
                 long                        lazy,
                 fd_rng_t *                  rng,
                 void *                      scratch,
                 void *                      ctx ) {

    /* pcap stream state */
    FILE *  pcap_file;  /* handle of pcap file stream */    

    /* in frag stream state */
    ulong                  in_seq;
    fd_archive_tile_in_t * in;
    void *                 dc_scratch; 

    /* out frag stream state */
    ulong   depth; /* depth of the mcache / positive integer power of 2 */
    ulong   _sync; /* local sync for mcache if mcache is NULL */
    ulong * sync;  /* local addr where mux mcache sync info is published */
    ulong   seq;   /* next archive frag sequence number to publish */

    /* housekeeping state */
    ulong    event_cnt; /* total number of housekeeping events */
    ulong    event_seq; /* current position in housekeeping event sequence, in [0,event_cnt) */
    ulong    async_min; /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */

    do {

        FD_LOG_INFO(( "Booting archive (in-cnt %lu)", in_cnt ));
        if( FD_UNLIKELY( in_cnt >FD_ARCHIVE_TILE_IN_MAX  ) ) { FD_LOG_WARNING(( "in_cnt too large"  )); return 1; }

        if( FD_UNLIKELY( !scratch ) ) {
            FD_LOG_WARNING(( "NULL scratch" ));
            return 1;
        }

        if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, fd_archive_tile_scratch_align() ) ) ) {
            FD_LOG_WARNING(( "misaligned scratch" ));
            return 1;
        }

        FD_SCRATCH_ALLOC_INIT( l, scratch );

        /* cnc state init */

        if( FD_UNLIKELY( !cnc ) ) { FD_LOG_WARNING(( "NULL cnc" )); return 1; }
        if( FD_UNLIKELY( fd_cnc_signal_query( cnc )!=FD_CNC_SIGNAL_BOOT ) ) { FD_LOG_WARNING(( "already booted" )); return 1; }

        /* pcap stream init */

        if( FD_UNLIKELY( !pcap_path ) ) { FD_LOG_WARNING(( "NULL pcap path" )); return 1; }

        FD_LOG_INFO(( "Opening pcap %s", pcap_path ));
        pcap_file = fopen(pcap_path, "wb");
        if( FD_UNLIKELY( !pcap_file ) ) { FD_LOG_WARNING(( "pcapng fopen failed" )); return 1; }

        fd_pcapng_shb_opts_t shb_opts = {
            .hardware     = "x86_64 ossdev",
            .os           = "Linux",
            .userappl     = "fd_archive",
        };
        fd_pcapng_fwrite_shb(&shb_opts, pcap_file);
        FD_LOG_DEBUG(( "Wrote SHB (end=%#lx)", ftell( pcap_file ) ));   

        fd_pcapng_idb_opts_t idb_opts = {};
        fd_pcapng_idb_defaults(&idb_opts, 0);
        fd_pcapng_fwrite_idb(FD_PCAPNG_LINKTYPE_ETHERNET, &idb_opts, pcap_file);
        FD_LOG_DEBUG(( "Wrote IDB (end=%#lx)", ftell( pcap_file ) ));

        /* in frag stream init */
            
        in_seq = 0UL;
        in         = (fd_archive_tile_in_t *) FD_SCRATCH_ALLOC_APPEND( l, alignof(fd_archive_tile_in_t), in_cnt*sizeof(fd_archive_tile_in_t) );
        dc_scratch = (void *)                 FD_SCRATCH_ALLOC_APPEND( l, alignof(uchar *), 1024UL ); // todo upper bound of frag size ??

        ulong min_in_depth = (ulong)LONG_MAX;

        if( FD_UNLIKELY( !!in_cnt && !in_mcache ) ) { FD_LOG_WARNING(( "NULL in_mcache" )); return 1; }
        if( FD_UNLIKELY( !!in_cnt && !in_dcache ) ) { FD_LOG_WARNING(( "NULL in_dcache" )); return 1; }
        if( FD_UNLIKELY( !!in_cnt && !in_fseq   ) ) { FD_LOG_WARNING(( "NULL in_fseq"   )); return 1; }
        if( FD_UNLIKELY( in_cnt > UINT_MAX ) ) { FD_LOG_WARNING(( "in_cnt too large" )); return 1; }
        
        for( ulong in_idx=0UL; in_idx<in_cnt; in_idx++ ) {

        /* FIXME: CONSIDER NULL OR EMPTY CSTR IN_FCTL[ IN_IDX ] TO SPECIFY
            NO FLOW CONTROL FOR A PARTICULAR IN? */
        if( FD_UNLIKELY( !in_mcache[ in_idx ] ) ) { FD_LOG_WARNING(( "NULL in_mcache[%lu]", in_idx )); return 1; }
        if( FD_UNLIKELY( !in_dcache[ in_idx ] ) ) { FD_LOG_WARNING(( "NULL in_dcache[%lu]", in_idx )); return 1; }
        if( FD_UNLIKELY( !in_fseq  [ in_idx ] ) ) { FD_LOG_WARNING(( "NULL in_fseq[%lu]",   in_idx )); return 1; }

        fd_archive_tile_in_t * this_in = &in[ in_idx ];

        this_in->mcache = in_mcache[ in_idx ];
        this_in->dcache = in_dcache[ in_idx ];
        this_in->fseq   = in_fseq  [ in_idx ];
        

        ulong const * this_in_sync = fd_mcache_seq_laddr_const( this_in->mcache );
        ulong depth    = fd_mcache_depth( this_in->mcache ); min_in_depth = fd_ulong_min( min_in_depth, depth );
        if( FD_UNLIKELY( depth > UINT_MAX ) ) { FD_LOG_WARNING(( "in_mcache[%lu] too deep", in_idx )); return 1; }
        this_in->depth = (uint)depth;
        this_in->idx   = (uint)in_idx;
        this_in->seq   = fd_mcache_seq_query( this_in_sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION? */
        this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in->seq, this_in->depth );

        }
        

        /* out frag stream init */

        if( FD_LIKELY( mcache ) ) {
            depth = fd_mcache_depth    ( mcache );
            sync  = fd_mcache_seq_laddr( mcache );
            seq = fd_mcache_seq_query( sync ); /* FIXME: ALLOW OPTION FOR MANUAL SPECIFICATION */
        } else {
            depth = 128UL;
            _sync = 0UL;
            sync  = &_sync;
            seq = 0UL;
        }

        /* housekeeping init */
        
        if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
        FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

        /* Initialize the initial event sequence to immediately update
        cr_avail on the first run loop iteration and then update all the
        ins accordingly. */

        event_cnt = in_cnt;        
        event_seq = 0UL;

        async_min = fd_tempo_async_min( lazy, event_cnt, (float)fd_tempo_tick_per_ns( NULL ) );
        if( FD_UNLIKELY( !async_min ) ) { FD_LOG_WARNING(( "bad lazy" )); return 1; }

    } while(0);


    FD_LOG_INFO(( "Running archive" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
    long then = fd_tickcount();
    long now = then;
    for(;;) {            
        /* housekeeping */
        if( FD_UNLIKELY( (now-then)>=0L ) ) {
            /* Send synchronization info */
            fd_mcache_seq_update( sync, seq );

            /* Send diagnostic info */
            /* When we drain, we don't do a fully atomic update of the
            diagnostics as it is only diagnostic and it will still be
            correct the usual case where individual diagnostic counters
            aren't used by multiple writers spread over different threads
            of execution. */
            fd_cnc_heartbeat( cnc, now );

            /* Receive command-and-control signals */
            ulong s = fd_cnc_signal_query( cnc );
            if( FD_UNLIKELY( s!=FD_CNC_SIGNAL_RUN ) ) {
                if( FD_LIKELY( s==FD_CNC_SIGNAL_HALT ) ) break;
                if( FD_UNLIKELY( s!=FD_ARCHIVE_CNC_SIGNAL_ACK ) ) {
                    char buf[ FD_CNC_SIGNAL_CSTR_BUF_MAX ];
                    FD_LOG_WARNING(( "Unexpected signal %s (%lu) received; trying to resume", fd_cnc_signal_cstr( s, buf ), s ));
                }
            }
            fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
        
            /* Select which event to do next (randomized round robin) and
                reload the housekeeping timer. */

            event_seq++;
            if( FD_UNLIKELY( event_seq>=event_cnt ) ) {
                event_seq = 0UL;

                /* We also do the same with the ins to prevent there being a
                correlated order frag origins from different inputs
                downstream at extreme fan in and extreme in load. */

                if( FD_LIKELY( in_cnt>1UL ) ) {
                ulong swap_idx = (ulong)fd_rng_uint_roll( rng, (uint)in_cnt );
                fd_archive_tile_in_t in_tmp;
                in_tmp         = in[ swap_idx ];
                in[ swap_idx ] = in[ 0        ];
                in[ 0        ] = in_tmp;
                }
            }

            /* Reload housekeeping timer */
            long next = fd_tickcount();
            then = now + (long)fd_tempo_async_reload( rng, async_min );
            now = next;
        }

        /* Select which in to poll next (randomized round robin) */

        if( FD_UNLIKELY( !in_cnt ) ) { now = fd_tickcount(); continue; }
        fd_archive_tile_in_t * this_in = &in[ in_seq ];
        in_seq++;
        if( in_seq>=in_cnt ) in_seq = 0UL; /* cmov */


        /* Check if this in has any new fragments to mux */

        ulong                  this_in_seq   = this_in->seq;
        fd_frag_meta_t const * this_in_mline = this_in->mline; /* Already at appropriate line for this_in_seq */

        __m128i seq_sig = fd_frag_meta_seq_sig_query( this_in_mline );
    #if FD_USING_CLANG
        /* TODO: Clang optimizes extremely aggressively which breaks the
        atomicity expected by seq_sig_query.  In particular, it replaces
        the sequence query with a second load (immediately following
        vector load).  The signature query a few lines down is still an
        extract from the vector which then means that effectively the
        signature is loaded before the sequence number.
        Adding this clobbers of the vector prevents this optimization by
        forcing the seq query to be an extract, but we probably want a
        better long term solution. */
        __asm__( "" : "+x"(seq_sig) );
    #endif
        ulong seq_found = fd_frag_meta_sse0_seq( seq_sig );
        long seq_diff = fd_seq_diff( this_in_seq, seq_found );

        if (FD_UNLIKELY(seq_diff)) { /* Caught up or overrun, optimize for new frag case */
            if( FD_UNLIKELY( seq_diff<0L ) ) { /* Overrun (impossible if in is honoring our flow control) */
                FD_LOG_WARNING(( "Overrun detected. Consumer is behind by %ld sequences.", seq_diff ));
                this_in->seq = seq_found; /* Resume from here (probably reasonably current, could query in mcache sync directly instead) */
            }       
            now = fd_tickcount();
            continue;
        }

        /* Process actual frag data. This attempt should always be successful if in producers are
           honoring our flow control. */
        FD_COMPILER_MFENCE();
        ulong chunk    = (ulong)this_in_mline->chunk;
        ulong sz       = (ulong)this_in_mline->sz;
        ulong ctl      = (ulong)this_in_mline->ctl;
        ulong tsorig   = (ulong)this_in_mline->tsorig;
        ulong sig      = (ulong)this_in_mline->sig;
        ulong data_offset = chunk * FD_DCACHE_ALIGN;        
        uchar *data = this_in->dcache + data_offset;
        fd_memcpy(dc_scratch, data, sz);
        FD_COMPILER_MFENCE();
        ulong seq_test = this_in_mline->seq;
        FD_COMPILER_MFENCE();
        
        if( FD_UNLIKELY( fd_seq_ne( seq_test, seq_found ) ) ) { /* Overrun while reading (impossible if this_in honoring our fctl) */
        FD_LOG_WARNING(( "Overrun detected. Consumer is behind by %ld sequences.", fd_seq_diff(seq_test, seq_found) ));
        this_in->seq = seq_test; /* Resume from here (probably reasonably current, could query in mcache sync instead) */        
        /* Don't bother with spin as polling multiple locations */
        long next = fd_tickcount();    
        now = next;
        continue;
        }
        
        /* We have successfully loaded the dcache. Write to the pcapng file */
        if (FD_UNLIKELY(tsorig > LONG_MAX)) {
            FD_LOG_WARNING(( "Tsorig too large for pcapng ts range" ));
            now = fd_tickcount();
            continue;
        }

        if( FD_UNLIKELY( 1UL!= fd_pcapng_fwrite_pkt((long)tsorig, (void const *)dc_scratch, sz, (void *)pcap_file)) ) {
            FD_LOG_WARNING(( "fd_pcapng_fwrite_pkt failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }

        /* Wind up for next iteration */ 

        this_in_seq    = fd_seq_inc( this_in_seq, 1UL );
        this_in->seq   = this_in_seq;
        this_in->mline = this_in->mcache + fd_mcache_line_idx( this_in_seq, this_in->depth );

        now = fd_tickcount();
    }


    do {
        FD_LOG_INFO(( "Stopping archive" ));

        FD_LOG_INFO(( "Closing pcap file" ));
        if (pcap_file) {
            fclose(pcap_file);
            pcap_file = NULL;
        }

        FD_LOG_INFO(( "Halted archive" ));
        fd_cnc_signal( cnc, FD_CNC_SIGNAL_BOOT );

    } while(0);

    return 0;
}
