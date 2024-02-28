#include "fd_archive.h"

#include <stdio.h>
#include <errno.h>

ulong 
fd_archive_tile_scratch_align( void ) {
    return FD_ARCHIVE_TILE_SCRATCH_ALIGN;
}

int 
fd_archive_tile( fd_cnc_t *             cnc,
                 char const *           pcap_path,        
                 fd_frag_meta_t const * mcache,
                 uchar const *          dcache,
                 ulong                  cr_max,
                 long                   lazy,
                 fd_rng_t *             rng,
                 void *                 scratch ) {

    /* pcap stream state */
    FILE *  pcap_file;  /* handle of pcap file stream */    

    /* in frag stream state */
    ulong   depth;      /* depth of the mcache / positive integer power of 2 */
    ulong * sync;       /* local addr where archive mcache sync info is published */
    ulong   rx_seq;     /* estimate of where the consumer currently is */
    ulong   tx_seq;     /* estimate of where the producer currently is */

    fd_frag_meta_t          meta[1];         /* location on the caller where the wait saves found metadata */
    fd_frag_meta_t  const * mline;           /* location where the caller can verify if it has been overrun by producer */
    long                    seq_diff;        /* sequence numbers ahead of seq_expected */

    /* housekeeping state */
    ulong async_min;    /* minimum number of ticks between processing a housekeeping event, positive integer power of 2 */
    ulong poll_max;     /* is the number of times FD_MCACHE_WAIT will poll the mcache */

    do {
        if( FD_UNLIKELY( !scratch ) ) {
            FD_LOG_WARNING(( "NULL scratch" ));
            return 1;
        }

        if( FD_UNLIKELY( !fd_ulong_is_aligned( (ulong)scratch, fd_archive_tile_scratch_align() ) ) ) {
            FD_LOG_WARNING(( "misaligned scratch" ));
            return 1;
        }

        FD_SCRATCH_ALLOC_INIT( l, scratch );

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
        fd_pcapng_idb_opts_t idb_opts = {};
        fd_pcapng_idb_defaults(&idb_opts, 0);
        fd_pcapng_fwrite_idb(FD_PCAPNG_LINKTYPE_ETHERNET, &idb_opts, pcap_file);

        /* in frag stream init */
        
        if( FD_UNLIKELY( !mcache ) ) { FD_LOG_WARNING(( "NULL mcache" )); return 1; }
        depth = fd_mcache_depth(mcache);
        sync  = fd_mcache_seq_laddr( mcache );
        rx_seq = fd_mcache_seq_query( sync );
        
        if( FD_UNLIKELY( !dcache ) ) { FD_LOG_WARNING(( "NULL dcache" )); return 1; }

        poll_max = ULONG_MAX;
        
        /* housekeeping init */

        if( lazy<=0L ) lazy = fd_tempo_lazy_default( cr_max );
        FD_LOG_INFO(( "Configuring housekeeping (lazy %li ns)", lazy ));

        async_min = fd_tempo_async_min( lazy, 1UL, (float)fd_tempo_tick_per_ns( NULL ) );
        if( FD_UNLIKELY( !async_min ) ) { FD_LOG_WARNING(( "bad lazy" )); return 1; }

    } while(0);


    FD_LOG_INFO(( "Running archive" ));
    fd_cnc_signal( cnc, FD_CNC_SIGNAL_RUN );
    long then = fd_tickcount();
    long now = then;
    for(;;) {
        FD_MCACHE_WAIT(meta, mline, tx_seq, seq_diff, poll_max, mcache, depth, rx_seq);
        
        /* housekeeping */
        if( FD_UNLIKELY( (now-then)>=0L ) ) {
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
            
            /* Reload housekeeping timer */
            then = now + (long)fd_tempo_async_reload( rng, async_min );   
        }

        if (FD_UNLIKELY(seq_diff)) {
            /*  Caller has fallen more than depth behind the producer
                Metadata for frag seq_expected is no longer available via the mcache  */
            FD_LOG_WARNING(( "Overrun detected. Consumer is behind by %ld sequences.", seq_diff ));
            rx_seq = tx_seq;
            now = fd_tickcount();
            continue;
        }

        /* Process actual frag data */
        ulong chunk_idx = meta->chunk;
        ulong data_sz = meta->sz;
        ulong data_offset = chunk_idx * FD_DCACHE_ALIGN;        
        uchar *data = dcache + data_offset;
                
        fd_memcpy(scratch, data, data_sz);

        tx_seq = fd_frag_meta_seq_query(mline);
        if (FD_UNLIKELY(fd_seq_ne(tx_seq, rx_seq))) {
            FD_LOG_WARNING(( "Overrun detected. Consumer is behind by %ld sequences.", fd_seq_diff(tx_seq, rx_seq) ));
            now = fd_tickcount();
            continue;
        }

        if (FD_UNLIKELY(meta->tsorig > LONG_MAX)) {
            FD_LOG_WARNING(( "Tsorig too large for pcapng ts range" ));
            now = fd_tickcount();
            continue;
        }
            
        if( FD_UNLIKELY( 1UL!= fd_pcapng_fwrite_pkt((long)meta->tsorig, (void const *)scratch, (ulong)meta->sz, (void *)pcap_file)) ) {
            FD_LOG_WARNING(( "fd_pcapng_fwrite_pkt failed (%i-%s)", errno, fd_io_strerror( errno ) ));
        }

        /* Next iteration */ 
        now = fd_tickcount();
        rx_seq = fd_seq_inc(rx_seq, 1UL);
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
