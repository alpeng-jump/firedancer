$(call add-hdrs,fd_archive.h)
$(call add-objs,fd_archive,fd_disco)
$(call make-bin,fd_archive_tile,fd_archive_tile,fd_disco fd_tango fd_util)
