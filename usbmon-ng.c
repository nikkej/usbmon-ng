/******************************************************************************
 * 
 *     usbmon-ng.c
 *     Copyright(c) 2018 Juha T Nikkanen <nikkej@gmail.com>
 * 
 * --- Legal stuff ---
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 ******************************************************************************/

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <pthread.h>
#include <linux/limits.h>
#include <libudev.h>

//#define BLOCKING_IO
#define THREADS_COUNT       2
#define MSEC_10             10000
#define MSEC_100            100000
#define USBMON_DEVICE       "/dev/usbmon"
#define MAX_PACKETS         32
#define SETUP_LEN           8

struct usbmon_packet {
    uint64_t id;                    /*  0: URB ID - from submission to callback */
    uint8_t type;                   /*  8: Same as text; extensible. */
    uint8_t xfer_type;              /*    ISO (0), Intr, Control, Bulk (3) */
    uint8_t epnum;                  /*     Endpoint number and transfer direction */
    uint8_t devnum;                 /*     Device address */
    uint16_t busnum;                /* 12: Bus number */
    char flag_setup;                /* 14: Same as text */
    char flag_data;                 /* 15: Same as text; Binary zero is OK. */
    int64_t ts_sec;                 /* 16: gettimeofday */
    int32_t ts_usec;                /* 24: gettimeofday */
    int32_t status;                 /* 28: */
    uint32_t length;                /* 32: Length of data (submitted or actual) */
    uint32_t len_cap;               /* 36: Delivered length */
    union {                         /* 40: */
        uint8_t setup[SETUP_LEN];   /* Only for Control S-type */
        struct iso_rec {            /* Only for ISO */
            int32_t error_count;
            int32_t numdesc;
        } iso;
    } s;
    int32_t interval;               /* 48: Only for Interrupt and ISO */
    int32_t start_frame;            /* 52: For ISO */
    uint32_t xfer_flags;            /* 56: copy of URB's transfer_flags */
    uint32_t ndesc;                 /* 60: Actual number of ISO descriptors */
};                                  /* 64 total length */

struct mon_mfetch_arg {
    uint32_t *offvec;               /* Vector of events fetched */
    uint32_t nfetch;                /* Number of events to fetch (out: fetched) */
    uint32_t nflush;                /* Number of events to flush */
};

struct mon_bin_stats {
    uint32_t queued;                /* Number of events currently queued */
    uint32_t dropped;               /* Number of events lost since last call */
};

typedef struct {
    sigset_t                sMask;
    int32_t                 busNum;
    int32_t                 devNum;
    char                    devPath[PATH_MAX];
    char*                   idVendor;
    char*                   idProduct;
    int32_t                 runSnooper;
    int32_t                 usbmonFd;
    FILE*                   outputFile;
    uint8_t*                mbuf;
    int32_t                 kbufLen;
    int32_t                 totalEvents;
    struct mon_mfetch_arg   fetch;
    pthread_t               thread[THREADS_COUNT];
} threadArgs_t;

#define MON_IOC_MAGIC       0x92
#define MON_IOCQ_URB_LEN    _IO(MON_IOC_MAGIC, 1)
#define MON_IOCG_STATS      _IOR(MON_IOC_MAGIC, 3, struct mon_bin_stats)
#define MON_IOCT_RING_SIZE  _IO(MON_IOC_MAGIC, 4)
#define MON_IOCQ_RING_SIZE  _IO(MON_IOC_MAGIC, 5)
//#define MON_IOCX_GET        _IOW(MON_IOC_MAGIC, 6, struct mon_bin_get)
#define MON_IOCX_MFETCH     _IOWR(MON_IOC_MAGIC, 7, struct mon_mfetch_arg)
#define MON_IOCH_MFLUSH     _IO(MON_IOC_MAGIC, 8)

static struct udev* udev;
static struct udev_device* dev;
static struct udev_monitor* mon;
static threadArgs_t tArgs  = { 0 };
static pthread_mutex_t usbmonFd_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  usbmonFd_cond = PTHREAD_COND_INITIALIZER;

void sigHandler( int32_t sigNum, siginfo_t* sigInfo, void* ctx ) {
    for( int32_t i = 0; i < THREADS_COUNT; i++ ) {
        pthread_cancel( tArgs.thread[i] );
    }
}

void usbSnooperCleanUp( void* arg ) {
    struct mon_bin_stats stats = { 0 };

    if( tArgs.mbuf ) {
        ioctl( tArgs.usbmonFd, MON_IOCH_MFLUSH, tArgs.fetch.nfetch );
        int32_t ret = ioctl( tArgs.usbmonFd, MON_IOCG_STATS, &stats );
        if( ret == 0 ) {
            fprintf( stderr, "\n%d events captured\n", tArgs.totalEvents );
            fprintf( stderr, "%d events received by filter\n", tArgs.totalEvents + stats.queued );
            fprintf( stderr, "%d events dropped by kernel\n", stats.dropped );
        }
        munmap( tArgs.mbuf, tArgs.kbufLen << 1 );
        close( tArgs.usbmonFd );
        tArgs.usbmonFd = -1;
        tArgs.mbuf = NULL;
    }
}

void* usbSnooper( void* argP ) {
    int32_t run = 1;

    struct usbmon_packet *hdr;
    int32_t nflush;
    uint32_t vec[MAX_PACKETS];
    uint32_t i;
    void* addr;

    fd_set fdRecFrom;
    int32_t ret;

    pthread_cleanup_push( usbSnooperCleanUp, NULL );

    while( run ) {
        usbSnooperCleanUp( NULL );

        pthread_mutex_lock( &usbmonFd_lock );
        while( tArgs.usbmonFd <= 0 )
            pthread_cond_wait( &usbmonFd_cond, &usbmonFd_lock );
        pthread_mutex_unlock( &usbmonFd_lock );

        /* Create circular buffer */
        if( ( tArgs.kbufLen = ioctl( tArgs.usbmonFd, MON_IOCQ_RING_SIZE ) ) < 0 ) {
            fprintf( stderr, "ioctl query for kernel USB ring buffer size failed: %s\n", strerror( errno ) );
            pthread_exit( NULL );
        }

        if( ( tArgs.mbuf = (uint8_t*)mmap( NULL, tArgs.kbufLen << 1, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0 ) ) == MAP_FAILED ) {
            fprintf( stderr, "mmap call #1 for underlying double sized private map failed: %s\n", strerror( errno ) );
            pthread_exit( NULL );
        }
        if( ( addr = (uint8_t*)mmap( tArgs.mbuf, tArgs.kbufLen, PROT_READ, MAP_FIXED | MAP_SHARED, tArgs.usbmonFd, 0 ) ) != tArgs.mbuf ) {
            fprintf( stderr, "mmap call #2 for 1st half mirror shared map failed: %s\n", strerror( errno ) );
            pthread_exit( NULL );
        }
        if( ( addr = (uint8_t*)mmap( tArgs.mbuf + tArgs.kbufLen, tArgs.kbufLen, PROT_READ, MAP_FIXED | MAP_SHARED, tArgs.usbmonFd, 0 ) ) != tArgs.mbuf + tArgs.kbufLen ) {
            fprintf( stderr, "mmap call #3 for 2nd half mirror shared map failed: %s\n", strerror( errno ) );
            pthread_exit( NULL );
        }

        fprintf( stderr, "Kernel USB ring buffer size: %d bytes\n", tArgs.kbufLen );
        nflush = 0;

        while( tArgs.runSnooper ) {
            FD_ZERO( &fdRecFrom );
            FD_SET( tArgs.usbmonFd, &fdRecFrom );

            ret = pselect( tArgs.usbmonFd + 1, &fdRecFrom, NULL, NULL, NULL, &tArgs.sMask );
            if( ret > 0 && FD_ISSET( tArgs.usbmonFd, &fdRecFrom ) ) {
                tArgs.fetch.offvec = vec;
                tArgs.fetch.nfetch = MAX_PACKETS;
                tArgs.fetch.nflush = nflush;
#ifdef BLOCKING_IO
                ioctl( tArgs.usbmonFd, MON_IOCX_MFETCH, &tArgs.fetch );
#else
                int32_t ioRet = 0;
                do {
                    ioRet = ioctl( tArgs.usbmonFd, MON_IOCX_MFETCH, &tArgs.fetch );
                    if( ioRet < 0 ) {
                        usleep( MSEC_10 );
                    }
                } while( ioRet < 0 && errno == EWOULDBLOCK );
#endif
                nflush = tArgs.fetch.nfetch;
                tArgs.totalEvents += nflush;
                for( i = 0; i < nflush; i++ ) {
                    hdr = ( struct usbmon_packet* ) &tArgs.mbuf[vec[i]];
                    if( hdr->busnum == tArgs.busNum && hdr->devnum == tArgs.devNum ) {
                        if( hdr->len_cap ) {
                            //fprintf( stderr, "From offset %ld, len_cap: %d bytes, length: %d\n", &tArgs.mbuf[vec[i]] - tArgs.mbuf, hdr->len_cap, hdr->length );
                            fwrite( &tArgs.mbuf[vec[i]], hdr->len_cap + sizeof( struct usbmon_packet ), 1, tArgs.outputFile );
                        }
                    }
                }
            }
        }
    }

    pthread_cleanup_pop( 1 );

    pthread_exit( NULL );
}

void openUSBMonitorFd( int* fd, const int32_t bus ) {
    char path[PATH_MAX];
#ifdef BLOCKING_IO
    int32_t flags = O_RDONLY;
#else
    int32_t flags = O_RDONLY | O_NONBLOCK;
#endif    
    snprintf( path, PATH_MAX - 1, "%s%d", USBMON_DEVICE, bus );
    if( ( *fd = open( path, flags ) ) == -1 ) {
        fprintf( stderr, "unable to open %s: %s\n", path, strerror( errno ) );
    }
}

void matchUSBDevice( struct udev_device* dev ) {
    const char* v = udev_device_get_sysattr_value( dev, "idVendor" );
    const char* p = udev_device_get_sysattr_value( dev, "idProduct" );
    if( ( v && p && tArgs.idVendor && tArgs.idProduct ) \
    && strncmp( tArgs.idVendor, v, 4 ) == 0 \
    &&  strncmp( tArgs.idProduct, p, 4 ) == 0 ) {
        strncpy( tArgs.devPath, udev_device_get_devpath( dev ), PATH_MAX - 1 );
        tArgs.busNum = atoi( udev_device_get_sysattr_value( dev, "busnum" ) );
        tArgs.devNum = atoi( udev_device_get_sysattr_value( dev, "devnum" ) );

        pthread_mutex_lock( &usbmonFd_lock );
        openUSBMonitorFd( &tArgs.usbmonFd, tArgs.busNum );
        pthread_mutex_unlock( &usbmonFd_lock );
        if( tArgs.usbmonFd > 0 ) {
            tArgs.runSnooper = 1;
            pthread_cond_signal( &usbmonFd_cond );
        }
    }
}

void scanUSBDevices( struct udev* udev ) {
    struct udev_enumerate* udevEnum;
    struct udev_list_entry* listEntry;
    struct udev_device* device;

    udevEnum = udev_enumerate_new( udev );
    if ( udevEnum == NULL ) {
        fprintf( stderr, "Can't create udev enumeration object\n" );
        return;
    }
    
    udev_enumerate_add_match_subsystem( udevEnum, "usb" );
    udev_enumerate_scan_devices( udevEnum );

    udev_list_entry_foreach( listEntry, udev_enumerate_get_list_entry( udevEnum ) ) {
        device = udev_device_new_from_syspath( udev_enumerate_get_udev( udevEnum ),
                                               udev_list_entry_get_name( listEntry ) );
        if ( device != NULL ) {
            matchUSBDevice( device );
            udev_device_unref( device );
        }
    }

    udev_enumerate_unref( udevEnum );
}

void udevCleanUp( void* arg ) {
    if( dev )
        udev_device_unref( dev );
    if( mon ) {
        udev_monitor_filter_remove( mon );
        udev_monitor_unref( mon );
    }
    if( udev )
        udev_unref( udev );
}

void* udevEventListener( void* argP ) {
    int32_t run = 1;

    pthread_cleanup_push( udevCleanUp, NULL );

    udev = udev_new();
    if( !udev ) {
        fprintf( stderr, "Can't create udev object\n" );
        pthread_exit( NULL );
    }

    scanUSBDevices( udev );

    int32_t fd;
    mon = udev_monitor_new_from_netlink( udev, "udev" );
    udev_monitor_filter_add_match_subsystem_devtype( mon, "usb", NULL );
    udev_monitor_enable_receiving( mon );
    fd = udev_monitor_get_fd( mon );

    fd_set fdRecFrom;
    int32_t ret;

    while( run ) {
        FD_ZERO( &fdRecFrom );
        FD_SET( fd, &fdRecFrom );

        ret = pselect( fd + 1, &fdRecFrom, NULL, NULL, NULL, &tArgs.sMask );
        if( ret > 0 && FD_ISSET( fd, &fdRecFrom ) ) {
            dev = udev_monitor_receive_device( mon );
            if( dev ) {
                if( strncmp( "add", udev_device_get_action( dev ), 3 ) == 0 ) {
                    /* Function matchUSBDevice captures the sys path for device 
                     * descriptor from first 'add' event. Subsequent event(s) 
                     * would give path for interface descriptor(s) */
                    matchUSBDevice( dev );
                } else if( strncmp( "remove", udev_device_get_action( dev ), 6 ) == 0 
                && strlen( tArgs.devPath ) == strlen( udev_device_get_devpath( dev ) )
                && strncmp( tArgs.devPath, udev_device_get_devpath( dev ), strlen( tArgs.devPath ) ) == 0 ) {
                    /* First 'remove' event(s) gives us interface descriptor path(s),
                     * and this branch waits for device descriptor path which seems
                     * to come with last remove event */
                    /* suspend snoop thread */
                    tArgs.runSnooper = 0;
                }
                udev_device_unref( dev );
                dev = NULL;
            }
        }
    }

    pthread_cleanup_pop( 1 );

    pthread_exit( NULL );
}

void usage1( void ) {
    fprintf( stderr, "Invalid format for device id, shall be vId:pId\n" );
    fprintf( stderr, "where both Id's are given in hexadecimal\n" );
}

void usage2( char* exeName ) {
    fprintf( stderr, "Usage: \n" );
    fprintf( stderr, "%s -d <vId:pId> where both Id's are given in hexadecimal\n", exeName );
    fprintf( stderr, " -f <filename> where file name refers to binary output data\n" );
}

int main( int32_t argc, char** argv ) {
    struct sigaction act;
    int32_t opt;
    int32_t mandatoryOpts = 0;

    while( ( opt = getopt( argc, argv, "d:f:" ) ) != -1 ) {
        switch ( opt ) {
        case 'd':
            if( strlen( optarg ) != 9 || strspn( optarg, "01234567890abcdef:" ) != 9 ) {
                usage1();
                return( -1 );
            }
            else {
                sscanf( optarg, "%m[a-f0-9]:%m[a-f0-9]", &tArgs.idVendor, &tArgs.idProduct );
                mandatoryOpts++;
            }
            break;
        case 'f':
            if( optarg && ( tArgs.outputFile = fopen( optarg, "w+b" ) ) == NULL ) {
                fprintf( stderr, "Could not open %s for writing data: %s\n", optarg, strerror( errno ) );
                return( -1 );
            }
            mandatoryOpts++;
            break;
        }
    }

    if( mandatoryOpts < 2 ) {
        usage2( *argv );
        return( -1 );
    }

    /* Block all but SIGINT and SIGTERM */
    sigfillset( &tArgs.sMask );
    sigdelset( &tArgs.sMask, SIGINT );
    sigdelset( &tArgs.sMask, SIGTERM );
    pthread_sigmask( SIG_BLOCK, &tArgs.sMask, NULL );

    int32_t ret[THREADS_COUNT] = { 0 };
    ret[0] = pthread_create( &tArgs.thread[0], NULL, udevEventListener, (void*)&tArgs );
    ret[1] = pthread_create( &tArgs.thread[1], NULL, usbSnooper, (void*)&tArgs );
    if( ret[0] != 0 || ret[1] != 0 ) {
        fprintf( stderr, "Error in pthread_create\n" );
        fprintf( stderr, "pthead_create for udevEventListener: %s\n", strerror( ret[0] ) );
        fprintf( stderr, "pthead_create for usbSnooper: %s\n", strerror( ret[1] ) );
        goto fail_out;
    }

    /* Now prepare to catch SIGINT and SIGTERM */
    act.sa_sigaction = sigHandler;
    sigemptyset( &act.sa_mask );
    act.sa_flags = SA_SIGINFO;
    sigaction( SIGINT, &act, NULL );
    sigaction( SIGTERM, &act, NULL );

    for( int32_t i = 0; i < THREADS_COUNT; i++ ) {
        pthread_join( tArgs.thread[i], NULL );
    }

fail_out:
    free( tArgs.idVendor );
    free( tArgs.idProduct );
    if( tArgs.outputFile ) {
        fclose( tArgs.outputFile );
    }
    return( 0 );
}
