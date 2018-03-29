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
#include <pcap/pcap.h>
#include <pcap/usb.h>


#define  THREADS_COUNT  2

typedef struct {
    sigset_t        sMask;
    int32_t         busNum;
    int32_t         devNum;
    char            devPath[PATH_MAX];
    char*           idVendor;
    char*           idProduct;
    int32_t         usbmonFd;
    char            outputFile[PATH_MAX];
    pcap_t*         pcapHandle;
    pcap_dumper_t*  pcapFile;
    int32_t         append;
    int32_t         totalEvents;
    int32_t         filteredEvents;
    pthread_t       thread[THREADS_COUNT];
} threadArgs_t;

static struct udev* udev;
static struct udev_device* dev;
static struct udev_monitor* mon;
static threadArgs_t tArgs  = { 0 };
static volatile int32_t runSnooper;
static pthread_mutex_t runSnooper_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  runSnooper_cond = PTHREAD_COND_INITIALIZER;

void sigHandler( int32_t sigNum, siginfo_t* sigInfo, void* ctx ) {
    for( int32_t i = 0; i < THREADS_COUNT; i++ ) {
        pthread_cancel( tArgs.thread[i] );
    }
}

void usbSnooperCleanUp( void* arg ) {
    struct pcap_stat stats = { 0 };

    if( tArgs.pcapHandle ) {
        int32_t ret = pcap_stats( tArgs.pcapHandle, &stats );
        if( ret == 0 ) {
            fprintf( stderr, "\n%d events captured\n", stats.ps_recv );
            fprintf( stderr, "%d events dropped by kernel\n", stats.ps_drop );
            fprintf( stderr, "%d events dropped by driver\n", stats.ps_ifdrop );
        }
        pcap_dump_close( tArgs.pcapFile );
        pcap_close( tArgs.pcapHandle );
        tArgs.pcapHandle = NULL;
        tArgs.pcapFile = NULL;
    }
}

void pcapCallback( u_char* bp, const struct pcap_pkthdr* header, const u_char* data ) {
    tArgs.totalEvents++;
    pcap_usb_header* usb_header = (pcap_usb_header*)data;
    if( usb_header->device_address == tArgs.devNum ) {
        tArgs.filteredEvents++;
        pcap_dump( (u_char*)tArgs.pcapFile, header, data );
    }
    fprintf( stderr, "Total events on bus #: %d, device events #: %d\r", tArgs.totalEvents, tArgs.filteredEvents );
}

void* usbSnooper( void* argP ) {
    int32_t run = 1;

    char errBuf[PCAP_ERRBUF_SIZE] = { 0 };
    char deviceName[16];
    fd_set fdRecFrom;
    int32_t ret;

    pthread_cleanup_push( usbSnooperCleanUp, NULL );

    while( run ) {
        usbSnooperCleanUp( NULL );

        pthread_mutex_lock( &runSnooper_lock );
        while( !runSnooper )
            pthread_cond_wait( &runSnooper_cond, &runSnooper_lock );
        pthread_mutex_unlock( &runSnooper_lock );

        snprintf( deviceName, 16, "usbmon%d", tArgs.busNum );
        if( ( tArgs.pcapHandle = pcap_open_live( deviceName, 65536, 1, 1000, errBuf ) ) == NULL ) {
            fprintf( stderr, "pcap_open_live: %s\n", errBuf );
            pthread_mutex_lock( &runSnooper_lock );
            runSnooper = 0;
            pthread_mutex_unlock( &runSnooper_lock );
            continue;
        }
        pcap_setnonblock( tArgs.pcapHandle, 1, errBuf );
        if( tArgs.append ) {
            tArgs.pcapFile = pcap_dump_open_append( tArgs.pcapHandle, tArgs.outputFile );
        } else {
            tArgs.pcapFile = pcap_dump_open( tArgs.pcapHandle, tArgs.outputFile );
        }
        tArgs.usbmonFd = pcap_get_selectable_fd( tArgs.pcapHandle );

        while( runSnooper ) {
            FD_ZERO( &fdRecFrom );
            FD_SET( tArgs.usbmonFd, &fdRecFrom );

            ret = pselect( tArgs.usbmonFd + 1, &fdRecFrom, NULL, NULL, NULL, &tArgs.sMask );
            if( ret > 0 && FD_ISSET( tArgs.usbmonFd, &fdRecFrom ) ) {
                if( pcap_dispatch( tArgs.pcapHandle, 1, pcapCallback, NULL ) < 0 ) {
                     fprintf( stderr, "pcap_dispatch: %s\n", pcap_geterr( tArgs.pcapHandle ) );
                     pthread_mutex_lock( &runSnooper_lock );
                     runSnooper = 0;
                     pthread_mutex_unlock( &runSnooper_lock );
                }
            }
        }
    }

    pthread_cleanup_pop( 1 );

    pthread_exit( NULL );
}

void matchUSBDevice( struct udev_device* dev ) {
    const char* v = udev_device_get_sysattr_value( dev, "idVendor" );
    const char* p = udev_device_get_sysattr_value( dev, "idProduct" );
    if( ( v && p && tArgs.idVendor && tArgs.idProduct ) \
    && strncmp( tArgs.idVendor, v, 4 ) == 0 \
    && strncmp( tArgs.idProduct, p, 4 ) == 0 ) {
        strncpy( tArgs.devPath, udev_device_get_devpath( dev ), PATH_MAX - 1 );
        tArgs.busNum = atoi( udev_device_get_sysattr_value( dev, "busnum" ) );
        tArgs.devNum = atoi( udev_device_get_sysattr_value( dev, "devnum" ) );

        pthread_mutex_lock( &runSnooper_lock );
        runSnooper = 1;
        pthread_mutex_unlock( &runSnooper_lock );
        pthread_cond_signal( &runSnooper_cond );
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
                    pthread_mutex_lock( &runSnooper_lock );
                    runSnooper = 0;
                    pthread_mutex_unlock( &runSnooper_lock );
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
    fprintf( stderr, "Usage: %s -df[a]\n", exeName );
    fprintf( stderr, "  -a            Append to existing pcap file\n" );
    fprintf( stderr, "  -d <vId:pId>  Where both Id's are given in hexadecimal\n" );
    fprintf( stderr, "  -f <filename> Where file name refers to binary output data\n" );
}

int main( int32_t argc, char** argv ) {
    struct sigaction act;
    int32_t opt;
    int32_t mandatoryOpts = 0;

    while( ( opt = getopt( argc, argv, "ad:f:" ) ) != -1 ) {
        switch ( opt ) {
        case 'a':
            tArgs.append = 1;
            break;
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
            strncpy( tArgs.outputFile, optarg, PATH_MAX );
            tArgs.outputFile[PATH_MAX-1] = 0;
            mandatoryOpts++;
            break;
        }
    }

    if( mandatoryOpts < 2 ) {
        usage2( *argv );
        return( -1 );
    }

    /* Check if output file exist already */
    if( access( tArgs.outputFile, F_OK | W_OK ) != 0 ) {
        /* File will be created */
        tArgs.append = 0;
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
    return( 0 );
}
