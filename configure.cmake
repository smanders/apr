include(CheckCSourceCompiles)
include(CheckFunctionExists)
include(CheckIncludeFile)
include(CheckLibraryExists)
include(CheckStructHasMember)
include(CheckSymbolExists)
include(CheckTypeSize)
include(TestBigEndian)
########################################
function(set_define var)
  if(${ARGC} GREATER 1 AND ${var})
    set(DEFINE_${var} cmakedefine01 PARENT_SCOPE)
  else()
    set(DEFINE_${var} cmakedefine PARENT_SCOPE)
  endif()
  if(${var})
    set(APR_TEST_DEFINES "${APR_TEST_DEFINES} -D${var}" PARENT_SCOPE)
    set(CMAKE_REQUIRED_DEFINITIONS ${APR_TEST_DEFINES} PARENT_SCOPE)
  endif(${var})
endfunction()
##########
function(set01 var boolVar)
  if(${boolVar})
    set(${var} 1 PARENT_SCOPE)
  else()
    set(${var} 0 PARENT_SCOPE)
  endif()
endfunction()
##########
macro(check_struct_has_member01 struct member header variable)
  check_struct_has_member(${struct} ${member} ${header} ${variable})
  set_define(${variable} 1)
endmacro()
##########
macro(check_include_file_concat incfile var)
  if(${ARGC} GREATER 2)
    unset(code)
    foreach(arg ${ARGN})
      set(code "${code}#include <${arg}>\n")
    endforeach()
    set(code "${code}#include <${incfile}>
int main(void)
{
  return 0;
}
"     )
    check_c_source_compiles("${code}" ${var})
  else()
    check_include_file("${incfile}" ${var})
  endif()
  set_define(${var} 1)
  if(${var})
    set(APR_INCLUDES ${APR_INCLUDES} ${incfile})
  endif(${var})
endmacro()
##########
macro(check_exists_define01 func var)
  if(UNIX)
    check_function_exists("${func}" ${var})
  else()
    check_symbol_exists("${func}" "${APR_INCLUDES}" ${var})
  endif()
  set_define(${var} 1)
endmacro()
##########
macro(check_symbol_exists_define01 sym inc var)
  check_symbol_exists(${sym} "${inc}" ${var})
  set_define(${var} 1)
endmacro()
##########
macro(check_library_exists_concat lib symbol var)
  check_library_exists("${lib};${APR_SYSTEM_LIBS}" ${symbol} "${CMAKE_LIBRARY_PATH}" ${var})
  set_define(${var} 1)
  if(${var})
    set(APR_SYSTEM_LIBS ${lib} ${APR_SYSTEM_LIBS})
    set(CMAKE_REQUIRED_LIBRARIES ${APR_SYSTEM_LIBS})
  endif(${var})
endmacro()
########################################
check_include_file_concat(windows.h HAVE_WINDOWS_H)
if(HAVE_WINDOWS_H)
  set(WIN32_LEAN_AND_MEAN TRUE) # Define to avoid automatic inclusion of winsock.h
endif()
set_define(WIN32_LEAN_AND_MEAN)
check_include_file_concat(arpa/inet.h HAVE_ARPA_INET_H)
check_include_file_concat(conio.h HAVE_CONIO_H)
check_include_file_concat(crypt.h HAVE_CRYPT_H)
check_include_file_concat(ctype.h HAVE_CTYPE_H)
check_include_file_concat(dirent.h HAVE_DIRENT_H)
check_include_file_concat(errno.h HAVE_ERRNO_H)
check_include_file_concat(fcntl.h HAVE_FCNTL_H)
check_include_file_concat(io.h HAVE_IO_H)
check_include_file_concat(limits.h HAVE_LIMITS_H)
check_include_file_concat(netdb.h HAVE_NETDB_H)
check_include_file_concat(netinet/in.h HAVE_NETINET_IN_H)
check_include_file_concat(netinet/sctp.h HAVE_NETINET_SCTP_H)
check_include_file_concat(netinet/sctp_uio.h HAVE_NETINET_SCTP_UIO_H)
if(${CMAKE_SYSTEM_NAME} STREQUAL SunOS AND HAVE_NETINET_IN_H)
  # TRICKY: Solaris needs an extra include, netinet/tcp.h doesn't compile by itself
  set(additionalInc netinet/in.h)
endif()
check_include_file_concat(netinet/tcp.h HAVE_NETINET_TCP_H ${additionalInc})
check_include_file_concat(process.h HAVE_PROCESS_H)
check_include_file_concat(pthread.h HAVE_PTHREAD_H)
check_include_file_concat(semaphore.h HAVE_SEMAPHORE_H)
check_include_file_concat(signal.h HAVE_SIGNAL_H)
check_include_file_concat(stdarg.h HAVE_STDARG_H)
check_include_file_concat(stdint.h HAVE_STDINT_H)
check_include_file_concat(stdio.h HAVE_STDIO_H)
check_include_file_concat(stdlib.h HAVE_STDLIB_H)
check_include_file_concat(string.h HAVE_STRING_H)
check_include_file_concat(strings.h HAVE_STRINGS_H)
check_include_file_concat(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_file_concat(sys/sendfile.h HAVE_SYS_SENDFILE_H)
check_include_file_concat(sys/signal.h HAVE_SYS_SIGNAL_H)
check_include_file_concat(sys/socket.h HAVE_SYS_SOCKET_H)
check_include_file_concat(sys/sockio.h HAVE_SYS_SOCKIO_H)
check_include_file_concat(sys/syslimits.h HAVE_SYS_SYSLIMITS_H)
check_include_file_concat(sys/time.h HAVE_SYS_TIME_H)
check_include_file_concat(sys/types.h HAVE_SYS_TYPES_H)
check_include_file_concat(sys/uio.h HAVE_SYS_UIO_H)
check_include_file_concat(sys/un.h HAVE_SYS_UN_H)
check_include_file_concat(sys/wait.h HAVE_SYS_WAIT_H)
check_include_file_concat(time.h HAVE_TIME_H)
check_include_file_concat(unistd.h HAVE_UNISTD_H)
check_include_file_concat(winsock2.h HAVE_WINSOCK2_H)
check_include_file_concat(ByteOrder.h HAVE_BYTEORDER_H)
check_include_file_concat(dir.h HAVE_DIR_H)
check_include_file_concat(dlfcn.h HAVE_DLFCN_H)
check_include_file_concat(dl.h HAVE_DL_H)
check_include_file_concat(grp.h HAVE_GRP_H)
check_include_file_concat(inttypes.h HAVE_INTTYPES_H)
check_include_file_concat(kernel/OS.h HAVE_KERNEL_OS_H)
check_include_file_concat(langinfo.h HAVE_LANGINFO_H)
check_include_file_concat(mach-o/dyld.h HAVE_MACH_O_DYLD_H)
check_include_file_concat(malloc.h HAVE_MALLOC_H)
check_include_file_concat(memory.h HAVE_MEMORY_H)
check_include_file_concat(net/errno.h HAVE_NET_ERRNO_H)
check_include_file_concat(os2.h HAVE_OS2_H)
check_include_file_concat(osreldate.h HAVE_OSRELDATE_H)
check_include_file_concat(OS.h HAVE_OS_H)
check_include_file_concat(poll.h HAVE_POLL_H)
check_include_file_concat(pwd.h HAVE_PWD_H)
check_include_file_concat(sched.h HAVE_SCHED_H) #TODO: configure doesn't find
check_include_file_concat(stddef.h HAVE_STDDEF_H)
check_include_file_concat(sysapi.h HAVE_SYSAPI_H)
check_include_file_concat(sysgtime.h HAVE_SYSGTIME_H)
check_include_file_concat(sys/file.h HAVE_SYS_FILE_H)
check_include_file_concat(sys/ipc.h HAVE_SYS_IPC_H)
check_include_file_concat(sys/mman.h HAVE_SYS_MMAN_H)
check_include_file_concat(sys/mutex.h HAVE_SYS_MUTEX_H)
check_include_file_concat(sys/param.h HAVE_SYS_PARAM_H)
check_include_file_concat(sys/poll.h HAVE_SYS_POLL_H)
check_include_file_concat(sys/resource.h HAVE_SYS_RESOURCE_H)
check_include_file_concat(sys/select.h HAVE_SYS_SELECT_H)
check_include_file_concat(sys/sem.h HAVE_SYS_SEM_H)
check_include_file_concat(sys/shm.h HAVE_SYS_SHM_H)
check_include_file_concat(sys/stat.h HAVE_SYS_STAT_H)
check_include_file_concat(sys/sysctl.h HAVE_SYS_SYSCTL_H)
check_include_file_concat(sys/uuid.h HAVE_SYS_UUID_H)
check_include_file_concat(termios.h HAVE_TERMIOS_H)
check_include_file_concat(tpfeq.h HAVE_TPFEQ_H)
check_include_file_concat(tpfio.h HAVE_TPFIO_H)
check_include_file_concat(unix.h HAVE_UNIX_H)
check_include_file_concat(uuid.h HAVE_UUID_H)
check_include_file_concat(uuid/uuid.h HAVE_UUID_UUID_H)
check_include_file_concat(alloca.h HAVE_ALLOCA_H)
##########
check_library_exists_concat(bsd random HAVE_LIBBSD)
check_library_exists_concat(sendfile sendfilev HAVE_LIBSENDFILE)
check_library_exists_concat(truerand main HAVE_LIBTRUERAND)
check_library_exists_concat(rt shm_open HAVE_LIBRT)
check_library_exists_concat(pthread pthread_yield HAVE_LIBPTHREAD)
check_library_exists_concat(dl dlopen HAVE_LIBDL)
#check_library_exists_concat(ws2_32 getch HAVE_LIBWS2_32)
#check_library_exists_concat(resolve hstrerror HAVE_LIBRESOLVE)
#check_library_exists_concat(socket connect HAVE_LIBSOCKET)
#check_library_exists_concat(nsl gethostbyaddr HAVE_LIBNSL)
##########
check_exists_define01(accept4 HAVE_ACCEPT4)
check_exists_define01(calloc HAVE_CALLOC)
check_exists_define01(create_area HAVE_CREATE_AREA)
check_exists_define01(create_sem HAVE_CREATE_SEM)
check_exists_define01(dup3 HAVE_DUP3)
check_exists_define01(epoll_create1 HAVE_EPOLL_CREATE1)
check_exists_define01(fdatasync HAVE_FDATASYNC)
check_exists_define01(flock HAVE_FLOCK)
check_exists_define01(fork HAVE_FORK)
check_exists_define01(gai_strerror HAVE_GAI_STRERROR)
check_exists_define01(getenv HAVE_GETENV)
check_exists_define01(getgrgid_r HAVE_GETGRGID_R)
check_exists_define01(getgrnam_r HAVE_GETGRNAM_R)
check_exists_define01(gethostbyaddr_r HAVE_GETHOSTBYADDR_R)
check_exists_define01(gethostbyname_r HAVE_GETHOSTBYNAME_R)
check_exists_define01(getifaddrs HAVE_GETIFADDRS)
check_exists_define01(getnameinfo HAVE_GETNAMEINFO)
check_exists_define01(getpass HAVE_GETPASS)
check_exists_define01(getpassphrase HAVE_GETPASSPHRASE)
check_exists_define01(getpwnam_r HAVE_GETPWNAM_R)
check_exists_define01(getpwuid_r HAVE_GETPWUID_R)
check_exists_define01(getrlimit HAVE_GETRLIMIT)
check_exists_define01(getservbyname_r HAVE_GETSERVBYNAME_R)
check_exists_define01(gmtime_r HAVE_GMTIME_R)
check_exists_define01(isinf HAVE_ISINF)
check_exists_define01(isnan HAVE_ISNAN)
check_exists_define01(kqueue HAVE_KQUEUE)
check_exists_define01(localtime_r HAVE_LOCALTIME_R)
check_exists_define01(memchr HAVE_MEMCHR)
check_exists_define01(memmove HAVE_MEMMOVE)
check_exists_define01(mkstemp HAVE_MKSTEMP)
check_exists_define01(mkstemp64 HAVE_MKSTEMP64) #TODO: configure doesn't find
check_exists_define01(mmap HAVE_MMAP)
check_exists_define01(mmap64 HAVE_MMAP64) #TODO: configure doesn't find
check_exists_define01(munmap HAVE_MUNMAP)
check_exists_define01(nl_langinfo HAVE_NL_LANGINFO)
check_exists_define01(poll HAVE_POLL)
check_exists_define01(port_create HAVE_PORT_CREATE)
check_exists_define01(pthread_attr_setguardsize HAVE_PTHREAD_ATTR_SETGUARDSIZE)
check_exists_define01(pthread_key_delete HAVE_PTHREAD_KEY_DELETE)
check_exists_define01(pthread_mutexattr_setpshared HAVE_PTHREAD_MUTEXATTR_SETPSHARED)
check_exists_define01(pthread_rwlock_init HAVE_PTHREAD_RWLOCK_INIT)
check_exists_define01(pthread_yield HAVE_PTHREAD_YIELD)
check_exists_define01(putenv HAVE_PUTENV)
check_exists_define01(readdir64_r HAVE_READDIR64_R) #TODO: configure doesn't find
check_exists_define01(sched_yield HAVE_SCHED_YIELD) #TODO: configure doesn't find
check_exists_define01(semctl HAVE_SEMCTL)
check_exists_define01(semget HAVE_SEMGET)
check_exists_define01(sem_close HAVE_SEM_CLOSE)
check_exists_define01(sem_post HAVE_SEM_POST)
check_exists_define01(sem_unlink HAVE_SEM_UNLINK)
check_exists_define01(sem_wait HAVE_SEM_WAIT)
check_exists_define01(sendfile HAVE_SENDFILE)
check_exists_define01(sendfile64 HAVE_SENDFILE64) #TODO: configure doesn't find
check_exists_define01(sendfilev HAVE_SENDFILEV)
check_exists_define01(sendfilev64 HAVE_SENDFILEV64)
check_exists_define01(send_file HAVE_SEND_FILE)
check_exists_define01(setenv HAVE_SETENV)
check_exists_define01(setrlimit HAVE_SETRLIMIT)
check_exists_define01(setsid HAVE_SETSID)
check_exists_define01(set_h_errno HAVE_SET_H_ERRNO)
check_exists_define01(shmat HAVE_SHMAT)
check_exists_define01(shmctl HAVE_SHMCTL)
check_exists_define01(shmdt HAVE_SHMDT)
check_exists_define01(shmget HAVE_SHMGET)
check_exists_define01(shm_open HAVE_SHM_OPEN)
check_exists_define01(shm_unlink HAVE_SHM_UNLINK)
check_exists_define01(sigaction HAVE_SIGACTION)
check_exists_define01(sigsuspend HAVE_SIGSUSPEND)
check_exists_define01(sigwait HAVE_SIGWAIT)
check_exists_define01(strcasecmp HAVE_STRCASECMP)
check_exists_define01(strdup HAVE_STRDUP)
check_exists_define01(strerror_r HAVE_STRERROR_R)
check_exists_define01(stricmp HAVE_STRICMP)
check_exists_define01(strncasecmp HAVE_STRNCASECMP)
check_exists_define01(strnicmp HAVE_STRNICMP)
check_exists_define01(strstr HAVE_STRSTR)
check_exists_define01(unsetenv HAVE_UNSETENV)
check_exists_define01(utime HAVE_UTIME)
check_exists_define01(utimes HAVE_UTIMES)
check_exists_define01(uuid_create HAVE_UUID_CREATE)
check_exists_define01(uuid_generate HAVE_UUID_GENERATE)
check_exists_define01(waitpid HAVE_WAITPID)
check_exists_define01(writev HAVE_WRITEV)
##########
check_symbol_exists_define01(alloca alloca.h HAVE_ALLOCA)
check_symbol_exists_define01(BONE_VERSION sys/socket.h HAVE_BONE_VERSION)
check_symbol_exists_define01(F_SETLK fcntl.h HAVE_F_SETLK)
check_symbol_exists_define01(LOCK_EX sys/file.h HAVE_LOCK_EX)
check_symbol_exists_define01(MAP_ANON sys/mman.h HAVE_MAP_ANON)
check_symbol_exists_define01(POLLIN poll.h HAVE_POLLIN)
if(NOT HAVE_POLLIN)
  check_symbol_exists_define01(POLLIN sys/poll.h HAVE_POLLIN)
endif()
check_symbol_exists_define01(PTHREAD_PROCESS_SHARED pthread.h HAVE_PTHREAD_PROCESS_SHARED)
check_symbol_exists_define01(SEM_UNDO sys/sem.h HAVE_SEM_UNDO)
check_symbol_exists_define01(SO_ACCEPTFILTER sys/socket.h HAVE_SO_ACCEPTFILTER)
check_symbol_exists_define01(TCP_CORK netinet/tcp.h HAVE_TCP_CORK)
check_symbol_exists_define01(TCP_NOPUSH netinet/tcp.h HAVE_TCP_NOPUSH)
##########
set(CMAKE_EXTRA_INCLUDE_FILES ${APR_INCLUDES})
check_type_size(char SIZEOF_CHAR)
check_type_size(ino_t SIZEOF_INO_T) # sets HAVE_SIZEOF_INO_T
check_type_size(int SIZEOF_INT)
check_type_size(long SIZEOF_LONG)
check_type_size("long long" SIZEOF_LONG_LONG)
check_type_size(off_t SIZEOF_OFF_T) # sets HAVE_SIZEOF_OFF_T
check_type_size(pid_t SIZEOF_PID_T) # sets HAVE_SIZEOF_PID_T
check_type_size(short SIZEOF_SHORT)
check_type_size(size_t SIZEOF_SIZE_T) # sets HAVE_SIZEOF_SIZE_T
check_type_size(ssize_t SIZEOF_SSIZE_T) # sets HAVE_SIZEOF_SSIZE_T
check_type_size("struct iovec" SIZEOF_STRUCT_IOVEC) # sets HAVE_SIZEOF_STRUCT_IOVEC
check_type_size("void*" SIZEOF_VOIDP)
check_type_size("struct ip_mreq" STRUCT_IPMREQ) # sets HAVE_STRUCT_IPMREQ
set_define(HAVE_STRUCT_IPMREQ 1)
check_type_size(socklen_t SOCKLEN_T) # sets HAVE_SOCKLEN_T
set_define(HAVE_SOCKLEN_T 1)
check_type_size(gid_t GID_T) # sets HAVE_GIT_T
check_type_size(uid_t UID_T) # sets HAVE_UID_T
check_type_size("struct rlimit" STRUCT_RLIMIT) # sets HAVE_STRUCT_RLIMIT
set(CMAKE_EXTRA_INCLUDE_FILES)
########################################
if(NOT HAVE_GID_T)
  set(gid_t "int") # Define to `int' if <sys/types.h> doesn't define.
endif()
if(NOT HAVE_SIZEOF_OFF_T)
  set(off_t "long int") # Define to `long int' if <sys/types.h> does not define.
  set(off_t_value ${off_t}) # used by apr.h.in
else()
  set(off_t_value off_t) # used by apr.h.in
endif()
if(NOT HAVE_SIZEOF_PID_T)
  set(pid_t "int") # Define to `int' if <sys/types.h> does not define.
endif()
if(NOT HAVE_SIZEOF_SIZE_T)
  set(size_t "unsigned int") # Define to `unsigned int' if <sys/types.h> does not define.
  set(size_t_value apr_int32_t) # used by apr.h.in
else()
  set(size_t_value size_t) # used by apr.h.in
endif()
if(NOT HAVE_SIZEOF_SSIZE_T)
  if(HAVE_WINDOWS_H AND SIZEOF_SIZE_T EQUAL 8)
    set(ssize_t "__int64")
  else()
    set(ssize_t "int") # Define to `int' if <sys/types.h> does not define.
  endif()
  set(ssize_t_value apr_int32_t) # used by apr.h.in
else()
  set(ssize_t_value ssize_t) # used by apr.h.in
endif()
if(NOT HAVE_UID_T)
  set(uid_t "int") # Define to `int' if <sys/types.h> doesn't define.
endif()
if(NOT HAVE_SOCKLEN_T)
  set(socklen_t_value int)
else()
  set(socklen_t_value socklen_t)
endif()
if(NOT HAVE_SIZEOF_INO_T)
  set(ino_t_value apr_int64_t) #TODO: determine
else()
  set(ino_t_value ino_t)
endif()
########################################
if(HAVE_SYS_STAT_H)
  set(statHdr sys/stat.h)
else()
  set(statHdr unknown.h)
endif()
check_struct_has_member01("struct stat" st_atimensec ${statHdr} HAVE_STRUCT_STAT_ST_ATIMENSEC)
check_struct_has_member01("struct stat" st_atime_n ${statHdr} HAVE_STRUCT_STAT_ST_ATIME_N)
check_struct_has_member01("struct stat" st_atim.tv_nsec ${statHdr} HAVE_STRUCT_STAT_ST_ATIM_TV_NSEC)
check_struct_has_member01("struct stat" st_blocks ${statHdr} HAVE_STRUCT_STAT_ST_BLOCKS)
check_struct_has_member01("struct stat" st_ctimensec ${statHdr} HAVE_STRUCT_STAT_ST_CTIMENSEC)
check_struct_has_member01("struct stat" st_ctime_n ${statHdr} HAVE_STRUCT_STAT_ST_CTIME_N)
check_struct_has_member01("struct stat" st_ctim.tv_nsec ${statHdr} HAVE_STRUCT_STAT_ST_CTIM_TV_NSEC)
check_struct_has_member01("struct stat" st_mtimensec ${statHdr} HAVE_STRUCT_STAT_ST_MTIMENSEC)
check_struct_has_member01("struct stat" st_mtime_n ${statHdr} HAVE_STRUCT_STAT_ST_MTIME_N)
check_struct_has_member01("struct stat" st_mtim.tv_nsec ${statHdr} HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC)
if(HAVE_TIME_H)
  set(tmHdr time.h)
else()
  set(tmHdr unknown.h)
endif()
check_struct_has_member01("struct tm" tm_gmtoff ${tmHdr} HAVE_STRUCT_TM_TM_GMTOFF)
check_struct_has_member01("struct tm" __tm_gmtoff ${tmHdr} HAVE_STRUCT_TM___TM_GMTOFF)
########################################
# Define if building universal (internal helper macro)
set(AC_APPLE_UNIVERSAL_BUILD) #TODO: determine on Apple
set_define(AC_APPLE_UNIVERSAL_BUILD)
####################
# path of random device
if(EXISTS /dev/urandom)
  set(DEV_RANDOM /dev/urandom)
endif()
set_define(DEV_RANDOM)
####################
# Define to the sub-directory in which libtool stores uninstalled libraries.
execute_process(COMMAND libtool --version
  OUTPUT_QUIET ERROR_QUIET RESULT_VARIABLE hasLibtool
  )
if(hasLibtool EQUAL 0) # 0 == success
  set(LT_OBJDIR .libs/)
endif()
####################
# Name of package
set(PACKAGE "APR")
# Version number of package
file(STRINGS include/apr_version.h MAJOR REGEX "^#define[\t ]+APR_MAJOR_VERSION[ \t]+([0-9]+)")
file(STRINGS include/apr_version.h MINOR REGEX "^#define[\t ]+APR_MINOR_VERSION[ \t]+([0-9]+)")
file(STRINGS include/apr_version.h PATCH REGEX "^#define[\t ]+APR_PATCH_VERSION[ \t]+([0-9]+)")
string(REGEX MATCH "([0-9]+)" MAJOR ${MAJOR})
string(REGEX MATCH "([0-9]+)" MINOR ${MINOR})
string(REGEX MATCH "([0-9]+)" PATCH ${PATCH})
set(VERSION ${MAJOR}.${MINOR}.${PATCH})
# Define to the address where bug reports for this package should be sent.
set(PACKAGE_BUGREPORT "ASF Bugzilla: https://bz.apache.org/bugzilla/enter_bug.cgi?product=APR")
# Define to the full name of this package.
set(PACKAGE_NAME ${PACKAGE})
# Define to the version of this package.
set(PACKAGE_VERSION ${VERSION})
# Define to the full name and version of this package.
set(PACKAGE_STRING "${PACKAGE} ${PACKAGE_VERSION}")
# Define to the one symbol short name of this package.
set(PACKAGE_TARNAME ${PACKAGE})
# Define to the home page for this package.
set(PACKAGE_URL http://apr.apache.org)
####################
# Define to 1 if you have the ANSI C header files.
set(STDC_HEADERS TRUE) #TODO: determine if true
set_define(STDC_HEADERS 1)
####################
set(_ALL_SOURCE TRUE)
set_define(_ALL_SOURCE 1)
set(_GNU_SOURCE TRUE)
set_define(_GNU_SOURCE 1)
add_definitions(-D_GNU_SOURCE)
set(_POSIX_PTHREAD_SEMANTICS TRUE)
set_define(_POSIX_PTHREAD_SEMANTICS 1)
set(_TANDEM_SOURCE TRUE)
set_define(_TANDEM_SOURCE 1)
set(__EXTENSIONS__ TRUE) #TODO: determine (configure does)
set_define(__EXTENSIONS__ 1)
####################
# Define WORDS_BIGENDIAN to 1 if your processor stores words with the most
# significant byte first (like Motorola and SPARC, unlike Intel).
test_big_endian(WORDS_BIGENDIAN)
set_define(WORDS_BIGENDIAN 1)
########################################
set(apr_include_arpainet "
#ifdef HAVE_ARPA_INET_H
# include <arpa/inet.h>
#endif"
  )
set(apr_include_netdb "
#ifdef HAVE_NETDB_H
# include <netdb.h>
#endif"
  )
set(apr_include_netinetin "
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif"
  )
set(apr_include_netinetsctp "
#ifdef HAVE_NETINET_SCTP_H
# include <netinet/sctp.h>
#endif
#ifdef HAVE_NETINET_SCTP_UIO_H
# include <netinet/sctp_uio.h>
#endif"
  )
set(apr_include_stdint "
#ifdef HAVE_STDINT_H
# include <stdint.h>
#endif"
  )
set(apr_include_stdlib "
#ifdef HAVE_STDLIB_H
# include <stdlib.h>
#endif"
  )
set(apr_include_string "
#ifdef HAVE_STRING_H
# include <string.h>
#endif"
  )
set(apr_include_sysipc "
#ifdef HAVE_SYS_IPC_H
# include <sys/ipc.h>
#endif"
  )
set(apr_include_syssem "
#ifdef HAVE_SYS_SEM_H
# include <sys/sem.h>
#endif"
  )
set(apr_include_systypes "
#ifdef HAVE_SYS_TYPES_H
# include <sys/types.h>
#endif"
  )
set(apr_include_syssocket "
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif"
  )
set(apr_include_windows "
#ifdef HAVE_WINDOWS_H
# ifndef WIN32_LEAN_AND_MEAN
#  define WIN32_LEAN_AND_MEAN
# endif
# include <windows.h>
#endif"
  )
set(apr_include_winsock "
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif"
  )
########################################
# Define if getaddrinfo accepts the AI_ADDRCONFIG flag
check_c_source_compiles("
${apr_include_netdb}
${apr_include_string}
${apr_include_systypes}
${apr_include_syssocket}
int main(int argc, char **argv)
{
  struct addrinfo hints, *ai;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = AI_ADDRCONFIG;
  return getaddrinfo(\"localhost\", NULL, &hints, &ai) != 0;
}
" HAVE_GAI_ADDRCONFIG
  )
set_define(HAVE_GAI_ADDRCONFIG 1)
########################################
# Define to 1 if getaddrinfo exists and works well enough for APR
check_c_source_compiles("
${apr_include_netdb}
${apr_include_string}
${apr_include_systypes}
${apr_include_syssocket}
int main(void)
{
  struct addrinfo hints;
  struct addrinfo *ai = 0;
  int error;
  memset(&hints, 0, sizeof(hints));
  hints.ai_flags = AI_NUMERICHOST;
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  error = getaddrinfo(\"127.0.0.1\", NULL, &hints, &ai);
  if(error || !ai || ai->ai_addr->sa_family != AF_INET)
    exit(1); /* fail */
  exit(0);
}
" HAVE_GETADDRINFO
  )
set_define(HAVE_GETADDRINFO 1)
########################################
# Define to empty if `const' does not conform to ANSI C.
check_c_source_compiles("
int main()
{
#ifndef __cplusplus
  /* Ultrix mips cc rejects this sort of thing.  */
  typedef int charset[2];
  const charset cs = { 0, 0 };
  /* SunOS 4.1.1 cc rejects this.  */
  char const *const *pcpcc;
  char **ppc;
  /* NEC SVR4.0.2 mips cc rejects this.  */
  struct point {int x, y;};
  static struct point const zero = {0,0};
  /* AIX XL C 1.02.0.0 rejects this.
     It does not let you subtract one const X* pointer from another in
     an arm of an if-expression whose if-part is not a constant
     expression */
  const char *g = \"string\";
  pcpcc = &g + (g ? g-g : 0);
  /* HPUX 7.0 cc rejects these. */
  ++pcpcc;
  ppc = (char**) pcpcc;
  pcpcc = (char const *const *) ppc;
  { /* SCO 3.2v4 cc rejects this sort of thing.  */
    char tx;
    char *t = &tx;
    char const *s = 0 ? (char *) 0 : (char const *) 0;

    *t++ = 0;
    if (s) return 0;
  }
  { /* Someone thinks the Sun supposedly-ANSI compiler will reject this.  */
    int x[] = {25, 17};
    const int *foo = &x[0];
    ++foo;
  }
  { /* Sun SC1.0 ANSI compiler rejects this -- but not the above. */
    typedef const int *iptr;
    iptr p = 0;
    ++p;
  }
  { /* AIX XL C 1.02.0.0 rejects this sort of thing, saying
       \"k.c\", line 2.27: 1506-025 (S) Operand must be a modifiable lvalue. */
    struct s { int j; const int *ap[3]; } bx;
    struct s *b = &bx; b->j = 5;
  }
  { /* ULTRIX-32 V3.1 (Rev 9) vcc rejects this */
    const int foo = 10;
    if (!foo) return 0;
  }
  return !cs[0] && !zero.x;
#endif
  ;
  return 0;
}
" ANSI_CONST
  )
if(NOT ANSI_CONST)
  set(const empty)
endif()
set_define(const)
########################################
check_c_source_compiles("
${apr_include_systypes}
${apr_include_netinetin}
${apr_include_winsock}
int main(void)
{
  struct in_addr arg;
  arg.s_addr = htonl(INADDR_ANY);
  ;
  return 0;
}
" HAVE_IN_ADDR
  )
########################################
check_c_source_compiles("
${apr_include_systypes}
${apr_include_arpainet}
int main(void)
{
  inet_addr(\"127.0.0.1\");
  ;
  return 0;
}
" HAVE_INET_ADDR
  )
########################################
check_c_source_compiles("
${apr_include_systypes}
${apr_include_arpainet}
int main(void)
{
  inet_network(\"127.0.0.1\");
  ;
  return 0;
}
" HAVE_INET_NETWORK
  )
########################################
check_c_source_compiles("
${apr_include_systypes}
${apr_include_netinetin}
int main(void)
{
  struct sockaddr_storage sa;
  ;
  return 0;
}
" HAVE_SA_STORAGE
  )
########################################
check_c_source_compiles("
${apr_include_systypes}
${apr_include_sysipc}
${apr_include_syssem}
int main(void)
{
  union semun arg;
  semctl(0,0,0,arg);
  ;
  return 0;
}
" HAVE_UNION_SEMUN
  )
########################################
check_c_source_compiles("
${apr_include_systypes}
${apr_include_syssocket}
${apr_include_netinetin}
${apr_include_netinetsctp}
${apr_include_stdlib}
int main(void)
{
  int s, opt = 1;
  if ((s = socket(AF_INET, SOCK_STREAM, IPPROTO_SCTP)) < 0)
    exit(1);
  if (setsockopt(s, IPPROTO_SCTP, SCTP_NODELAY, &opt, sizeof(int)) < 0)
    exit(2);
  exit(0);
}
" HAVE_SCTP
  )
########################################
check_c_source_compiles("
${apr_include_systypes}
${apr_include_netinetin}
int main(void)
{
  struct sockaddr_in6 sa;
  ;
  return 0;
}
" HAVE_SOCKADDR_IN6
  )
########################################
check_c_source_compiles("
${apr_include_stdint}
int main(void)
{
#ifdef INT64_C
  return 0;
#else
  return 1;
#endif
}
" HAVE_INT64_C_DEFINED
  )
########################################
unset(inline)
########################################
set(APR_ALLOCATOR_USES_MMAP FALSE) #TODO: determine
set(APR_INT64_STRFN strtol) #TODO: determine
set(APR_OFF_T_STRFN strtol) #TODO: determine
set(CRAY_STACKSEG_END FALSE) #TODO: determine
set(C_ALLOCA FALSE) #TODO: determine
list(APPEND cmakedefine
  APR_INT64_STRFN
  APR_OFF_T_STRFN
  )
list(APPEND cmakedefine01
  APR_ALLOCATOR_USES_MMAP
  CRAY_STACKSEG_END
  C_ALLOCA
  )
########################################
set(DIRENT_INODE d_fileno) #TODO: determine
set(DIRENT_TYPE d_type) #TODO: determine
list(APPEND cmakedefine
  DIRENT_INODE
  DIRENT_TYPE
  )
########################################
# DSO support TODO: determine
set(DSO_USE_DLFCN TRUE) # uses dlfcn.h
set(DSO_USE_DYLD FALSE) # uses dyld.h
set(DSO_USE_SHL FALSE) # uses shl_load
list(APPEND cmakedefine01
  DSO_USE_DLFCN
  DSO_USE_DYLD
  DSO_USE_SHL
  )
########################################
set(EGD_DEFAULT_SOCKET FALSE) #TODO: determine
list(APPEND cmakedefine EGD_DEFAULT_SOCKET)
########################################
set(FCNTL_IS_GLOBAL FALSE) #TODO: determine
set(FCNTL_TRYACQUIRE_EACCES FALSE) #TODO: determine
set(FLOCK_IS_GLOBAL FALSE) #TODO: determine
list(APPEND cmakedefine01
  FCNTL_IS_GLOBAL
  FCNTL_TRYACQUIRE_EACCES
  FLOCK_IS_GLOBAL
  )
########################################
set(GETHOSTBYADDR_IS_THREAD_SAFE FALSE) #TODO: determine
set(GETHOSTBYNAME_IS_THREAD_SAFE FALSE) #TODO: determine
set(GETHOSTBYNAME_R_GLIBC2 TRUE) #TODO: determine
set(GETHOSTBYNAME_R_HOSTENT_DATA FALSE) #TODO: determine
set(GETSERVBYNAME_IS_THREAD_SAFE FALSE) #TODO: determine
set(GETSERVBYNAME_R_GLIBC2 TRUE) #TODO: determine
set(GETSERVBYNAME_R_OSF1 FALSE) #TODO: determine
set(GETSERVBYNAME_R_SOLARIS FALSE) #TODO: determine
list(APPEND cmakedefine01
  GETHOSTBYADDR_IS_THREAD_SAFE
  GETHOSTBYNAME_IS_THREAD_SAFE
  GETHOSTBYNAME_R_GLIBC2
  GETHOSTBYNAME_R_HOSTENT_DATA
  GETSERVBYNAME_IS_THREAD_SAFE
  GETSERVBYNAME_R_GLIBC2
  GETSERVBYNAME_R_OSF1
  GETSERVBYNAME_R_SOLARIS
  )
########################################
set(HAVE_DECL_SYS_SIGLIST TRUE) #TODO: determine
set01(HAVE_DECL_SYS_SIGLIST HAVE_DECL_SYS_SIGLIST)
########################################
set(HAVE_AIO_MSGQ FALSE) #TODO: determine
set(HAVE_ATOMIC_BUILTINS TRUE) #TODO: determine
set(HAVE_EGD FALSE) #TODO: determine
set(HAVE_EPOLL TRUE) #TODO: determine
set(HAVE_HSTRERROR FALSE) #TODO: determine
set(HAVE_PTHREAD_MUTEX_RECURSIVE TRUE) #TODO: determine
set(HAVE_PTHREAD_MUTEX_ROBUST TRUE) #TODO: determine
set(HAVE_PTHREAD_RWLOCKS TRUE) #TODO: determine
set(HAVE_SOCK_CLOEXEC TRUE) #TODO: determine
set(HAVE_TCP_NODELAY_WITH_CORK TRUE) #TODO: determine
set(HAVE_TRUERAND FALSE) #TODO: determine
set(HAVE_VLA TRUE) #TODO: determine
set(HAVE_ZOS_PTHREADS FALSE) #TODO: determine
list(APPEND cmakedefine01
  HAVE_AIO_MSGQ
  HAVE_ATOMIC_BUILTINS
  HAVE_EGD
  HAVE_EPOLL
  HAVE_HSTRERROR
  HAVE_PTHREAD_MUTEX_RECURSIVE
  HAVE_PTHREAD_MUTEX_ROBUST
  HAVE_PTHREAD_RWLOCKS
  HAVE_SOCK_CLOEXEC
  HAVE_TCP_NODELAY_WITH_CORK
  HAVE_TRUERAND
  HAVE_VLA
  HAVE_ZOS_PTHREADS
  )
########################################
set(NEGATIVE_EAI TRUE) #TODO: determine
set(POSIXSEM_IS_GLOBAL FALSE) #TODO: determine
set(PPC405_ERRATA FALSE) #TODO: determine
set(PTHREAD_ATTR_GETDETACHSTATE_TAKES_ONE_ARG FALSE) #TODO: determine
set(PTHREAD_GETSPECIFIC_TAKES_TWO_ARGS FALSE) #TODO: determine
set(READDIR_IS_THREAD_SAFE FALSE) #TODO: determine
set(SETPGRP_VOID TRUE) #TODO: determine
set(SIGWAIT_TAKES_ONE_ARG FALSE) #TODO: determine
set(STACK_DIRECTION FALSE) #TODO: determine
set(STRERROR_R_RC_INT FALSE) #TODO: determine
set(SYSVSEM_IS_GLOBAL FALSE) #TODO: determine
list(APPEND cmakedefine01
  NEGATIVE_EAI
  POSIXSEM_IS_GLOBAL
  PPC405_ERRATA
  PTHREAD_ATTR_GETDETACHSTATE_TAKES_ONE_ARG
  PTHREAD_GETSPECIFIC_TAKES_TWO_ARGS
  READDIR_IS_THREAD_SAFE
  SETPGRP_VOID
  SIGWAIT_TAKES_ONE_ARG
  STACK_DIRECTION
  STRERROR_R_RC_INT
  SYSVSEM_IS_GLOBAL
  )
########################################
set(USE_ATOMICS_GENERIC FALSE) #TODO: determine
set(USE_BEOSSEM FALSE) #TODO: determine
set(USE_FCNTL_SERIALIZE FALSE) #TODO: determine
set(USE_FLOCK_SERIALIZE FALSE) #TODO: determine
set(USE_SHMEM_BEOS FALSE) #TODO: determine
set(USE_SHMEM_BEOS_ANON FALSE) #TODO: determine
set(USE_SHMEM_MMAP_ANON TRUE) #TODO: determine
set(USE_SHMEM_MMAP_SHM FALSE) #TODO: determine
set(USE_SHMEM_MMAP_TMP FALSE) #TODO: determine
set(USE_SHMEM_MMAP_ZERO FALSE) #TODO: determine
set(USE_SHMEM_OS2 FALSE) #TODO: determine
set(USE_SHMEM_OS2_ANON FALSE) #TODO: determine
set(USE_SHMEM_SHMGET TRUE) #TODO: determine
set(USE_SHMEM_SHMGET_ANON FALSE) #TODO: determine
set(USE_SHMEM_WIN32 FALSE) #TODO: determine
set(USE_SHMEM_WIN32_ANON FALSE) #TODO: determine
list(APPEND cmakedefine01
  USE_ATOMICS_GENERIC
  USE_BEOSSEM
  USE_FCNTL_SERIALIZE
  USE_FLOCK_SERIALIZE
  USE_SHMEM_BEOS
  USE_SHMEM_BEOS_ANON
  USE_SHMEM_MMAP_ANON
  USE_SHMEM_MMAP_SHM
  USE_SHMEM_MMAP_TMP
  USE_SHMEM_MMAP_ZERO
  USE_SHMEM_OS2
  USE_SHMEM_OS2_ANON
  USE_SHMEM_SHMGET
  USE_SHMEM_SHMGET_ANON
  USE_SHMEM_WIN32
  USE_SHMEM_WIN32_ANON
  )
########################################
set(USE_SYSVSEM_SERIALIZE TRUE) #TODO: determine
set(WAITIO_USES_POLL TRUE) #TODO: determine
set(_MINIX FALSE) #TODO: determine
set(_POSIX_1_SOURCE FALSE) #TODO: determine
set(_POSIX_SOURCE FALSE) #TODO: determine
list(APPEND cmakedefine01
  USE_SYSVSEM_SERIALIZE
  WAITIO_USES_POLL
  _MINIX
  _POSIX_1_SOURCE
  _POSIX_SOURCE
  )
########################################
foreach(var ${cmakedefine01})
  set_define(${var} 1)
endforeach()
foreach(var ${cmakedefine})
  set_define(${var})
endforeach()
########################################
configure_file(${CMAKE_SOURCE_DIR}/include/arch/unix/apr_private.cmake.in .)
configure_file(${CMAKE_BINARY_DIR}/apr_private.cmake.in ${PROJECT_BINARY_DIR}/apr_private.h)
################################################################################
set01(arpa_ineth HAVE_ARPA_INET_H)
set01(conioh HAVE_CONIO_H)
set01(crypth HAVE_CRYPT_H)
set01(ctypeh HAVE_CTYPE_H)
set01(direnth HAVE_DIRENT_H)
set01(errnoh HAVE_ERRNO_H)
set01(fcntlh HAVE_FCNTL_H)
set01(ioh HAVE_IO_H)
set01(limitsh HAVE_LIMITS_H)
set01(netdbh HAVE_NETDB_H)
set01(netinet_inh HAVE_NETINET_IN_H)
set01(netinet_sctph HAVE_NETINET_SCTP_H)
set01(netinet_sctp_uioh HAVE_NETINET_SCTP_UIO_H)
set01(netinet_tcph HAVE_NETINET_TCP_H)
set01(processh HAVE_PROCESS_H)
set01(pthreadh HAVE_PTHREAD_H)
set01(semaphoreh HAVE_SEMAPHORE_H)
set01(signalh HAVE_SIGNAL_H)
set01(stdargh HAVE_STDARG_H)
set01(stdint HAVE_STDINT_H)
set01(stdioh HAVE_STDIO_H)
set01(stdlibh HAVE_STDLIB_H)
set01(stringh HAVE_STRING_H)
set01(stringsh HAVE_STRINGS_H)
set01(sys_ioctlh HAVE_SYS_IOCTL_H)
set01(sys_sendfileh HAVE_SYS_SENDFILE_H)
set01(sys_signalh HAVE_SYS_SIGNAL_H)
set01(sys_socketh HAVE_SYS_SOCKET_H)
set01(sys_sockioh HAVE_SYS_SOCKIO_H)
set01(sys_syslimitsh HAVE_SYS_SYSLIMITS_H)
set01(sys_timeh HAVE_SYS_TIME_H)
set01(sys_typesh HAVE_SYS_TYPES_H)
set01(sys_uioh HAVE_SYS_UIO_H)
set01(sys_unh HAVE_SYS_UN_H)
set01(sys_waith HAVE_SYS_WAIT_H)
set01(timeh HAVE_TIME_H)
set01(unistdh HAVE_UNISTD_H)
set01(windowsh HAVE_WINDOWS_H)
set01(winsock2h HAVE_WINSOCK2_H)
#####
set(HAVE_MMAP_TMP HAVE_SYS_MMAN_H AND HAVE_MMAP AND HAVE_MUNMAP)
set(HAVE_MMAP_SHM HAVE_MMAP_TMP AND HAVE_SHM_OPEN AND HAVE_SHM_UNLINK)
set(HAVE_MMAP_ZERO HAVE_MMAP_TMP AND EXISTS /dev/zero)
set(HAVE_SHM_HEADERS HAVE_SYS_IPC_H AND HAVE_SYS_SHM_H AND HAVE_SYS_FILE_H)
set(HAVE_SHM_FUNCS HAVE_SHMGET AND HAVE_SHMAT AND HAVE_SHMDT AND HAVE_SHMCTL)
set(HAVE_SHM_GETANON HAVE_SHM_HEADERS AND HAVE_SHM_FUNCS)
set(HAVE_SHM_GET HAVE_SHM_HEADERS AND HAVE_SHM_FUNCS)
set(HAVE_MMAP_ANON HAVE_MMAP_TMP AND HAVE_MAP_ANON)
set(HAVE_BEOS_AREA FALSE) # no tests in configure
set01(havemmaptmp HAVE_MMAP_TMP)
set01(havemmapshm HAVE_MMAP_SHM)
set01(havemmapzero HAVE_MMAP_ZERO)
set01(haveshmgetanon HAVE_SHM_GETANON)
set01(haveshmget HAVE_SHM_GET)
set01(havemmapanon HAVE_MMAP_ANON)
set01(havebeosarea HAVE_BEOS_AREA)
#####
set01(usemmaptmp USE_SHMEM_MMAP_TMP)
set01(usemmapshm USE_SHMEM_MMAP_SHM)
set01(usemmapzero USE_SHMEM_MMAP_ZERO)
set01(useshmgetanon USE_SHMEM_SHMGET_ANON)
set01(useshmget USE_SHMEM_SHMGET)
set01(usemmapanon USE_SHMEM_MMAP_ANON)
set01(usebeosarea USE_SHMEM_BEOS)
#####
set01(flockser USE_FLOCK_SERIALIZE)
set01(sysvser USE_SYSVSEM_SERIALIZE)
set01(posixser USE_POSIXSEM_SERIALIZE) # not in configure
set01(fcntlser USE_FCNTL_SERIALIZE) # in configure, not in apr_private
set01(procpthreadser USE_PROC_PTHREAD_SERIALIZE) # in configure, not in apr_private
set01(pthreadser HAVE_PTHREAD_H) # maybe more to do to determine?
#####
set(HAS_FLOCK_SER HAVE_FLOCK AND HAVE_LOCK_EX)
set(HAS_SYSV_SER HAVE_SEMGET AND HAVE_SEMCTL AND HAVE_SEM_UNDO)
set(HAS_POSIX_SER HAVE_SEMAPHORE_H AND HAVE_SEM_CLOSE AND HAVE_SEM_UNLINK AND HAVE_SEM_POST AND HAVE_SEM_WAIT)
set(HAS_FCNTL_SER HAVE_FCNTL_H AND HAVE_F_SETLK)
set(HAS_PROC_PTHREAD_SER HAVE_PTHREAD_H AND HAVE_PTHREAD_PROCESS_SHARED AND HAVE_PTHREAD_MUTEXATTR_SETPSHARED AND EXISTS /dev/zero)
set01(hasflockser HAS_FLOCK_SER)
set01(hassysvser HAS_SYSV_SER)
set01(hasposixser HAS_POSIX_SER)
set01(hasfcntlser HAS_FCNTL_SER)
set01(hasprocpthreadser HAS_PROC_PTHREAD_SER)
#####
set01(proclockglobal FALSE) #TODO: determine
#####
set01(have_corkable_tcp HAVE_TCP_CORK)
set01(have_getrlimit HAVE_GETRLIMIT)
set01(have_in_addr HAVE_IN_ADDR)
set01(have_inet_addr HAVE_INET_ADDR)
set01(have_inet_network HAVE_INET_NETWORK)
set(HAVE_IPV6 HAVE_SOCKADDR_IN6 AND HAVE_GETADDRINFO AND HAVE_GETNAMEINFO AND HAVE_GAI_ADDRCONFIG)
set01(have_ipv6 HAVE_IPV6)
set01(have_memmove HAVE_MEMMOVE)
set01(have_setrlimit HAVE_SETRLIMIT)
set01(have_sigaction HAVE_SIGACTION)
set01(have_sigsuspend HAVE_SIGSUSPEND)
set01(have_sigwait HAVE_SIGWAIT)
set01(have_sa_storage HAVE_SA_STORAGE)
set01(have_strcasecmp HAVE_STRCASECMP)
set01(have_strdup HAVE_STRDUP)
set01(have_stricmp HAVE_STRICMP)
set01(have_strncasecmp HAVE_STRNCASECMP)
set01(have_strnicmp HAVE_STRNICMP)
set01(have_strstr HAVE_STRSTR)
set01(have_memchr HAVE_MEMCHR)
set01(struct_rlimit HAVE_STRUCT_RLIMIT)
set01(have_union_semun HAVE_UNION_SEMUN)
set01(have_sctp HAVE_SCTP)
set01(have_iovec HAVE_SIZEOF_STRUCT_IOVEC)
#####
set(HAVE_SHAREDMEM USE_SHMEM_MMAP_TMP OR USE_SHMEM_MMAP_SHM OR USE_SHMEM_MMAP_ZERO OR USE_SHMEM_SHMGET OR
  USE_SHMEM_MMAP_ANON OR USE_SHMEM_BEOS OR USE_SHMEM_OS2 OR USE_SHMEM_WIN32)
set01(sharedmem HAVE_SHAREDMEM)
set01(threads TRUE) #TODO: determine
set01(sendfile TRUE) #TODO: determine
set01(mmap TRUE) #TODO: determine
set01(fork HAVE_FORK)
set01(rand TRUE) #TODO: determine
set01(oc TRUE) #TODO: determine
set01(aprdso DSO_USE_DLFCN OR DSO_USE_SHL OR DSO_USE_DYLD)
set01(acceptfilter HAVE_SO_ACCEPTFILTER)
set01(have_unicode_fs FALSE) #TODO: determine
set01(have_proc_invoked FALSE) #TODO: determine
set01(apr_has_user TRUE) #TODO: determine
set01(aprlfs FALSE) #TODO: determine
set01(apr_has_xthread_files FALSE) #TODO: determine
set01(osuuid FALSE) #TODO: determine
#####
set01(apr_procattr_user_set_requires_password FALSE) #TODO: determine
set01(file_as_socket TRUE) #TODO: determine
set01(apr_charset_ebcdic FALSE) #TODO: determine
set(apr_tcp_nopush_flag TCP_CORK) #TODO: determine
set01(tcp_nodelay_inherited TRUE) #TODO: determine
set01(o_nonblock_inherited FALSE) #TODO: determine
#####
if(SIZEOF_SHORT EQUAL 2)
  set(short_value short)
else()
  set(short_value unknown)
endif()
if(SIZEOF_INT EQUAL 4)
  set(int_value int)
else()
  set(int_value unknown)
endif()
set(voidp_size ${SIZEOF_VOIDP})
if(SIZEOF_INT EQUAL 8)
  set(int64_literal "#define APR_INT64_C(val) (val)")
  set(uint64_literal "#define APR_UINT64_C(val) (val##U)")
  set(int64_t_fmt "#define APR_INT64_T_FMT \"d\"")
  set(uint64_t_fmt "#define APR_UINT64_T_FMT \"u\"")
  set(uint64_t_hex_fmt "#define APR_UINT64_T_HEX_FMT \"x\"")
  set(long_value int)
elseif(SIZEOF_LONG EQUAL 8)
  set(int64_literal "#define APR_INT64_C(val) (val##L)")
  set(uint64_literal "#define APR_UINT64_C(val) (val##UL)")
  set(int64_t_fmt "#define APR_INT64_T_FMT \"ld\"")
  set(uint64_t_fmt "#define APR_UINT64_T_FMT \"lu\"")
  set(uint64_t_hex_fmt "#define APR_UINT64_T_HEX_FMT \"lx\"")
  set(long_value long)
elseif(SIZEOF_LONG_LONG EQUAL 8)
  set(int64_literal "#define APR_INT64_C(val) (val##LL)")
  set(uint64_literal "#define APR_UINT64_C(val) (val##ULL)")
  # Linux, Solaris, FreeBSD all support ll with printf.
  # BSD 4.4 originated 'q'. Solaris is more popular and
  # doesn't support 'q'. Solaris wins. Exceptions can
  # go to the OS-dependent section.
  set(int64_t_fmt "#define APR_INT64_T_FMT \"lld\"")
  set(uint64_t_fmt "#define APR_UINT64_T_FMT \"llu\"")
  set(uint64_t_hex_fmt "#define APR_UINT64_T_HEX_FMT \"llx\"")
  set(long_value "long long")
elseif(SIZEOF_LONG_LONG EQUAL 8)
  set(int64_literal "#define APR_INT64_C(val) (val##LL)")
  set(uint64_literal "#define APR_UINT64_C(val) (val##ULL)")
  set(int64_t_fmt "#define APR_INT64_T_FMT \"qd\"")
  set(uint64_t_fmt "#define APR_UINT64_T_FMT \"qu\"")
  set(uint64_t_hex_fmt "#define APR_UINT64_T_HEX_FMT \"qx\"")
  set(long_value "__int64")
else()
  message(FATAL_ERROR "could not detect a 64-bit integer type")
endif()
if(HAVE_INT64_C_DEFINED)
  set(int64_literal "#define APR_INT64_C(val) INT64_C(val)")
  set(uint64_literal "#define APR_UINT64_C(val) UINT64_C(val)")
endif()
#####
set01(bigendian WORDS_BIGENDIAN)
#####
set(apr_thread_func) # TODO: handle case where it should be set to __stdcall
###
if(${CMAKE_SYSTEM_NAME} STREQUAL SOME_PLATFORM) # TODO: handle other cases
  # where SOME_PLATFORM matches results from CMakeDetermineSystem.cmake:
  # AIX BSD/OS FreeBSD HP-UX IRIX Linux GNU/kFreeBSD NetBSD OpenBSD OSF1
  # SCO_SV UnixWare UNIX_SV Xenix SunOS Tru64 ULTRIX CYGWIN_NT-5.1 Darwin
else()
  set(ssize_t_fmt "#define APR_SSIZE_T_FMT \"ld\"")
  set(size_t_fmt "#define APR_SIZE_T_FMT \"lu\"")
endif()
if(HAVE_SIZEOF_OFF_T)
  if(SIZEOF_OFF_T EQUAL SIZEOF_LONG)
    set(off_t_fmt "#define APR_OFF_T_FMT \"ld\"")
  elseif(SIZEOF_OFF_T EQUAL SIZEOF_INT)
    set(off_t_fmt "#define APR_OFF_T_FMT \"d\"")
  elseif(SIZEOF_OFF_T EQUAL SIZEOF_LONG_LONG)
    set(off_t_fmt "#define APR_OFF_T_FMT APR_INT64_T_FMT")
  else()
    message(FATAL_ERROR "could not determine the size of off_t")
  endif()
else()
  message(FATAL_ERROR "could not determine APR_OFF_T_FMT")
endif()
if(HAVE_SIZEOF_PID_T)
  if(SIZEOF_PID_T EQUAL SIZEOF_SHORT)
    set(pid_t_fmt "#define APR_PID_T_FMT \"hd\"")
  elseif(SIZEOF_PID_T EQUAL SIZEOF_INT)
    set(pid_t_fmt "#define APR_PID_T_FMT \"d\"")
  elseif(SIZEOF_PID_T EQUAL SIZEOF_LONG)
    set(pid_t_fmt "#define APR_PID_T_FMT \"ld\"")
  elseif(SIZEOF_PID_T EQUAL SIZEOF_LONG_LONG)
    set(pid_t_fmt "#define APR_PID_T_FMT APR_INT64_T_FMT")
  else()
    message(FATAL_ERROR "could not determine the proper size for pid_t")
  endif()
else()
  message(FATAL_ERROR "could not determine APR_PID_T_FMT")
endif()
#####
set01(proc_mutex_is_global FALSE) #TODO: determine
if(MINGW OR OS2) #TODO: verify OS2 is a cmake variable
  set(eolstr \\r\\n)
  #set(shlibpath_var) #TODO: handle cases where it isn't LD_LIBRARY_PATH
else()
  set(eolstr \\n)
  set(shlibpath_var LD_LIBRARY_PATH)
endif()
configure_file(${CMAKE_SOURCE_DIR}/include/apr.h.in apr.h)
##########
set(CMAKE_REQUIRED_LIBRARIES)
set(CMAKE_REQUIRED_DEFINITIONS)
add_definitions(-DHAVE_CONFIG_H)
if(UNIX)
  add_definitions(-DCMAKE_UNIX)
endif()
