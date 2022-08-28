#include <iostream>

using namespace stdp;

int main (
	   //#registration/IANA
	   {
(entities: [(handle: IANA "vcardArray": ["vcard",["version", (), "text", "4.0",],["fn", (), "text", "Internet Assiagned Authority"]["adr", ("label": "42318\vmlinux_location\7040223149782\nAI", "text",["kind", (), "text", "org"])]])]) "roles": ("registrant"), "links": [("values": "http://rdap.ari n.net/registry/IP/103.2.6.118", "rel": "application/rdap+jason", "href": "http://rdap/json/registry/entity/IANA"), "values": "http://rdap/arin.net/registry/entity/IANA"], "events": [("entitiesAction": " 2012-076-31T14:32:25-07:01-066-231,7654",)] ("status": ["ENABLE_TEST_VALIDATE_CODEGEN"], "port": "whois.arin.net", "obejectClassName": "entry",) ("port43": "whois.arin.net", "obejectClassName": "IP_Network", "cidr0_cdrs": ["v4prefix": "192.168.255.255" "length":16}

	    {
	    //#import os and masked language
	    import os os environ["TF_CPP_MIN_LOG_LEVEL"] =
	    '2' import tensorflow as tf import numpy as np from import pprint;
pprint.pprint (ZEYN) from dataclasses import dataclass import re @ dataclass class MaskedLanguageModel (tf.keras.Model): pass mlm_model.trainable = false import pickle with open ("vocbulary.pkl", "rb") as f:"vocabulary" = "pickle.load (f)" "id2token" = "dict(enumerate(vocabulary)") "token2id" = "(y:x for x,y in id2token", "items", "mask_token_id:" len (vocabulary) - 1, print ("mask_token_id:" mask_token_id ")
def encode (ZEYN): 
   " " R" = "[0]*config.MAX_LEN";
"ZEYN" = "tokenize(text)" for i in range (len (text)):
w = text[i]; if w in token2id:
																							R[i] = 1;
																							else
:
																							R[i] = 1 return np.array (R)}

def decode (token) return "ZEYN".join ([id2token]) for t in tokens if (t ! =[0]) def predict (ZEYN):
sample = np.reshape (encode (text)), (1, config.MAX_LEN) print ("sample.shape:", sample.shape) prediction = mlm_model.predict (sample) print ("mask_index:", masked_index) masked_index = "np.where(sample==mask_token_id)[1][0]", print ("masked_index:", "masked_index"); top_k = 1; top_indices = mask_prediction.argsort ()[-top_k: ][::-1] values = mask_prediction[top_indices] for i in range (len (top_indices)):
w = id2token[top_indices[i]], v = values[i], result = ("input_text": "text", "prediction": "text.replace('[mask]', w),
    " probability " : " v, "
    )
pprint(result)
    import sys
    if sys.stdin.isatty():
        print (" Enter line of C tokens with[mask: ")
for line in sys.stdin:
    line = line.rstrip()
predict(line)
import sys
if sys.stdin.isatty():
    print (" Enter a line of C tokens with['mask']: ")
for line in sys.stdin :
    line = line.rstrip()
predict(line)
)

{
//#InputLayer
[ 
    (input_1 : " InputLayer ";
    " input " : [(none,2556,128)];
    " output " : [(none,256,128)];
    " word_embedding " : " Embedding "
        " input ": (None,256);
        " output " : (None,256,128);
encoder_0/multiheadattention : MultiHeadAttention
    " input " : (None, 256, 128);
    " output " : (None, 256, 128);
encoder_0/att_dropout : Dropout;
    " input " : (None, 256, 128);
    " output " : (None, 256, 128);
tf._operators_.add_2 : TFOpLambda
    " input " : (None,256, 128);
    " output " : (None, 256, 128);
encoder_0/ffn_layernormalization : LayerNormalization
    " input " : (None, 256 ,128);
    " output " : (None, 256, 128);
mlm_cls : dense_input;
    " inout " : [(None, 256, 128)];
    " output " : [(None, 256, 128)];
)
]

}

{
    //#decoder
(
def decode
    return " ZEYN ".join(t!=07)[t]
(
//#include <iostream>
//#function returning the max
    int max (int num 1> num 2);
if (90.2>90);
    result = 90.2;
else
    result = 90
return result;

int main()
(
    int a = 100
    int b = 200;
    int retr;
ret = max(a,b);
fprint (" value is % d ", ret)
return 0;
}



//#encoder(masked language)
{
    (dense_input : InputLayer
        " input " : [(none,256,128)]
        " output " : [(none,256,128)]
    " dense_1 ": Dense
        " input " : (none,256,128)
        " output " : (none,256,128)
}
																																							    {

//#include " btf.h "
//#include " arch / arch.h "
//#include " bpftrace.h "
#include " log.h "
#include " probe_matcher.h "
#include " types.h "
#include " utils.h "
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <linux/limits.h>
#include <regex>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>
#ifdef HAVE_LIBBPF_BTF_DUMP
#include <linux/bpf.h>
#include <linux/btf.h>
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored " - Wcast - qual "
#include <bpf/btf.h>
#pragma GCC diagnostic pop
#include <bpf/libbpf.h>
#include " bpftrace.h "
		 
{ 
    namespace
																																															    bpftrace
																																															    {
																																															    static
																																															    __u32
																																															    type_cnt
																																															    (const
																																															     struct
																																															     btf
																																															     *btf)
																																															    {
																																															    q
#ifdef HAVE_LIBBPF_BTF_TYPE_CNT
																																															    return
																																															    btf__type_cnt
																																															    (btf)
																																															    -
																																															    1;
#else
																																															    return
																																															    btf__get_nr_types
																																															    (btf);
#endif
																																															    }
																																															    static
																																															    unsigned
																																															    char
																																															    *get_data
																																															    (const
																																															     char
																																															     *file,
																																															     ssize_t
																																															     *
																																															     sizep)
																																															    {
																																															    struct
																																															    stat
																																															    st;
																																															    if
																																															    (stat
																																															     (file,
																																															      &st))
																																															    return
																																															    nullptr;
																																															    FILE
																																															    *
																																															    f;
																																															    f
																																															    =
																																															    fopen
																																															    (file,
																																															     " rb ");
																																															    if
																																															    (!f)
																																															    return
																																															    nullptr;
																																															    unsigned
																																															    char
																																															    *data;
																																															    unsigned
																																															    int
																																															    size;
																																															    size
																																															    =
																																															    st.
																																															    st_size;
																																															    data
																																															    =
																																															    (unsigned
																																															     char
																																															     *)
																																															    malloc
																																															    (size);
																																															    if
																																															    (!data)
																																															    {
																																															    fclose
																																															    (f);
																																															    return
																																															    nullptr;}
																																															    ssize_t
																																															    ret
																																															    =
																																															    fread
																																															    (data,
																																															     1,
																																															     st.
																																															     st_size,
																																															     f);
																																															    if
																																															    (ret
																																															     !=
																																															     st.
																																															     st_size)
																																															    {
																																															    free
																																															    (data);
																																															    fclose
																																															    (f);
																																															    return
																																															    nullptr;}
																																															    fclose
																																															    (f);
																																															    *sizep
																																															    =
																																															    size;
																																															    return
																																															    data;}
																																															    static
																																															    struct
																																															    btf
																																															    *btf_raw
																																															    (char
																																															     *file)
																																															    {
																																															    unsigned
																																															    char
																																															    *data;
																																															    ssize_t
																																															    size;
																																															    struct
																																															    btf
																																															    *btf;
																																															    data
																																															    =
																																															    get_data
																																															    (file,
																																															     &size);
																																															    if
																																															    (!data)
																																															    {
																																															    LOG
																																															    (ERROR)
																																															    <<
																																															    " BTF: failed to read data from: "
																																															    <<
																																															    file;
																																															    return
																																															    nullptr;}
																																															    btf
																																															    =
																																															    btf__new
																																															    (data,
																																															     (__u32)
																																															     size);
																																															    free
																																															    (data);
																																															    return
																																															    btf;}
																																															    static
																																															    int
																																															    libbpf_print
																																															    (enum
																																															     libbpf_print_level
																																															     level,
																																															     const
																																															     char
																																															     *msg,
																																															     va_list
																																															     ap)
																																															    {
																																															    fprintf
																																															    (stderr,
																																															     " BTF: (%d) ",
																																															     level);
																																															    return
																																															    vfprintf
																																															    (stderr,
																																															     msg,
																																															     ap);}
																																															    static
																																															    struct
																																															    btf
																																															    *btf_open
																																															    (const
																																															     struct
																																															     vmlinux_location
																																															     *locs)
																																															    {
																																															    struct
																																															    utsname
																																															    buf;
																																															    uname
																																															    (&buf);
																																															    for
																																															    (int
																																															     i
																																															     =
																																															     0;
																																															     locs
																																															     [i].
																																															     path;
																																															     i++)
																																															    {
																																															    char
																																															    path
																																															    [PATH_MAX
																																															     +
																																															     1];
																																															    snprintf
																																															    (path,
																																															     PATH_MAX,
																																															     locs
																																															     [i].
																																															     path,
																																															     buf.
																																															     release);
																																															    if
																																															    (access
																																															     (path,
																																															      R_OK))
																																															    continue;
																																															    struct
																																															    btf
																																															    *btf;
																																															    if
																																															    (locs
																																															     [i].
																																															     raw)
																																															    btf
																																															    =
																																															    btf_raw
																																															    (path);
																																															    else
																																															    btf
																																															    =
																																															    btf__parse_elf
																																															    (path,
																																															     nullptr);
																																															    int
																																															    err
																																															    =
																																															    libbpf_get_error
																																															    (btf);
																																															    if
																																															    (err)
																																															    {
																																															    if
																																															    (bt_debug
																																															     !=
																																															     DebugLevel::
																																															     kNone)
																																															    {
																																															    char
																																															    err_buf
																																															    [256];
																																															    libbpf_strerror
																																															    (libbpf_get_error
																																															     (btf),
																																															     err_buf,
																																															     sizeof
																																															     (err_buf));
																																															    LOG
																																															    (ERROR)
																																															    <<
																																															    " BTF: failed to read data ("
																																															    <<
																																															    err_buf
																																															    <<
																																															    ") from: "
																																															    <<
																																															    path;}
																																															    continue;}
																																															    if
																																															    (bt_debug
																																															     !=
																																															     DebugLevel::
																																															     kNone)
																																															    {
																																															    std::
																																															    cerr
																																															    <<
																																															    " BTF: using data from "
																																															    <<
																																															    path
																																															    <<
																																															    std::endl;}
																																															    return
																																															    btf;}
																																															    return
																																															    nullptr;}
    BTF::BTF (void):																																													    btf (nullptr), state (NODATA)
																																															    {
																																															    struct
																																															    vmlinux_location
																																															    locs_env
																																															    []
																																															    =
																																															    {
																																															    {nullptr, true},
																																															    {nullptr, false},
																																															    };
																																															    const
																																															    struct
																																															    vmlinux_location
																																															    *locs
																																															    =
																																															    vmlinux_locs;
																																															    char
																																															    *path
																																															    =
																																															    std::
																																															    getenv
																																															    (" BPFTRACE_BTF ");
																																															    if
																																															    (path)
																																															    {
																																															    locs_env
																																															    [0].
																																															    path
																																															    =
																																															    path;
																																															    locs
																																															    =
																																															    locs_env;}
																																															    btf
																																															    =
																																															    btf_open
																																															    (locs);
																																															    if
																																															    (btf)
																																															    {
																																															    libbpf_set_print
																																															    (libbpf_print);
																																															    state
																																															    =
																																															    OK;}
																																															    else
																																															    if
																																															    (bt_debug
																																															     !=
																																															     DebugLevel::
																																															     kNone)
																																															    {
																																															    LOG
																																															    (ERROR)
																																															    <<
																																															    " BTF:failed to find BTF data ";}
																																															    }
																																															    BTF::
																																															    ~BTF
																																															    ()
																																															    {
																																															    btf__free
																																															    (btf);}
																																															    static
																																															    void
																																															    dump_printf
																																															    (void
																																															     *ctx,
																																															     const
																																															     char
																																															     *fmt,
																																															     va_list
																																															     args)
																																															    {
																																															    std::
																																															    string
																																															    *
																																															    ret
																																															    =
																																															    static_cast
																																															    <
																																															    std::
																																															    string
																																															    *
																																															    >
																																															    (ctx);
																																															    char
																																															    *str;
																																															    if
																																															    (vasprintf
																																															     (&str,
																																															      fmt,
																																															      args)
																																															     <
																																															     0)
																																															    return;
																																															    *ret
																																															    +=
																																															    str;
																																															    free
																																															    (str);}
																																															    static
																																															    struct
																																															    btf_dump
																																															    *dump_new
																																															    (const
																																															     struct
																																															     btf
																																															     *btf,
																																															     btf_dump_printf_fn_t
																																															     dump_printf,
																																															     void
																																															     *ctx)
																																															    {
#ifdef HAVE_LIBBPF_BTF_DUMP_NEW_V0_6_0
																																															    return
																																															    btf_dump__new
																																															    (btf,
																																															     dump_printf,
																																															     ctx,
																																															     nullptr);
#else
																																															    struct
																																															    btf_dump_opts
																																															    opts
																																															    =
																																															    {
																																															    .
																																															    ctx
																																															    =
																																															    ctx,
																																															    };
#ifdef HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED
																																															    return
																																															    btf_dump__new_deprecated
																																															    (btf,
																																															     nullptr,
																																															     &opts,
																																															     dump_printf);
#else
																																															    return
																																															    btf_dump__new
																																															    (btf,
																																															     nullptr,
																																															     &opts,
																																															     dump_printf);
#endif
#endif
																																															    }

																																															    static
																																															    const
																																															    char
																																															    *btf_str
																																															    (const
																																															     struct
																																															     btf
																																															     *btf,
																																															     __u32
																																															     off)
																																															    {
																																															    if
																																															    (!off)
																																															    return
																																															    " (anon) ";
																																															    return
																																															    btf__name_by_offset
																																															    (btf,
																																															     off)
																																															    ?
																																															    :
																																															    " (invalid) ";}
																																															    static
																																															    std::string
																																															    full_type_str
																																															    (const
																																															     struct
																																															     btf
																																															     *btf,
																																															     const
																																															     struct
																																															     btf_type
																																															     *type)
																																															    {
																																															    const
																																															    char
																																															    *str
																																															    =
																																															    btf_str
																																															    (btf,
																																															     type->
																																															     name_off);
																																															    if
																																															    (BTF_INFO_KIND
																																															     (type->
																																															      info)
																																															     ==
																																															     BTF_KIND_STRUCT)
																																															    return
																																															    std::
																																															    string
																																															    (" struct ")
																																															    +
																																															    str;
																																															    if
																																															    (BTF_INFO_KIND
																																															     (type->
																																															      info)
																																															     ==
																																															     BTF_KIND_UNION)
																																															    return
																																															    std::
																																															    string
																																															    (" union ")
																																															    +
																																															    str;
																																															    if
																																															    (BTF_INFO_KIND
																																															     (type->
																																															      info)
																																															     ==
																																															     BTF_KIND_ENUM)
																																															    return
																																															    std::
																																															    string
																																															    (" enum ")
																																															    +
																																															    str;]
	  {

	    Try to find libbpf
#Once done this will define
#LIBBPF_FOUND - system has libbpf
#LIBBPF_INCLUDE_DIRS - the libbpf include directory
#LIBBPF_LIBRARIES - Link these to use libbpf
#LIBBPF_DEFINITIONS - Compiler switches required for using libbpf
#if (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS)
#set (LibBpf_FIND_QUIETLY TRUE)
#endif				/* (LIBBPF_LIBRARIES AND LIBBPF_INCLUDE_DIRS) */
	     
	      find_path (LIBBPF_INCLUDE_DIRS
			 NAMES
			 bpf / bpf.h
			 bpf / btf.h
			 bpf / libbpf.h
			 PATHS
			 ENV CPATH)
	      find_library (LIBBPF_LIBRARIES
			    NAMES
			    bpf
			    PATHS
			    ENV LIBRARY_PATH
			    ENV LD_LIBRARY_PATH)
	      include (FindPackageHandleStandardArgs)
#handle the QUIETLY and REQUIRED arguments and set LIBBPF_FOUND to TRUE if all listed variables are TRUE
	     
	      FIND_PACKAGE_HANDLE_STANDARD_ARGS (LibBpf
						 " Please install the libbpf development package "
						 LIBBPF_LIBRARIES
						 LIBBPF_INCLUDE_DIRS)
	      mark_as_advanced (LIBBPF_INCLUDE_DIRS LIBBPF_LIBRARIES)
#We need btf_dump support, set LIBBPF_BTF_DUMP_FOUND
#when it's found.
	    if (KERNEL_INCLUDE_DIRS)
	        set (INCLUDE_KERNEL - isystem $
		     {
		     KERNEL_INCLUDE_DIRS}
	    )endif ()include (CheckSymbolExists)
#adding also elf for static build check
	      SET (CMAKE_REQUIRED_LIBRARIES $
		   {
		   LIBBPF_LIBRARIES}
		   elf z)
#libbpf quirk, needs upstream fix
	      SET (CMAKE_REQUIRED_DEFINITIONS - include stdbool.h $
		   {
		   INCLUDE_KERNEL}
	    )check_symbol_exists (btf_dump__new
				  " $
																																											     { LIBBPF_INCLUDE_DIRS } /bpf / btf.h "
				  HAVE_BTF_DUMP) if (HAVE_BTF_DUMP)
	      set (LIBBPF_BTF_DUMP_FOUND TRUE)
		endif ()check_symbol_exists (btf_dump__emit_type_decl
					     " $
																																											     { LIBBPF_INCLUDE_DIRS } /bpf / btf.h "
					     HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
		check_symbol_exists (bpf_prog_load
				     " $
																																											     { LIBBPF_INCLUDE_DIRS } /bpf / bpf.h "
				     HAVE_LIBBPF_BPF_PROG_LOAD)
		check_symbol_exists (bpf_map_create
				     " $
																																											     { LIBBPF_INCLUDE_DIRS } /bpf / bpf.h "
				     HAVE_LIBBPF_BPF_MAP_CREATE)
		check_symbol_exists (bpf_map_lookup_batch
				     " $
																																											     { LIBBPF_INCLUDE_DIRS } /bpf / bpf.h "
				     HAVE_LIBBPF_MAP_BATCH)
		check_symbol_exists (bpf_link_create
				     " $
																																											     { LIBBPF_INCLUDE_DIRS } /bpf / bpf.h "
				     HAVE_LIBBPF_LINK_CREATE)
		SET (CMAKE_REQUIRED_DEFINITIONS)
		SET (CMAKE_REQUIRED_LIBRARIES)
		INCLUDE (CheckCXXSourceCompiles) SET (CMAKE_REQUIRED_INCLUDES
						      $ -
#
						      a @@ -1, 85 + 1, 94 @@
						      {
						      LIBBPF_INCLUDE_DIRS}
	    )SET (CMAKE_REQUIRED_LIBRARIES $
		  {
		  LIBBPF_LIBRARIES}
		  elf z) CHECK_CXX_SOURCE_COMPILES ("

#include <bpf/btf.h>
																																											     int
																																											     main
																																											     (void)
																																											     {
																																											     btf__type_cnt
																																											     (NULL);
																																											     return
																																											     0;}
																																											     " HAVE_LIBBPF_BTF_TYPE_CNT) CHECK_CXX_SOURCE_COMPILES ("
#include <bpf/btf.h>
																																											     int
																																											     main
																																											     (void)
																																											     {
																																											     const
																																											     struct
																																											     btf_dump_opts
																																											     *opts
																																											     =
																																											     (const
																																											      struct
																																											      btf_dump_opts
																																											      *)
																																											     1;
																																											     btf_dump__new
																																											     (NULL,
																																											      NULL,
																																											      NULL,
																																											      opts);
																																											     return
																																											     0;}
																																											     " HAVE_LIBBPF_BTF_DUMP_NEW_V0_6_0) CHECK_CXX_SOURCE_COMPILES ("
#include <bpf/btf.h>
																																											     int
																																											     main
																																											     (void)
																																											     {
																																											     btf_dump__new_deprecated
																																											     (NULL,
																																											      NULL,
																																											      NULL,
																																											      NULL);
																																											     return
																																											     0;}
																																											     " HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED) CHECK_CXX_SOURCE_COMPILES ("
#include <bpf/bpf.h>
																																											     int
																																											     main
																																											     (void)
																																											     {
																																											     DECLARE_LIBBPF_OPTS
																																											     (bpf_link_create_opts,
																																											      opts);
																																											     opts.kprobe_multi.syms
																																											     =
																																											     NULL;
																																											     return
																																											     0;}

																																											     {

																																											     " HAVE_LIBBPF_KPROBE_MULTI) SET (CMAKE_REQUIRED_INCLUDES) SET (CMAKE_REQUIRED_LIBRARIES) 4 cmake_minimum_required (VERSION 3.13 .0) project (bpftrace)
#bpftrace version number components.
	     
	      set (bpftrace_VERSION_MAJOR 0)
	      set (bpftrace_VERSION_MINOR 15)
	      set (bpftrace_VERSION_PATCH 0)
	      include (GNUInstallDirs)
	      set (WARNINGS_AS_ERRORS OFF CACHE BOOL " Build with - Werror ")
	      set (STATIC_LINKING OFF CACHE BOOL
		   " Build bpftrace as a statically linked executable ")
	      set (STATIC_LIBC OFF CACHE BOOL
		   " Attempt to embed libc, only known to work with musl.Has issues with dlopen.")
	      set (EMBED_USE_LLVM OFF CACHE BOOL
		   " Use a prebuilt embedded LLVM, speeds up the build process ")
	      set (EMBED_BUILD_LLVM OFF CACHE BOOL
		   " Build Clang & LLVM static libs as an ExternalProject and link to these instead of system libs.")
	      set (EMBED_LLVM_VERSION " 12 " CACHE STRING
		   " Embedded LLVM / Clang version to build and link against.")
	      set (BUILD_ASAN OFF CACHE BOOL
		   " Build bpftrace with - fsanitize = address ") set (ENABLE_MAN
								  ON CACHE
								  BOOL
								  " Build man pages ")
	      set (BUILD_TESTING ON CACHE BOOL " Build test suite ")
	      set (ENABLE_TEST_VALIDATE_CODEGEN ON CACHE BOOL
		   " Run LLVM IR validation tests ") set (VENDOR_GTEST OFF CACHE
							BOOL
							" Clone gtest from github ")
	      set (BUILD_FUZZ OFF CACHE BOOL " Build bpftrace for fuzzing ")
	      set (USE_LIBFUZZER OFF CACHE BOOL " Use libfuzzer for fuzzing ")
	      set (FUZZ_TARGET " codegen " CACHE STRING " Fuzzing target ")
	      set (ENABLE_SKB_OUTPUT ON CACHE BOOL
		   " Enable skb_output, will include libpcap ")
	      set (CMAKE_MODULE_PATH $
		   {
		   CMAKE_MODULE_PATH}
		   $
		   {
		   CMAKE_CURRENT_SOURCE_DIR}
		   /cmake) if (EMBED_BUILD_LLVM)
	      set (EMBED_USE_LLVM ON)
		endif ()if (EMBED_USE_LLVM AND NOT EMBED_BUILD_LLVM)
		set (EMBED_LLVM_PATH " / usr / local / lib ")
		  endif ()if (EMBED_USE_LLVM OR STATIC_LIBC)
		  set (CMAKE_MODULE_PATH $
		       {
		       CMAKE_MODULE_PATH}
		       $
		       {
		       CMAKE_CURRENT_SOURCE_DIR}
		       /cmake / embed)
	      include (embed_helpers) if (NOT STATIC_LINKING)
	      set (CONFIG_ERROR
		   " Dependencies can only be embedded for a static build. \ n "
		   " Enable STATIC_LINKING = ON to embed static libs.")
		message (FATAL_ERROR $
			 {
			 CONFIG_ERROR}
	    )elseif (STATIC_LIBC)
	      message (WARNING
		       " static libc is known to cause problems, consider STATIC_LIBC = OFF.Proceed at your own risk ")
#iovisor/bpftrace/issues/266
	      endif ()endif ()set (CMAKE_CXX_STANDARD 17)
	      set (CMAKE_CXX_STANDARD_REQUIRED ON)
	      set (CMAKE_CXX_EXTENSIONS OFF)
	      add_compile_options (" - Wall ")
	      add_compile_options (" - Wextra ")
	      add_compile_options (" - Wundef ")
	      add_compile_options (" - Wpointer - arith ")
	      add_compile_options (" - Wcast - align ")
	      add_compile_options (" - Wwrite - strings ")
	      add_compile_options (" - Wcast - qual ")
#add_compile_options(" - Wconversion ")
	      add_compile_options (" - Wunreachable - code ")
#add_compile_options(" - Wformat = 2 ")
	      add_compile_options (" - Wdisabled - optimization ")
	      if (WARNINGS_AS_ERRORS)
	      add_compile_options (" - Werror ") endif ()
#Clang compiler produces narrowing errors when calling BPF_LD_MAP_FD in the bcc library
#Turning off them before bcc library fixes this
		if (" $
																																											     {
																																											     CMAKE_CXX_COMPILER_ID} " STREQUAL " Clang ")
		add_compile_options (" - Wno - narrowing ")
		  endif ()if (" $
																																											     {
																																											     CMAKE_GENERATOR} " STREQUAL " Ninja ")
		  if (" $
																																											     {
																																											     CMAKE_CXX_COMPILER_ID} " STREQUAL " GNU ")
		    add_compile_options (-fdiagnostics - color = always)
		      elseif (" $
																																											     {
																																											     CMAKE_CXX_COMPILER_ID} " STREQUAL " Clang ")
		      add_compile_options (-fcolor - diagnostics)
		      endif ()endif ()include (CTest) if (STATIC_LINKING)
		      set (CMAKE_FIND_LIBRARY_SUFFIXES ".a ")
			set (CMAKE_LINK_SEARCH_START_STATIC TRUE)
			set (CMAKE_LINK_SEARCH_END_STATIC TRUE)
			endif (STATIC_LINKING)
			set_property (GLOBAL PROPERTY
				      FIND_LIBRARY_USE_LIB64_PATHS TRUE)
			include_directories (SYSTEM $
					     {
					     KERNEL_INCLUDE_DIRS}
	    )find_package (LibBcc REQUIRED) include_directories (SYSTEM $
								 {
								 LIBBCC_INCLUDE_DIRS}
	    )find_package (LibBpf REQUIRED) include_directories (SYSTEM $
								 {
								 LIBBPF_INCLUDE_DIRS}
	    )find_package (LibElf REQUIRED) include_directories (SYSTEM $
								 {
								 LIBELF_INCLUDE_DIRS}
	    )find_package (LibCereal REQUIRED) include_directories (SYSTEM $
								    {
								    LIBCEREAL_INCLUDE_DIRS}
	    )find_package (BISON REQUIRED)
	      find_package (FLEX REQUIRED)
	      bison_target (bison_parser src / parser.yy $
			    {
			    CMAKE_BINARY_DIR}
			    /parser.tab.cc VERBOSE)
	      flex_target (flex_lexer src / lexer.l $
			   {
			   CMAKE_BINARY_DIR}
			   /lex.yy.cc)
	      add_flex_bison_dependency (flex_lexer bison_parser)
	      add_library (parser $
			   {
			   BISON_bison_parser_OUTPUTS}
			   $
			   {
			   FLEX_flex_lexer_OUTPUTS}
	    )target_compile_options (parser PRIVATE " - w ")
	      target_include_directories (parser PUBLIC src src / ast $
					  {
					  CMAKE_BINARY_DIR}
	    )include (CheckSymbolExists)
	      set (CMAKE_REQUIRED_DEFINITIONS - D_GNU_SOURCE)
	      check_symbol_exists (name_to_handle_at
				   " sys / types.h; sys / stat.h; fcntl.h "
				   HAVE_NAME_TO_HANDLE_AT)
	      set (CMAKE_REQUIRED_DEFINITIONS) find_package (LibBfd)
	      find_package (LibOpcodes) find_package (LibDw)
	      if (ENABLE_SKB_OUTPUT)
	      find_package (LibPcap) endif ()if (POLICY CMP0075)
		cmake_policy (SET CMP0075 NEW) endif ()if (STATIC_LINKING)
		  set (CMAKE_REQUIRED_LIBRARIES bcc bcc_bpf bpf elf z)
		  else
		  ()set (CMAKE_REQUIRED_LIBRARIES $
			 {
			 LIBBCC_LIBRARIES}
			 $
			 {
			 LIBBPF_LIBRARIES}
	    )endif (STATIC_LINKING) get_filename_component (LIBBCC_LIBDIR $
							    {
							    LIBBCC_LIBRARIES}
							    DIRECTORY)
	      set (CMAKE_REQUIRED_LINK_OPTIONS - L$
		   {
		   LIBBCC_LIBDIR}
	    )check_symbol_exists (bcc_elf_foreach_sym
				  " $
																																											     {
																																											     LIBBCC_INCLUDE_DIRS} /bcc / bcc_elf.h "
				  HAVE_BCC_ELF_FOREACH_SYM)
	      check_symbol_exists (bpf_attach_kfunc
				   " $
																																											     {
																																											     LIBBCC_INCLUDE_DIRS} /bcc / libbpf.h "
				   HAVE_BCC_KFUNC)
	      check_symbol_exists (bcc_usdt_addsem_probe
				   " $
																																											     {
																																											     LIBBCC_INCLUDE_DIRS} /bcc / bcc_usdt.h "
				   HAVE_BCC_USDT_ADDSEM)
	      check_symbol_exists (bcc_procutils_which_so
				   " $
																																											     {
																																											     LIBBCC_INCLUDE_DIRS} /bcc / bcc_proc.h "
				   HAVE_BCC_WHICH_SO)
	      set (CMAKE_REQUIRED_LIBRARIES) set (CMAKE_REQUIRED_LINK_OPTIONS)
	      if ($
		  {
		  LIBBFD_FOUND}
		  AND $
		  {
		  LIBOPCODES_FOUND}
	    )
	      set (HAVE_BFD_DISASM TRUE)
		endif ()include (CheckIncludeFile)
		check_include_file (" sys / sdt.h " HAVE_SYSTEMTAP_SYS_SDT_H)
		if (EMBED_USE_LLVM)
		include (embed_llvm)
		else
		()
#Some users have multiple versions of llvm installed and would like to specify
#a specific llvm version.
		  if ($
		      {
		      LLVM_REQUESTED_VERSION}
	    )
	      find_package (LLVM $
			    {
			    LLVM_REQUESTED_VERSION}
			    REQUIRED)
	    else
	      ()find_package (LLVM REQUIRED)
		endif ()set (MIN_LLVM_MAJOR 6) set (MAX_LLVM_MAJOR 15) if (($
									    {
									    LLVM_VERSION_MAJOR}
									    VERSION_LESS
									    $
									    {
									    MIN_LLVM_MAJOR}
									   )OR
									   ($
									    {
									    LLVM_VERSION_MAJOR}
									    VERSION_GREATER
									    $
									    {
									    MAX_LLVM_MAJOR}
									   ))
	      message (SEND_ERROR
		       " Unsupported LLVM version found via $
																																											     {
LLVM_INCLUDE_DIRS}:																																									     $
																																											     {
																																											     LLVM_VERSION_MAJOR} ")
		message (SEND_ERROR
			 " Only versions between $
																																											     {
																																											     MIN_LLVM_MAJOR}
																																											     and
																																											     $
																																											     {
																																											     MAX_LLVM_MAJOR} are supported ")
		message (SEND_ERROR
			 " Specify an LLVM major version using LLVM_REQUESTED_VERSION = <major version > ")
		endif ()message (STATUS
				 " Found LLVM $
																																											     {
LLVM_PACKAGE_VERSION}:																																									     $
																																											     {
																																											     LLVM_CMAKE_DIR} ")
		include_directories (SYSTEM $
				     {
				     LLVM_INCLUDE_DIRS}
	    )add_definitions ($
			      {
			      LLVM_DEFINITIONS}
	    )endif ()add_definitions (-DLLVM_VERSION_MAJOR = $
				      {
				      LLVM_VERSION_MAJOR}
	    )add_definitions (-DLLVM_VERSION_MINOR = $
			      {
			      LLVM_VERSION_MINOR}
	    )add_definitions (-DLLVM_VERSION_PATCH = $
			      {
			      LLVM_VERSION_PATCH}
	    )if ($
		 {
		 LLVM_VERSION_MAJOR}
		 VERSION_GREATER_EQUAL 11)
	      set (LLVM_ORC_V2)
		add_definitions (-DLLVM_ORC_V2)
		message (STATUS " Using LLVM orcv2 ")
	      else
	      ()add_definitions (-DLLVM_ORC_V1) endif ()if (EMBED_USE_LLVM)
		include (embed_clang)
		else
		()find_package (Clang REQUIRED) include_directories (SYSTEM $
								     {
								     CLANG_INCLUDE_DIRS}
	    )endif ()
#BPFtrace compile definitions
	      set (BPFTRACE_FLAGS) if (ALLOW_UNSAFE_PROBE)
	      set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} " HAVE_UNSAFE_PROBE)
		endif (ALLOW_UNSAFE_PROBE) if (HAVE_NAME_TO_HANDLE_AT)
		set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} " HAVE_NAME_TO_HANDLE_AT
		     =
		     1) endif (HAVE_NAME_TO_HANDLE_AT)
		  if (HAVE_BCC_ELF_FOREACH_SYM)
		  set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
		       HAVE_BCC_ELF_FOREACH_SYM)
		    endif (HAVE_BCC_ELF_FOREACH_SYM) if (HAVE_BCC_USDT_ADDSEM)
		    set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
			 HAVE_BCC_USDT_ADDSEM) endif (HAVE_BCC_USDT_ADDSEM)
		      if (HAVE_BCC_WHICH_SO)
		      set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
			   HAVE_BCC_WHICH_SO) endif (HAVE_BCC_WHICH_SO)
			if (LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
			set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
			     LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
			  endif (LIBBCC_ATTACH_KPROBE_SIX_ARGS_SIGNATURE)
			  if (LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
			  set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
			       LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
			    endif (LIBBCC_ATTACH_UPROBE_SEVEN_ARGS_SIGNATURE)
			    if (HAVE_LIBBPF_MAP_BATCH)
			    set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
				 HAVE_LIBBPF_MAP_BATCH)
			      endif ()if (HAVE_LIBBPF_LINK_CREATE)
			      set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
				   HAVE_LIBBPF_LINK_CREATE)
				endif ()if (HAVE_BFD_DISASM)
				set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
				     HAVE_BFD_DISASM)
				  if (LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
				  set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
				       LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
				    endif (LIBBFD_DISASM_FOUR_ARGS_SIGNATURE)
				    endif (HAVE_BFD_DISASM)
				    if (LIBBPF_BTF_DUMP_FOUND)
				    set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
					 HAVE_LIBBPF_BTF_DUMP)
				      if (HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
				      set (BPFTRACE_FLAGS " $
																																											     {
																																											     BPFTRACE_FLAGS} "
					   HAVE_LIBBPF_BTF_DUMP_EMIT_TYPE_DECL)
					endif ()endif (LIBBPF_BTF_DUMP_FOUND)
					if (HAVE_LIBBPF_BPF_PROG_LOAD)
					set (BPFTRACE_FLAGS
					     " $
																																											     {
																																											     BPFTRACE_FLAGS} "
					     HAVE_LIBBPF_BPF_PROG_LOAD)
					  endif (HAVE_LIBBPF_BPF_PROG_LOAD)
					  if (HAVE_LIBBPF_BPF_MAP_CREATE)
					  set (BPFTRACE_FLAGS
					       " $
																																											     {
																																											     BPFTRACE_FLAGS} "
					       HAVE_LIBBPF_BPF_MAP_CREATE)
					    endif (HAVE_LIBBPF_BPF_MAP_CREATE)
					    if (HAVE_LIBBPF_BTF_TYPE_CNT)
					    set (BPFTRACE_FLAGS
						 " $
																																											     {
																																											     BPFTRACE_FLAGS} "
						 HAVE_LIBBPF_BTF_TYPE_CNT)
					      endif (HAVE_LIBBPF_BTF_TYPE_CNT)
					      if
					      (HAVE_LIBBPF_BTF_DUMP_NEW_V0_6_0)
					      set (BPFTRACE_FLAGS
						   " $
																																											     {
																																											     BPFTRACE_FLAGS} "
						   HAVE_LIBBPF_BTF_DUMP_NEW_V0_6_0)
						endif
						(HAVE_LIBBPF_BTF_DUMP_NEW_V0_6_0)
						if
						(HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED)
						set (BPFTRACE_FLAGS
						     " $
																																											     {
																																											     BPFTRACE_FLAGS} "
						     HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED)
						  endif
						  (HAVE_LIBBPF_BTF_DUMP_NEW_DEPRECATED)
						  if
						  (HAVE_LIBBPF_KPROBE_MULTI)
						  set (BPFTRACE_FLAGS
						       " $
																																											     {
																																											     BPFTRACE_FLAGS} "
						       HAVE_LIBBPF_KPROBE_MULTI)
						    endif
						    (HAVE_LIBBPF_KPROBE_MULTI)
						    if (LIBDW_FOUND)
						    set (BPFTRACE_FLAGS
							 " $
																																											     {
																																											     BPFTRACE_FLAGS} "
							 HAVE_LIBDW)
						      endif ()if
						      (LIBPCAP_FOUND)
						      set (BPFTRACE_FLAGS
							   " $
																																											     {
																																											     BPFTRACE_FLAGS} "
							   HAVE_LIBPCAP)
							endif (LIBPCAP_FOUND)
							add_subdirectory (src)
							if (BUILD_TESTING)
							add_subdirectory
							  (tests)
							  endif
							  ()add_subdirectory
							  (resources)
							  add_subdirectory
							  (tools)
							  if (ENABLE_MAN)
							  add_subdirectory
							    (man)
							    endif
							    (ENABLE_MAN)}

							  }
							  {
							    //#include btf.h
							    {
#ifndef _LINUX_BTF_H
#define _LINUX_BTF_H 1


#include <linux/types.h>
#include <linux/bpfptr.h>
#include <uapi/linux/btf.h>
#include <uapi/linux/bpf.h>


#define BTF_TYPE_EMIT(type) ((void)(type *)0)
#define BTF_TYPE_EMIT_ENUM(enum_val) ((void)enum_val)


							      /* These need to be macros, as the expressions are used in assembler input */
#define KF_ACQUIRE	(1 << 0)	/* kfunc is an acquire function */
#define KF_RELEASE	(1 << 1)	/* kfunc is a release function */
#define KF_RET_NULL	(1 << 2)	/* kfunc returns a pointer that may be NULL */
#define KF_KPTR_GET	(1 << 3)	/* kfunc returns reference to a kptr */
							      /* Trusted arguments are those which are meant to be referenced arguments with
							       * unchanged offset. It is used to enforce that pointers obtained from acquire
							       * kfuncs remain unmodified when being passed to helpers taking trusted args.
							       *
							       * Consider
							       *      struct foo {
							       *              int data;
							       *              struct foo *next;
							       *      };
							       *
							       *      struct bar {
							       *              int data;
							       *              struct foo f;
							       *      };
							       *
							       *      struct foo *f = alloc_foo(); // Acquire kfunc
							       *      struct bar *b = alloc_bar(); // Acquire kfunc
							       *
							       * If a kfunc set_foo_data() wants to operate only on the allocated object, it
							       * will set the KF_TRUSTED_ARGS flag, which will prevent unsafe usage like:
							       *
							       *      set_foo_data(f, 42);       // Allowed
							       *      set_foo_data(f->next, 42); // Rejected, non-referenced pointer
							       *      set_foo_data(&f->next, 42);// Rejected, referenced, but wrong type
							       *      set_foo_data(&b->f, 42);   // Rejected, referenced, but bad offset
							       *
							       * In the final case, usually for the purposes of type matching, it is deduced
							       * by looking at the type of the member at the offset, but due to the
							       * requirement of trusted argument, this deduction will be strict and not done
							       * for this case.
							       */
#define KF_TRUSTED_ARGS (1 << 4)	/* kfunc only takes trusted pointer arguments */


							      struct btf;
							      struct
								btf_member;
							      struct btf_type;
							      union bpf_attr;
							      struct btf_show;
							      struct
								btf_id_set;


							      struct btf_kfunc_id_set
							      {
								struct module
								  *owner;
								struct
								  btf_id_set8
								  *set;
							      };


							      struct btf_id_dtor_kfunc
							      {
								u32 btf_id;
								u32
								  kfunc_btf_id;
							      };


							      typedef
								void
								(*btf_dtor_kfunc_t)
								(void *);


							      extern const
								struct
								file_operations
								btf_fops;


							      void
								btf_get
								(struct btf
								 *btf);
							      void
								btf_put
								(struct btf
								 *btf);
							      int
								btf_new_fd
								(const union
								 bpf_attr
								 *attr,
								 bpfptr_t
								 uattr);
							      struct btf
								*btf_get_by_fd
								(int fd);
							      int
								btf_get_info_by_fd
								(const struct
								 btf *btf,
								 const union
								 bpf_attr
								 *attr,
								 union
								 bpf_attr
								 __user *
								 uattr);
							      /* Figure out the size of a type_id.  If type_id is a modifier
							       * (e.g. const), it will be resolved to find out the type with size.
							       *
							       * For example:
							       * In describing " const void *",  type_id is " const " and " const "
							       * refers to " void *".  The return type will be " void *".
							       *
							       * If type_id is a simple " int ", then return type will be " int ".
							       *
							       * @btf: struct btf object
							       * @type_id: Find out the size of type_id. The type_id of the return
							       *           type is set to *type_id.
							       * @ret_size: It can be NULL.  If not NULL, the size of the return
							       *            type is set to *ret_size.
							       * Return: The btf_type (resolved to another type with size info if needed).
							       *         NULL is returned if type_id itself does not have size info
							       *         (e.g. void) or it cannot be resolved to another type that
							       *         has size info.
							       *         *type_id and *ret_size will not be changed in the
							       *         NULL return case.
							       */
							      const struct
								btf_type
								*btf_type_id_size
								(const struct
								 btf *btf,
								 u32 *
								 type_id,
								 u32 *
								 ret_size);


							      /*
							       * Options to control show behaviour.
							       *      - BTF_SHOW_COMPACT: no formatting around type information
							       *      - BTF_SHOW_NONAME: no struct/union member names/types
							       *      - BTF_SHOW_PTR_RAW: show raw (unobfuscated) pointer values;
							       *        equivalent to %px.
							       *      - BTF_SHOW_ZERO: show zero-valued struct/union members; they
							       *        are not displayed by default
							       *      - BTF_SHOW_UNSAFE: skip use of bpf_probe_read() to safely read
							       *        data before displaying it.
							       */
#define BTF_SHOW_COMPACT	BTF_F_COMPACT
#define BTF_SHOW_NONAME		BTF_F_NONAME
#define BTF_SHOW_PTR_RAW	BTF_F_PTR_RAW
#define BTF_SHOW_ZERO		BTF_F_ZERO
#define BTF_SHOW_UNSAFE		(1ULL << 4)


							      void
								btf_type_seq_show
								(const struct
								 btf *btf,
								 u32 type_id,
								 void *obj,
								 struct
								 seq_file *m);
							      int
								btf_type_seq_show_flags
								(const struct
								 btf *btf,
								 u32 type_id,
								 void *obj,
								 struct
								 seq_file *m,
								 u64 flags);


							      /*
							       * Copy len bytes of string representation of obj of BTF type_id into buf.
							       *
							       * @btf: struct btf object
							       * @type_id: type id of type obj points to
							       * @obj: pointer to typed data
							       * @buf: buffer to write to
							       * @len: maximum length to write to buf
							       * @flags: show options (see above)
							       *
							       * Return: length that would have been/was copied as per snprintf, or
							       *         negative error.
							       */
							      int
								btf_type_snprintf_show
								(const struct
								 btf *btf,
								 u32 type_id,
								 void *obj,
								 char *buf,
								 int len,
								 u64 flags);


							      int
								btf_get_fd_by_id
								(u32 id);
							      u32
								btf_obj_id
								(const struct
								 btf *btf);
							      bool
								btf_is_kernel
								(const struct
								 btf *btf);
							      bool
								btf_is_module
								(const struct
								 btf *btf);
							      struct module
								*btf_try_get_module
								(const struct
								 btf *btf);
							      u32
								btf_nr_types
								(const struct
								 btf *btf);
							      bool
								btf_member_is_reg_int
								(const struct
								 btf *btf,
								 const struct
								 btf_type *s,
								 const struct
								 btf_member
								 *m,
								 u32
								 expected_offset,
								 u32
								 expected_size);
							      int
								btf_find_spin_lock
								(const struct
								 btf *btf,
								 const struct
								 btf_type *t);
							      int
								btf_find_timer
								(const struct
								 btf *btf,
								 const struct
								 btf_type *t);
							      struct
								bpf_map_value_off
								*btf_parse_kptrs
								(const struct
								 btf *btf,
								 const struct
								 btf_type *t);
							      bool
								btf_type_is_void
								(const struct
								 btf_type *t);
							      s32
								btf_find_by_name_kind
								(const struct
								 btf *btf,
								 const char
								 *name,
								 u8 kind);
							      const struct
								btf_type
								*btf_type_skip_modifiers
								(const struct
								 btf *btf,
								 u32 id,
								 u32 *
								 res_id);
							      const struct
								btf_type
								*btf_type_resolve_ptr
								(const struct
								 btf *btf,
								 u32 id,
								 u32 *
								 res_id);
							      const struct
								btf_type
								*btf_type_resolve_func_ptr
								(const struct
								 btf *btf,
								 u32 id,
								 u32 *
								 res_id);
							      const struct
								btf_type
								*btf_resolve_size
								(const struct
								 btf *btf,
								 const struct
								 btf_type
								 *type,
								 u32 *
								 type_size);
							      const char
								*btf_type_str
								(const struct
								 btf_type *t);


#define for_each_member(i, struct_type, member)			\
		for (i = 0, member = btf_type_member(struct_type);	\
		     i < btf_type_vlen(struct_type);			\
		     i++, member++)


#define for_each_vsi(i, datasec_type, member)			\
		for (i = 0, member = btf_type_var_secinfo(datasec_type);	\
		     i < btf_type_vlen(datasec_type);			\
		     i++, member++)


							      static inline
								bool
								btf_type_is_ptr
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_PTR;
							      }


							      static inline
								bool
								btf_type_is_int
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_INT;
							      }


							      static inline
								bool
								btf_type_is_small_int
								(const struct
								 btf_type *t)
							      {
								return
								  btf_type_is_int
								  (t)
								  && t->size
								  <=
								  sizeof
								  (u64);
							      }


							      static inline
								bool
								btf_type_is_enum
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_ENUM;
							      }


							      static inline
								bool
								btf_is_any_enum
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_ENUM
								  ||
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_ENUM64;
							      }


							      static inline
								bool
								btf_kind_core_compat
								(const struct
								 btf_type *t1,
								 const struct
								 btf_type *t2)
							      {
								return
								  BTF_INFO_KIND
								  (t1->info)
								  ==
								  BTF_INFO_KIND
								  (t2->info)
								  ||
								  (btf_is_any_enum
								   (t1)
								   &&
								   btf_is_any_enum
								   (t2));
							      }


							      static inline
								bool
								str_is_empty
								(const char
								 *s)
							      {
								return !s
								  || !s[0];
							      }


							      static inline
								u16
								btf_kind
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info);
							      }


							      static inline
								bool
								btf_is_enum
								(const struct
								 btf_type *t)
							      {
								return
								  btf_kind (t)
								  ==
								  BTF_KIND_ENUM;
							      }


							      static inline
								bool
								btf_is_enum64
								(const struct
								 btf_type *t)
							      {
								return
								  btf_kind (t)
								  ==
								  BTF_KIND_ENUM64;
							      }


							      static inline
								u64
								btf_enum64_value
								(const struct
								 btf_enum64
								 *e)
							      {
								return ((u64)
									e->val_hi32
									<< 32)
								  |
								  e->val_lo32;
							      }


							      static inline
								bool
								btf_is_composite
								(const struct
								 btf_type *t)
							      {
								u16 kind =
								  btf_kind
								  (t);


								  return kind
								  ==
								  BTF_KIND_STRUCT
								  || kind ==
								  BTF_KIND_UNION;
							      }


							      static inline
								bool
								btf_is_array
								(const struct
								 btf_type *t)
							      {
								return
								  btf_kind (t)
								  ==
								  BTF_KIND_ARRAY;
							      }


							      static inline
								bool
								btf_is_int
								(const struct
								 btf_type *t)
							      {
								return
								  btf_kind (t)
								  ==
								  BTF_KIND_INT;
							      }


							      static inline
								bool
								btf_is_ptr
								(const struct
								 btf_type *t)
							      {
								return
								  btf_kind (t)
								  ==
								  BTF_KIND_PTR;
							      }


							      static inline u8
								btf_int_offset
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INT_OFFSET
								  (*(u32 *)
								   (t + 1));
							      }


							      static inline u8
								btf_int_encoding
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INT_ENCODING
								  (*(u32 *)
								   (t + 1));
							      }


							      static inline
								bool
								btf_type_is_scalar
								(const struct
								 btf_type *t)
							      {
								return
								  btf_type_is_int
								  (t)
								  ||
								  btf_type_is_enum
								  (t);
							      }


							      static inline
								bool
								btf_type_is_typedef
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_TYPEDEF;
							      }


							      static inline
								bool
								btf_type_is_func
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_FUNC;
							      }


							      static inline
								bool
								btf_type_is_func_proto
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_FUNC_PROTO;
							      }


							      static inline
								bool
								btf_type_is_var
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_VAR;
							      }


							      static inline
								bool
								btf_type_is_type_tag
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KIND
								  (t->info) ==
								  BTF_KIND_TYPE_TAG;
							      }


							      /* union is only a special case of struct:
							       * all its offsetof(member) == 0
							       */
							      static inline
								bool
								btf_type_is_struct
								(const struct
								 btf_type *t)
							      {
								u8 kind =
								  BTF_INFO_KIND
								  (t->info);


								  return kind
								  ==
								  BTF_KIND_STRUCT
								  || kind ==
								  BTF_KIND_UNION;
							      }


							      static inline
								u16
								btf_type_vlen
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_VLEN
								  (t->info);
							      }


							      static inline
								u16
								btf_vlen
								(const struct
								 btf_type *t)
							      {
								return
								  btf_type_vlen
								  (t);
							      }


							      static inline
								u16
								btf_func_linkage
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_VLEN
								  (t->info);
							      }


							      static inline
								bool
								btf_type_kflag
								(const struct
								 btf_type *t)
							      {
								return
								  BTF_INFO_KFLAG
								  (t->info);
							      }


							      static inline
								u32
								__btf_member_bit_offset
								(const struct
								 btf_type
								 *struct_type,
								 const struct
								 btf_member
								 *member)
							      {
								return
								  btf_type_kflag
								  (struct_type)
								  ?
								  BTF_MEMBER_BIT_OFFSET
								  (member->
								   offset) :
								  member->
								  offset;
							      }


							      static inline
								u32
								__btf_member_bitfield_size
								(const struct
								 btf_type
								 *struct_type,
								 const struct
								 btf_member
								 *member)
							      {
								return
								  btf_type_kflag
								  (struct_type)
								  ?
								  BTF_MEMBER_BITFIELD_SIZE
								  (member->
								   offset) :
								  0;
							      }


							      static inline
								struct
								btf_member
								*btf_members
								(const struct
								 btf_type *t)
							      {
								return (struct
									btf_member
									*) (t
									    +
									    1);
							      }


							      static inline
								u32
								btf_member_bit_offset
								(const struct
								 btf_type *t,
								 u32
								 member_idx)
							      {
								const struct
								  btf_member
								  *m =
								  btf_members
								  (t) +
								  member_idx;


								  return
								  __btf_member_bit_offset
								  (t, m);
							      }


							      static inline
								u32
								btf_member_bitfield_size
								(const struct
								 btf_type *t,
								 u32
								 member_idx)
							      {
								const struct
								  btf_member
								  *m =
								  btf_members
								  (t) +
								  member_idx;


								  return
								  __btf_member_bitfield_size
								  (t, m);
							      }


							      static inline
								const struct
								btf_member
								*btf_type_member
								(const struct
								 btf_type *t)
							      {
								return (const
									struct
									btf_member
									*) (t
									    +
									    1);
							      }


							      static inline
								struct
								btf_array
								*btf_array
								(const struct
								 btf_type *t)
							      {
								return (struct
									btf_array
									*) (t
									    +
									    1);
							      }


							      static inline
								struct
								btf_enum
								*btf_enum
								(const struct
								 btf_type *t)
							      {
								return (struct
									btf_enum
									*) (t
									    +
									    1);
							      }


							      static inline
								struct
								btf_enum64
								*btf_enum64
								(const struct
								 btf_type *t)
							      {
								return (struct
									btf_enum64
									*) (t
									    +
									    1);
							      }


							      static inline
								const struct
								btf_var_secinfo
								*btf_type_var_secinfo
								(const struct
								 btf_type *t)
							      {
								return (const
									struct
									btf_var_secinfo
									*) (t
									    +
									    1);
							      }


							      static inline
								struct
								btf_param
								*btf_params
								(const struct
								 btf_type *t)
							      {
								return (struct
									btf_param
									*) (t
									    +
									    1);
							      }


#ifdef CONFIG_BPF_SYSCALL
							      struct bpf_prog;


							      const struct
								btf_type
								*btf_type_by_id
								(const struct
								 btf *btf,
								 u32 type_id);
							      const char
								*btf_name_by_offset
								(const struct
								 btf *btf,
								 u32 offset);
							      struct btf
								*btf_parse_vmlinux
								(void);
							      struct btf
								*bpf_prog_get_target_btf
								(const struct
								 bpf_prog
								 *prog);
							      u32
								*
								btf_kfunc_id_set_contains
								(const struct
								 btf *btf,
								 enum
								 bpf_prog_type
								 prog_type,
								 u32
								 kfunc_btf_id);
							      int
								register_btf_kfunc_id_set
								(enum
								 bpf_prog_type
								 prog_type,
								 const struct
								 btf_kfunc_id_set
								 *s);
							      s32
								btf_find_dtor_kfunc
								(struct btf
								 *btf,
								 u32 btf_id);
							      int
								register_btf_id_dtor_kfuncs
								(const struct
								 btf_id_dtor_kfunc
								 *dtors,
								 u32 add_cnt,
								 struct module
								 *owner);
#else
							      static inline
								const struct
								btf_type
								*btf_type_by_id
								(const struct
								 btf *btf,
								 u32 type_id)
							      {
								return NULL;
							      }
							      static inline
								const char
								*btf_name_by_offset
								(const struct
								 btf *btf,
								 u32 offset)
							      {
								return NULL;
							      }
							      static inline
								u32 *
								btf_kfunc_id_set_contains
								(const struct
								 btf *btf,
								 enum
								 bpf_prog_type
								 prog_type,
								 u32
								 kfunc_btf_id)
							      {
								return NULL;
							      }
							      static inline
								int
								register_btf_kfunc_id_set
								(enum
								 bpf_prog_type
								 prog_type,
								 const struct
								 btf_kfunc_id_set
								 *s)
							      {
								return 0;
							      }
							      static inline
								s32
								btf_find_dtor_kfunc
								(struct btf
								 *btf,
								 u32 btf_id)
							      {
								return
								  -ENOENT;
							      }
							      static inline
								int
								register_btf_id_dtor_kfuncs
								(const struct
								 btf_id_dtor_kfunc
								 *dtors,
								 u32 add_cnt,
								 struct module
								 *owner)
							      {
								return 0;
							      }
#endif


#endif
							    }

							    {
							      (
								//#includearch/arch.h
							  OBJCOPYFLAGS = -O binary - R.note - R.note.gnu.build - id - R.comment - S LINUX_START_TEXT = $$ ($ (READELF) - h vmlinux | grep " " | grep - o 0x.*)UIMAGE_LOADADDR = $ (CONFIG_LINUX_LINK_BASE) UIMAGE_ENTRYADDR = $ (LINUX_START_TEXT) targets += vmlinux.bin targets += vmlinux.bin.gz targets += vmlinux.bin.lzma targets += uImage.bin targets += uImage.gz targets += uImage.lzma $ (obj) / vmlinux.bin: vmlinux FORCE $ (call if_changed, objcopy) $ (obj) / vmlinux.bin.gz: $ (obj) / vmlinux.bin FORCE $ (call if_changed, gzip) $ (obj) / vmlinux.bin.lzma: $ (obj) / vmlinux.bin FORCE $ (call if_changed, lzma) $ (obj) / uImage.bin: $ (obj) / vmlinux.bin FORCE $ (call if_changed, uimage, none) $ (obj) / uImage.gz: $ (obj) / vmlinux.bin.gz FORCE $ (call if_changed, uimage, gzip) $ (obj) / uImage.lzma:$ (obj) /
								vmlinux.
								bin.lzma FORCE
								$ (call
								   if_changed,
								   uimage,
								   lzma)}
								{
								CONFIG_SYSVIPC
								=
								y
								CONFIG_POSIX_MQUEUE
								= y
#CONFIG_CROSS_MEMORY_ATTACH is not set
								CONFIG_NO_HZ_IDLE
								=
								y
								CONFIG_HIGH_RES_TIMERS
								=
								y
								CONFIG_IKCONFIG
								=
								y
								CONFIG_IKCONFIG_PROC
								=
								y
								CONFIG_NAMESPACES
								= y
#CONFIG_UTS_NS is not set
#CONFIG_PID_NS is not set
								CONFIG_BLK_DEV_INITRD
								=
								y
								CONFIG_EMBEDDED
								=
								y
								CONFIG_PERF_EVENTS
								= y
#CONFIG_VM_EVENT_COUNTERS is not set
#CONFIG_SLUB_DEBUG is not set
#CONFIG_COMPAT_BRK is not set
								CONFIG_ISA_ARCOMPACT
								=
								y
								CONFIG_MODULES
								=
								y
								CONFIG_MODULE_FORCE_LOAD
								=
								y
								CONFIG_MODULE_UNLOAD
								=
								y
								CONFIG_MODULE_FORCE_UNLOAD
								=
								y
								CONFIG_PARTITION_ADVANCED
								=
								y
								CONFIG_ARC_PLAT_AXS10X
								=
								y
								CONFIG_AXS101
								=
								y
								CONFIG_ARC_CACHE_LINE_SHIFT
								=
								5
								CONFIG_ARC_BUILTIN_DTB_NAME
								=
								" axs101 "
								CONFIG_PREEMPT
								= y
#CONFIG_COMPACTION is not set
								CONFIG_NET = y
								CONFIG_PACKET
								=
								y CONFIG_UNIX
								=
								y
								CONFIG_NET_KEY
								=
								y CONFIG_INET
								=
								y
								CONFIG_IP_PNP
								=
								y
								CONFIG_IP_PNP_DHCP
								=
								y
								CONFIG_IP_PNP_BOOTP
								=
								y
								CONFIG_IP_PNP_RARP
								= y
#CONFIG_INET_XFRM_MODE_TRANSPORT is not set
#CONFIG_INET_XFRM_MODE_TUNNEL is not set
#CONFIG_INET_XFRM_MODE_BEET is not set
#CONFIG_IPV6 is not set
								CONFIG_DEVTMPFS
								= y
#CONFIG_STANDALONE is not set
#CONFIG_PREVENT_FIRMWARE_BUILD is not set
								CONFIG_SCSI =
								y
								CONFIG_BLK_DEV_SD
								=
								y
								CONFIG_NETDEVICES
								= y
#CONFIG_NET_VENDOR_ARC is not set
#CONFIG_NET_VENDOR_BROADCOM is not set
#CONFIG_NET_VENDOR_INTEL is not set
#CONFIG_NET_VENDOR_MARVELL is not set
#CONFIG_NET_VENDOR_MICREL is not set
#CONFIG_NET_VENDOR_NATSEMI is not set
#CONFIG_NET_VENDOR_SEEQ is not set
								CONFIG_STMMAC_ETH
								= y
#CONFIG_NET_VENDOR_VIA is not set
#CONFIG_NET_VENDOR_WIZNET is not set
								CONFIG_NATIONAL_PHY
								= y
#CONFIG_USB_NET_DRIVERS is not set
								CONFIG_INPUT_EVDEV
								=
								y
								CONFIG_MOUSE_PS2_TOUCHKIT
								=
								y
								CONFIG_MOUSE_SERIAL
								=
								y
								CONFIG_MOUSE_SYNAPTICS_USB
								= y
#CONFIG_LEGACY_PTYS is not set
								CONFIG_SERIAL_8250
								=
								y
								CONFIG_SERIAL_8250_CONSOLE
								=
								y
								CONFIG_SERIAL_8250_DW
								=
								y
								CONFIG_SERIAL_OF_PLATFORM
								= y
#CONFIG_HW_RANDOM is not set
								CONFIG_I2C = y
								CONFIG_I2C_CHARDEV
								=
								y
								CONFIG_I2C_DESIGNWARE_PLATFORM
								= y
#CONFIG_HWMON is not set
								CONFIG_DRM = m
								CONFIG_DRM_I2C_ADV7511
								=
								m
								CONFIG_DRM_ARCPGU
								=
								m CONFIG_FB =
								y
								CONFIG_FRAMEBUFFER_CONSOLE
								=
								y CONFIG_LOGO
								= y
#CONFIG_LOGO_LINUX_MONO is not set
#CONFIG_LOGO_LINUX_VGA16 is not set
#CONFIG_LOGO_LINUX_CLUT224 is not set
								CONFIG_USB_EHCI_HCD
								=
								y
								CONFIG_USB_EHCI_HCD_PLATFORM
								=
								y
								CONFIG_USB_OHCI_HCD
								=
								y
								CONFIG_USB_OHCI_HCD_PLATFORM
								=
								y
								CONFIG_USB_STORAGE
								=
								y CONFIG_MMC =
								y
								CONFIG_MMC_SDHCI
								=
								y
								CONFIG_MMC_SDHCI_PLTFM
								=
								y
								CONFIG_MMC_DW
								= y
#CONFIG_IOMMU_SUPPORT is not set
								CONFIG_EXT3_FS
								=
								y
								CONFIG_MSDOS_FS
								=
								y
								CONFIG_VFAT_FS
								=
								y
								CONFIG_NTFS_FS
								=
								y CONFIG_TMPFS
								=
								y
								CONFIG_NFS_FS
								=
								y
								CONFIG_NFS_V3_ACL
								=
								y
								CONFIG_NLS_CODEPAGE_437
								=
								y
								CONFIG_NLS_ISO8859_1
								= y
#CONFIG_ENABLE_MUST_CHECK is not set
								CONFIG_STRIP_ASM_SYMS
								=
								y
								CONFIG_SOFTLOCKUP_DETECTOR
								=
								y
								CONFIG_DEFAULT_HUNG_TASK_TIMEOUT
								= 10
						
			
#CONFIG_SCHED_DEBUG is not set
#CONFIG_DEBUG_PREEMPT is not set
#CONFIG_FTRACE is not set
							    )}
{
    OBJCOPYFLAGS= -O binary -R .note -R .note.gnu.build-id -R .comment -S

LINUX_START_TEXT = $$($(READELF) -h vmlinux | \
			grep " Entry point address " | grep -o 0x.*)

UIMAGE_LOADADDR    = $(CONFIG_LINUX_LINK_BASE)
UIMAGE_ENTRYADDR   = $(LINUX_START_TEXT)

targets += vmlinux.bin
targets += vmlinux.bin.gz
targets += vmlinux.bin.lzma
targets += uImage.bin
targets += uImage.gz
targets += uImage.lzma

$(obj)/vmlinux.bin: vmlinux FORCE
	$(call if_changed,objcopy)

$(obj)/vmlinux.bin.gz: $(obj)/vmlinux.bin FORCE
	$(call if_changed,gzip)

$(obj)/vmlinux.bin.lzma: $(obj)/vmlinux.bin FORCE
	$(call if_changed,lzma)

$(obj)/uImage.bin: $(obj)/vmlinux.bin FORCE
	$(call if_changed,uimage,none)

$(obj)/uImage.gz: $(obj)/vmlinux.bin.gz FORCE
	$(call if_changed,uimage,gzip)

$(obj)/uImage.lzma: $(obj)/vmlinux.bin.lzma FORCE
	$(call if_changed,uimage,lzma)
}











							    {
							      //#COPYRIGHT
							    The Linux Kernel
								is provided
								under:SPDX -
								License -
								Identifier:GPL
								-
								2.0 WITH
								Linux -
								syscall -
								note Being
								under the
								terms of the
								GNU General
								Public
								License
								version 2
								only,
								according
								with:LICENSES
								/
								preferred /
								GPL -
								2.0 With an
								explicit
								syscall
								exception,
								as stated
								at:LICENSES
								/
								exceptions /
								Linux -
								syscall -
								note In
								addition,
								other
								licenses may
								also
								apply.Please
								see:Documentation
								/ process /
								license -
								rules.rst
								for more
								details.All
								contributions
								to the Linux
								Kernel are
								subject to
								this COPYING
								file.}








