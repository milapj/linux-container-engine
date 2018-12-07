/* 
 * This file is part of the Hawker container engine developed by
 * the HExSA Lab at Illinois Institute of Technology.
 *
 * Copyright (c) 2018, Kyle C. Hale <khale@cs.iit.edu>
 *
 * All rights reserved.
 *
 * Author: Kyle C. Hale <khale@cs.iit.edu>
 *
 * This is free software.  You are permitted to use,
 * redistribute, and modify it as specified in the 
 * file "LICENSE.txt".
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>


#include "hawker.h"
#include "net.h"
#include "img.h"

static pid_t child_pid = -1;

static void
set_child_pid (long pid)
{
    child_pid = pid;
}


/* 
 * This is the (child) container process. By the time it invokes the user command
 * specified (using execvp()), it will be in a fully isolated container
 * environment.
 */
static int 
child_exec (void * arg)
{
        struct parms *p           = (struct parms*)arg;
        char c;
	printf("Entered Child Functoin\n");
        // if our parent dies and doesn't kill us
        // explicitly, we should also die, instead of hanging
        // around. Note that this is not POSIX-compliant, 
        // so it will only work on Linux.
        prctl(PR_SET_PDEATHSIG, SIGKILL);

        close(p->pipefd[1]); // close write end of our pipe

        // wait for the parent to hangup its write end of the pipe,
        // signaling that we can now start the container stuff.
        if (read(p->pipefd[0], &c, 1) != 0) {
            fprintf(stderr, "Read from pipe in child returned != 0\n");
            exit(EXIT_FAILURE);
        }

        close(p->pipefd[0]); // close read end of the pipe, we're done with it

        // FILL ME IN: our parent should now have set things up properly
        // We need to:
        // (1) change our root to the new directory for the image
	printf("%s %s\n",p->cmd, p->img);
	char * img = hkr_get_img_path();
	//printf("%s\n",img);
	//strcat("/",img);
	//strcat(img,p->img);
	//printf("%s\n",img);
	char * full_img_path = (char *)malloc(1 + strlen(img) + strlen(p->img));
	strcpy(full_img_path,img);
	strcat(full_img_path,"/");
	strcat(full_img_path,p->img);
	printf("%s\n",full_img_path);
	chroot(full_img_path);	
        // (2) actually move into that root
	chdir("/");
        // (3) change our hostname
	sethostname(DEFAULT_HOSTNAME,strlen(DEFAULT_HOSTNAME));
        // (4) execute the command that the user gave us
	printf("%s\n",p->argv[0]);
	execvp(p->argv[0],p->argv);
	printf("End of Child Function reached\n");
	exit(EXIT_FAILURE);
}


static void
version ()
{
    printf("hawker %s\n", VERSION_STRING);
}


static void
usage (char * prog)
{
    printf("\n\thawker -- the container engine\n\n");

    printf("\tDescription\n");
    printf("\t\thawker is a minimal container engine.\n");
    printf("\t\tIt creates a container and runs the\n");
    printf("\t\tspecified command inside of it.\n\n");

    printf("\tUsage: %s [OPTIONS] IMAGE COMMAND [ARG...]\n", prog);

    printf("\n\tOptions:\n");

    printf("\t\t  -c, ---cpu-share <percentage> : percent of CPU to give to container (from 0 to 100); default=100\n");
    printf("\t\t  -m, ---mem-limit <limit-in-bytes> : max amount of memory that the container can use\n");
    printf("\t\t  -C, --clear-cache : clear all cached container images\n");
    printf("\t\t  -h, ---help : display this message\n");
    printf("\t\t  -v, --version : display the version number and exit\n");

    printf("\n");
}


static void
parse_args (int argc, char **argv, struct parms * p)
{
        int cpu_pct    = DEFAULT_CPU_PCT;
        long mem_limit = DEFAULT_MEM_LIMIT;
        int optidx     = 0;
        char c;

        while (1) {

            static struct option lopts[] = {
                {"cpu-share", required_argument, 0, 'c'},
                {"mem-limit", required_argument, 0, 'm'},
                {"clear-cache", no_argument, 0, 'C'},
                {"help", no_argument, 0, 'h'},
                {"version", no_argument, 0, 'v'},
                {0, 0, 0, 0}
            };

            c = getopt_long(argc, argv, "c:m:Chv", lopts, &optidx);

            if (c == -1) {
                break;
            }

            switch (c) {
                case 'c':
                    cpu_pct = atoi(optarg);
                    break;
                case 'C':
                    hkr_clear_img_cache();
                    exit(EXIT_SUCCESS);
                case 'm':
                    mem_limit = atol(optarg);
                    break;
                case 'h':
                    usage(argv[0]);
                    exit(EXIT_SUCCESS);
                case 'v':
                    version();
                    exit(EXIT_SUCCESS);
                case '?':
                    break;
                default:
                    printf("?? getopt returned character code 0%o ??\n", c);
            }
        }

        if (optind < argc) {
            p->img = argv[optind++];
        } else {
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        if (optind < argc) {
            p->cmd = argv[optind];
        } else {
            usage(argv[0]);
            exit(EXIT_SUCCESS);
        }

        p->argv      = &argv[optind];
        p->mem_limit = mem_limit;
        p->cpu_pct   = cpu_pct;
}


static inline void
construct_cgroup_path (char * buf, size_t len, long pid, char * subdir)
{
    memset(buf, 0, len);
    snprintf(buf, len, "/sys/fs/cgroup/%s/hawker/%ld", subdir, pid);
}


static inline void
construct_cgroup_subpath (char * buf, size_t len, long pid, char * subdir, char * subent)
{
    memset(buf, 0, len);
    snprintf(buf, len, "/sys/fs/cgroup/%s/hawker/%ld/%s", subdir, pid, subent);
}


static void
make_cgroup_subdir(long pid, char * subdir)
{
    char path[PATH_MAX];
    construct_cgroup_path(path, PATH_MAX, pid, subdir);

    // does it already exist?
    if (access(path, F_OK) == 0) {
        return;
    }

    if (mkdir(path, S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) != 0) {
        fprintf(stderr, "Could not create cgroup dir: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}


static void
remove_cgroup_subdir(long pid, char * subdir)
{
    char path[PATH_MAX];

    construct_cgroup_path(path, PATH_MAX, pid, subdir);

    // dir isn't there
    if (access(path, F_OK) != 0) {
        return;
    }

    if (rmdir(path) != 0) {
        fprintf(stderr, "Could not remove cgroup dir: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }
}


static void
setup_cgroup_dirs (long pid)
{
    make_cgroup_subdir(pid, "cpuacct");
    make_cgroup_subdir(pid, "memory");
}


static void
cleanup_cgroup_dirs (long pid)
{
    remove_cgroup_subdir(pid, "cpuacct");
    remove_cgroup_subdir(pid, "memory");
}


static void
cleanup (void)
{
    cleanup_cgroup_dirs(child_pid);
}

static void 
death_handler (int sig)
{
    kill(child_pid, SIGKILL);
    // if we don't wait for the child to
    // completely die here, cgroups won't let us remove
    // the subdirectories
    waitpid(child_pid, NULL, 0);
    cleanup();
}

static void
handle_setgroups_file(pid_t pid) {
	int sg;
	char setgroup_filename[50];
	strcpy(setgroup_filename, "/proc/");
	char pid_buf[50];
        sprintf(pid_buf,"%d",pid);
	strcat(setgroup_filename,pid_buf);
	strcat(setgroup_filename, "/setgroups");
	sg = open(setgroup_filename, O_RDWR);
        if(sg == -1) {
                printf("Could not open file\n");
        }
        else {
                printf("setgroups file opened\n");
        }

        if(write(sg,"deny",strlen("deny")) != strlen("deny")) {
                fprintf(stderr, "write %s: %s\n",setgroup_filename, strerror(errno));
                exit(EXIT_FAILURE);
        }
        else {
                printf("setgroups file written\n");
        }
	close(sg);

}

static void
handle_child_mapping(char * map_filename, pid_t pid) {
	int fd;
	//int sg = 0;
	//map_size = DEFAULT_MAP;
	char filename[64];
	//char setgroup_filename[50];
	strcpy(filename, "/proc/");
	//strcpy(setgroup_filename, "/proc/");
	//char uid_map[50] = "/uid_map";
	//char gid_map[50] = "/gid_map";
	char pid_buf[50];
	sprintf(pid_buf,"%d",pid);
	strcat(filename, pid_buf);
	//strcat(setgroup_filename, pid_buf);
	//strcat(setgroup_filename, "/setgroups");
	strcat(filename, map_filename);
        //printf("%s",filename);
	
	/*sg = open(setgroup_filename, O_RDWR);
	if(sg == -1) {
		printf("Could not open file\n");
	}
	else {
		printf("setgroups file opened\n");
	}
	
	if(write(sg,"allow",sizeof("allow")) != sizeof("allow")) {
		fprintf(stderr, "write %s: %s\n",filename, strerror(errno));
                exit(EXIT_FAILURE);
	}
	else {
		printf("setgroups file written\n");
	}*/

	fd = open(filename, O_RDWR);
	if(fd == -1) {
		printf("Could not open file: %s\n", filename);
	}
	if(write(fd, DEFAULT_MAP, strlen(DEFAULT_MAP)) != strlen(DEFAULT_MAP)) {
		fprintf(stderr, "write %s: %s\n",filename, strerror(errno));
		exit(EXIT_FAILURE);
		//printf("Could not write in file: %s\n",filename);
	}

	close(fd);	
}

int 
main (int argc, char **argv)
{
        void * child_stack = NULL;
        unsigned stk_sz    = DEFAULT_STACKSIZE;
        struct parms p;
        int clone_flags;
        pid_t pid;

        // get our network subsystem going
        hkr_net_init();

        // create a cache for our container images
        if (hkr_img_cache_init() != 0) {
            fprintf(stderr, "Could not create hawker image cache\n");
            exit(EXIT_FAILURE);
        }

        parse_args(argc, argv, &p);

        // if the image isn't cached, we need to download it
        if (!hkr_img_exists(p.img)) {

            printf("Unable to find image '%s' locally\n", p.img);

            // we get it in the form of a .txz file
            if (hkr_net_get_img(p.img) != 0) {
                fprintf(stderr, "Image '%s' not found in hawker repository\n", p.img);
                exit(EXIT_FAILURE);
            }

            // now extract it into our cache dir
            if (hkr_img_extract(p.img) != 0) {
                fprintf(stderr, "Could not extract compressed image (%s)\n", p.img);
                exit(EXIT_FAILURE);
            }

        }

        // FILL ME IN: we need to add flags to clone
        // to setup namespaces properly, you should create
        // new UTS, PID, user, mountpoint, network, and IPC 
        // namespaces. See man 3 clone if in doubt.
        // The SIGCHILD indicates the signal which should
        // be delivered to the parent process when the
        // child exits (if does, indeed, exit);
        clone_flags = CLONE_NEWUTS | CLONE_NEWPID | CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWIPC | SIGCHLD;

        // FILL ME IN: when we create a new process using clone(), we
        // must give the new process a stack. We are in charge of allocating
        // that stack. We could either use malloc() or mmap() here. 
        // malloc() is of course easier, but mmap() gives us more control
        // over the characteristics of that memory.
	child_stack = malloc(stk_sz);
        // FILL ME IN: remove this when you get a stack setup
        //exit(EXIT_SUCCESS);

        // we'll use this pipe for communicating with the child
        if (pipe(p.pipefd) != 0) {
            fprintf(stderr, "Could not create pipe: %s\n", strerror(errno));
            exit(EXIT_FAILURE);
        }

        // We must now call clone and get a pid back. We must pass
        // in the stack we allocated, its size, the flags for the clone, and an argument
        // to pass to the function. The result of this call is 
        // that our child_exec function will be run in another
        // process. Clone will give us the child's
        // PID as a return value. -1 means it encountered an error.
        pid = clone(child_exec, child_stack + stk_sz, clone_flags, &p);
        if (pid < 0) {
                fprintf(stderr, "Clone failed: %s\n", strerror(errno));
                exit(EXIT_FAILURE);
        }
        set_child_pid(pid);
	handle_child_mapping("/uid_map",pid);
	handle_setgroups_file(pid);
        handle_child_mapping("/gid_map",pid);
	// FILL ME IN: we have to setup the PID namespace now
        // This will involve writing /proc/<PID>/uid_map, gid_map
		
        // BEGIN RESOURCE CONTROL SETUP
        
        // I'm setting up these cgroup directories for you. You'll
        // need to modify files within these to actually control the cgroups
        setup_cgroup_dirs(pid);

        // we must clean these cgroup dirs up if the process exits,
        // so we make sure here that we'll catch user interrupts (^C)
        signal(SIGINT, death_handler);

        // FILL ME IN: 
        // we must set the relative amount of CPU
        // this process will get and the maximum amount of 
        // memory it can use (in bytes). We use the values
        // passed to us in p.cpu_pct and p.mem_limit, and
        // translate those into the cgroup file entries
            
        // we hang up both ends of the pipe to let the child
        // know that we've written the appropriate files. It 
        // can then continue. Note that we could also do this
        // with signal()
        close(p.pipefd[0]); // close read end of pipe
        close(p.pipefd[1]); // close write end of pipe

        // wait on child to exit
        waitpid(pid, NULL, 0);

        // goodbye
        exit(EXIT_SUCCESS);
}
