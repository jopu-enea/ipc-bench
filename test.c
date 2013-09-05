/*
 * Copyright (c) 2011 Anil Madhavapeddy <anil@recoil.org>
 * Copyright (c) 2013 Josep Puigdemont <josep.puigdemont@enea.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <sys/stat.h>
#include <assert.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <sys/time.h>
#include <err.h>
#include <inttypes.h>
#include <netdb.h>
#include <pthread.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <sys/uio.h>
#include <errno.h>

#include "test.h"
#include "xutil.h"

static void
wait_for_children_to_finish(void)
{
  int status, rv;

  /* Make sure the child really does go away when it's no longer
     needed. */
  while (1) {
    rv = waitpid(-1, &status, 0);
    assert(rv != 0);
    if (rv < 0) {
      if (errno == ECHILD)
	break;
      err(1, "waitpid()");
    }
    if (WIFSIGNALED(status))
      errx(1, "child killed by signal %d", WTERMSIG(status));
    if (WIFEXITED(status)) {
      if (WEXITSTATUS(status) != 0)
	errx(1, "child exited with status %d", WEXITSTATUS(status));
    } else {
      errx(1, "unexpected status %x from waitpid", status);
    }
  }
}

static void stosmemset(void* buf, int byte, size_t count) {
#ifdef USE_INLINE_ASM
  int clobber;
  assert(count % 8 == 0);
  asm volatile ("rep stosq\n"
		: "=c" (clobber)
		: "a" ((unsigned long)(byte & 0xff) * 0x0101010101010101ul),
		  "D" (buf),
		  "0" (count / 8)
		: "memory");
#else
  errx(1, "stosmemset: not implemented");
#endif
}

static int repmemcmp(void* buf, int byte, size_t count) {
#ifdef USE_INLINE_ASM
  unsigned long clobber;
  void* clobber2;
  char result;
  assert(count % 8 == 0);
  asm ("repe scasq\n"
       "setne %%al\n"
       : "=a" (result),
	 "=c" (clobber),
	 "=D" (clobber2)
       : "a" ((unsigned long)(byte & 0xff) * 0x0101010101010101ul),
	 "c" (count / 8),
	 "D" (buf)
       );
  return result;
#else
  errx(1, "repmemcmp: not implemented");
#endif
}

void parent_main(test_t* test, test_data* td, int is_latency_test) {

  char* private_buffer = xmalloc(td->size);
  struct timeval start;
  struct timeval stop;						
  unsigned long *iter_cycles;						
  unsigned long delta;	
  unsigned long t = 0;
  struct iovec private_vec = { .iov_base = private_buffer, .iov_len = td->size };
			
  if(test->init_parent)
    test->init_parent(td);
    									
  /* calm compiler */							
  iter_cycles = NULL;							
									
  if (td->per_iter_timings) {						
    iter_cycles = calloc(sizeof(iter_cycles[0]), td->count);		
    if (!iter_cycles)							
      err(1, "calloc");						
  }									
									
  gettimeofday(&start, NULL);						
  for (int i = 0; i < td->count; i++) {	
    if(td->per_iter_timings)
      t = rdtsc();

    struct iovec* write_bufs;
    int n_write_bufs;
    struct iovec* produce_bufs;
    int n_produce_bufs;

    if(!is_latency_test) {
      write_bufs = test->get_write_buffer(td, td->size, &n_write_bufs);
      if(td->write_in_place) {
	produce_bufs = write_bufs;
	n_produce_bufs = n_write_bufs;
      }
      else {
	produce_bufs = &private_vec;
	n_produce_bufs = 1;
      }

      for(int j = 0; j < n_produce_bufs; j++) {
	if(td->produce_method == PRODUCE_GLIBC_MEMSET)
	  memset(produce_bufs[j].iov_base, (char)i, produce_bufs[j].iov_len);
	else if(td->produce_method == PRODUCE_STOS_MEMSET)
	  stosmemset(produce_bufs[j].iov_base, (char)i, produce_bufs[j].iov_len);
	else if(td->produce_method == PRODUCE_LOOP) {
	  for(int k = 0; k < produce_bufs[j].iov_len; k++)
	    ((char*)produce_bufs[j].iov_base)[k] = (char)i;
	}
	else {
	  assert(0 && "Bad produce method!");
	}
      }

      if(!td->write_in_place) {
	int offset = 0;
	for(int j = 0; j < n_produce_bufs; j++) {
	  memcpy(((char*)write_bufs[j].iov_base) + offset, private_buffer + offset, write_bufs[j].iov_len);
	  offset += write_bufs[j].iov_len;
	}
      }

      test->release_write_buffer(td, write_bufs, n_write_bufs);
    }
    else {
      test->parent_ping(td);
    }

    if(td->per_iter_timings)
      iter_cycles[i] = rdtsc() - t;					
  }									

  if(test->finish_parent)
    test->finish_parent(td);

  gettimeofday(&stop, NULL);						
									
  delta = ((stop.tv_sec - start.tv_sec) * (int64_t) 1000000 +		
	   stop.tv_usec - start.tv_usec);				
									
  if (is_latency_test)								
    logmsg(td,							
	   "headline",						
	   "%s %d %" PRIu64 " %fs\n", td->name, td->size, td->count,
	   delta / (td->count * 1e6));				
  else								
    logmsg(td,							
	   "headline",						
	   "%s %d %d %d %d %d %d %d %d %" PRId64 " %" PRId64 " Mbps\n", td->name, td->first_core, td->second_core,
	   td->numa_node,
	   td->size, 
	   td->produce_method, td->write_in_place, td->read_in_place, td->do_verify, td->count,							
	   ((((td->count * (int64_t)1e6) / delta) * td->size * 8) / (int64_t) 1e6)); 
									
  if (td->per_iter_timings)						
    dump_tsc_counters(td, iter_cycles, td->count);

}

void child_main(test_t* test, test_data* td, int is_latency_test) {

  char* private_buffer = xmalloc(td->size);
  struct iovec private_vec = { .iov_base = private_buffer, .iov_len = td->size };

  if(test->init_child)
    test->init_child(td);

  for(int i = 0; i < td->count; i++) {

    struct iovec* check_bufs;
    int n_check_bufs;
    struct iovec* read_bufs;
    int n_read_bufs;

    if(!is_latency_test) {
      read_bufs = test->get_read_buffer(td, td->size, &n_read_bufs);
      if(td->read_in_place) {
	check_bufs = read_bufs;
	n_check_bufs = n_read_bufs;
      }
      else {
	check_bufs = &private_vec;
	n_check_bufs = 1;
	for(int j = 0, offset = 0; j < n_read_bufs; offset += read_bufs[j].iov_len, j++) {
	  memcpy(private_buffer + offset, read_bufs[j].iov_base, read_bufs[j].iov_len);
	}
      }

      if(td->do_verify) {
	for(int j = 0; j < n_check_bufs; j++) {
	  if(repmemcmp(check_bufs[j].iov_base, i, check_bufs[j].iov_len))
	    err(1, "bad data");
	}
      }

      test->release_read_buffer(td, read_bufs, n_read_bufs);
    }
    else {
      test->child_ping(td);
    }

  }

  if(test->finish_child)
    test->finish_child(td);
}

static int
thread_setaffinity(pthread_t thread, int cpunum)
{
	int retval = 0;
#ifdef Linux
	cpu_set_t *mask;
	size_t size;
	int nrcpus = 160;

	mask = CPU_ALLOC(nrcpus);
	size = CPU_ALLOC_SIZE(nrcpus);
	CPU_ZERO_S(size, mask);
	CPU_SET_S(cpunum, size, mask);
	retval = pthread_setaffinity_np(thread, size, mask);
	if (retval != 0)
		err(1, "pthread_setaffinity_np()");
	CPU_FREE(mask);
#else
	fprintf(stderr, "setaffinity: skipping\n");
#endif
	return retval;
}

static void *
receiver_thread(void *arg)
{
	test_data *td = (test_data *)arg;
	test_t *test = td->test;

	child_main(test, td, td->flags & FLAG_LATENCY);
	pthread_exit(arg);
}

static void *
sender_thread(void *arg)
{
	test_data *td = (test_data *)arg;
	test_data *td2 = xmalloc(sizeof(test_data));
	void *retval;
	test_t *test = td->test;
	pthread_t child;
	int res;

	test->init_test(td);
	memcpy(td2, td, sizeof(test_data));

	res = pthread_create(&child, NULL, receiver_thread, td2);
	if (res != 0) {
		perror("pthread_create()");
		fprintf(stderr, "ERROR: test %d terminating\n",	td->num);
		free(td2);
		pthread_exit(arg);
	}

	thread_setaffinity(child, td->second_core);
	parent_main(td->test, td, td->flags & FLAG_LATENCY);

	/* wait for children to return */
	res = pthread_join(child, &retval);
	if (res != 0)
		perror("pthread_join()");
	if (retval == PTHREAD_CANCELED)
		fprintf(stderr, "CHILD thread %d canceled\n", td->num);
	else
		assert(retval == td2);

	free(td2);
	pthread_exit(arg);
}

static void
run_threads(test_data *params)
{
	pthread_t *thread_id;
	test_data *td;
	int num, ret;

	if (mkdir(params->output_dir, 0755) < 0 && errno != EEXIST)
		err(1, "creating directory %s", params->output_dir);

	thread_id = (pthread_t *)malloc(sizeof(pthread_t) * params->num);

	for (num = 0; num < params->num; num++) {
		td = xmalloc(sizeof(test_data));
		memcpy(td, params, sizeof(test_data));
		td->num = num;
		ret = pthread_create(&thread_id[num], NULL,
				     sender_thread, td);
		if (ret != 0)
			err(1, "pthread_create(): %d", ret);
		thread_setaffinity(thread_id[num], td->first_core);
	}

	/* join threads */
	for (num = 0; num < params->num; num++) {
		ret = pthread_join(thread_id[num], (void **)&td);
		if (ret != 0)
			fprintf(stderr, "pthread_join() error: %d, %m\n", ret);
		else if (td == PTHREAD_CANCELED)
			fprintf(stderr, "Thread %d canceled\n", num);
		else
			free(td);
	}
}

/* Execute a test with as many parallel iterations as requested */
void
run_test(int argc, char *argv[], test_t *test)
{
  test_data tp;

  memset(&tp, 0, sizeof(test_data));
  tp.test = test;
  tp.name = test->name;
  parse_args(argc, argv, &tp);

  if ((!test->is_latency_test) &&
      (!(tp.produce_method >= 1 && tp.produce_method <= 3))) {
    fprintf(stderr, "Produce method (option -m) must be specified and between 1 and 3\n");
    exit(1);
  }

  /* should it run threaded? */
  if (tp.flags & FLAG_THREADED) {
	  if (!(test->flags & FLAG_THREADED)) {
		  fprintf(stderr,
			  "Test %s is not thread-aware but -T was given\n",
			  test->name);
		  exit(1);
	  }
	  run_threads(&tp);
	  return;
  }

  if (mkdir(tp.output_dir, 0755) < 0 && errno != EEXIST)
    err(1, "creating directory %s", tp.output_dir);

  while (tp.num > 0) {
    pid_t pid1 = fork ();
    if (!pid1) { /* child1 */
      /* Initialise a test run */
      test_data *td = xmalloc(sizeof(test_data));

      memcpy(td, &tp, sizeof(test_data));
      /* Test-specific init */
      test->init_test(td);
      pid_t pid2 = fork ();
      if (!pid2) { /* child2 */
        setaffinity(td->first_core);
	child_main(test, td, test->is_latency_test);
        exit (0);
      } else { /* parent2 */
        setaffinity(td->second_core);
	parent_main(test, td, test->is_latency_test);

	wait_for_children_to_finish();

        exit (0);
      }
    } else { /* parent */ 
      /* continue to fork */
      tp.num--;
    }
  }
  wait_for_children_to_finish();
}
