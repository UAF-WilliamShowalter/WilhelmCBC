// Code borrowed with permission from Dr. Orion Sky Lawlor's NetRun project.
// lawlor@alaska.edu

/******* Function Performance Profiling ***********/
/**
 Return the current time in seconds (since something or other).
 */

#if defined(_WIN32)
#  include <sys/timeb.h>
#  define time_in_seconds_granularity 0.1 /* seconds */
double time_in_seconds(void) { /* This seems to give terrible resolution (60ms!) */
    struct _timeb t;
    _ftime(&t);
    return t.millitm*1.0e-3+t.time*1.0;
}
#else /* UNIX or other system */
#  include <sys/time.h> //For gettimeofday time implementation
#  define time_in_seconds_granularity 0.01 /* seconds */
double time_in_seconds(void) {
	struct timeval tv;
	gettimeofday(&tv,NULL);
	return tv.tv_usec*1.0e-6+tv.tv_sec*1.0;
}
#endif